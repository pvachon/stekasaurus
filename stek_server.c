#include "stek_common.h"
#include "list.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#define STEK_SERVER_MAX_MSG_LENGTH      128

#define MESSAGE(_msg, ...) do { \
        fprintf(stderr, _msg " (" __FILE__ ":%d @ %s)\n", ##__VA_ARGS__, __LINE__, __FUNCTION__); \
    } while (0)

enum stek_server_session_state {
    STEK_SERVER_SESSION_STATE_STARTING = 0,
    STEK_SERVER_SESSION_STATE_RUNNING,
    STEK_SERVER_SESSION_STATE_CLOSING,
    STEK_SERVER_SESSION_STATE_CLOSED
};

struct stek_server_session {
    SSL *conn;
    int sess_fd;
    enum stek_server_session_state st;
    size_t nr_pings;

    uint8_t rx_msg[STEK_SERVER_MAX_MSG_LENGTH];
    size_t rx_msg_bytes;
    struct list_entry s_node;

    struct sockaddr_in remote;
};

static
LIST_HEAD(active_sessions);

static
char *server_cert_file = NULL;

static
char *private_key_file = NULL;

static
char *client_cert_file = NULL;

static
char *stek_file = NULL;

static
uint16_t port = 24601;

static volatile
bool running = true;

static volatile
bool terminating = false;

static
void _handle_sigint(int signum)
{
    if (true == terminating) {
        MESSAGE("User insisted we terminate ASAP, aborting.");
        exit(EXIT_FAILURE);
    }

    terminating = true;
    MESSAGE("User asked that we terminate, trying to do so cleanly.");
}

static
void show_help(const char *arg0)
{
    printf("Usage: %s -s [server cert chain] -c [client cert roots] -S [STEK]\n", arg0);
    printf("Where:\n");
    printf("    -s [server cert chain]      a file containing the server certificate chain (PEM, concat)\n");
    printf("    -P [private key file]       a PEM file containing the server private key\n");
    printf("    -c [client cert roots]      a file containing one or more trusted client certificate roots\n");
    printf("    -S [STEK]                   session ticket encryption key (raw binary file)\n");
    printf("    -p [port]                   listening port (default: 24601)\n");
    exit(EXIT_SUCCESS);
}

static
void handle_args(int argc, char* const argv[])
{
    int ch = 0;

    while (-1 != (ch = getopt(argc, argv, "s:c:S:p:P:hv"))) {
        switch (ch) {
        case 's':
            server_cert_file = strdup(optarg);
            MESSAGE("Server certificate chain file: [%s]", server_cert_file);
            break;
        case 'c':
            client_cert_file = strdup(optarg);
            MESSAGE("Client certificate roots file: [%s]", client_cert_file);
            break;
        case 'S':
            stek_file = strdup(optarg);
            MESSAGE("Session Ticket Encryption Key file: [%s]", stek_file);
            break;
        case 'P':
            private_key_file = strdup(optarg);
            MESSAGE("Private key file: [%s]", private_key_file);
            break;
        case 'p':
            port = strtoul(optarg, NULL, 0);
            break;
        case 'v':
            MESSAGE("We're gonna be verbose!");
            stek_common_set_verbose(true);
            break;
        case 'h':
            show_help(argv[0]);
            break;
        default:
            MESSAGE("Unknown argument: %s", argv[opterr]);
            show_help(argv[0]);
        }
    }

    if (NULL == private_key_file) {
        MESSAGE("You must specify a private key file (-P)");
        show_help(argv[0]);
    }

    if (NULL == server_cert_file) {
        MESSAGE("You must specify a server certificate chain (-s)");
        show_help(argv[0]);
    }

    MESSAGE("Provisioned to listen  on TCP port %u", (unsigned)port);
}

static
int stek_server_new_session(struct stek_server_session **p_sess, int sess_fd, SSL_CTX *ctx, struct sockaddr_in *remote)
{
    int ret = EXIT_FAILURE;

    struct stek_server_session *sess = NULL;
    BIO *s_bio = NULL;

    if (NULL == (sess = calloc(1, sizeof(struct stek_server_session)))) {
        MESSAGE("Out of memory during calloc(3), unable to allocate state for new session.");
        /* TODO: think about error handling */
        exit(ret);
    }

    if (NULL == (s_bio = BIO_new_socket(sess_fd, BIO_NOCLOSE))) {
        MESSAGE("Failed to create socket BIO. Aborting.");
        /* TODO: think about error handling */
        exit(ret);
    }

    sess->conn = SSL_new(ctx);

    SSL_set_bio(sess->conn, s_bio, s_bio);

    sess->st = STEK_SERVER_SESSION_STATE_STARTING;
    sess->sess_fd = sess_fd;
    list_append(&active_sessions, &sess->s_node);
    sess->remote = *remote;

    *p_sess = sess;

    ret = EXIT_SUCCESS;
done:
    if (EXIT_FAILURE == ret) {
        if (NULL != sess) {
            if (NULL != sess->conn) {
                SSL_free(sess->conn);
                sess->conn = NULL;
            }
            free(sess);
            sess = NULL;
        }
    }

    return ret;
}

static
int stek_server_delete_session(struct stek_server_session **p_sess)
{
    int ret = EXIT_FAILURE;

    struct stek_server_session *sess = NULL;

    if (NULL == p_sess) {
        MESSAGE("Tried to destroy NULL session, aborting.");
        goto done;
    }

    sess = *p_sess;

    /* Remove the session from whatever list it is in */
    list_del(&sess->s_node);

    if (STEK_SERVER_SESSION_STATE_CLOSED != sess->st) {
        MESSAGE("WARNING: Peer killed the connection.");
    }

    /* Terminate the SSL session */
    if (NULL != sess->conn) {
        SSL_free(sess->conn);
        sess->conn = NULL;
    }

    /* Close the file descriptor */
    if (0 <= sess->sess_fd) {
        close(sess->sess_fd);
        sess->sess_fd = -1;
    }

    free(sess);
    *p_sess = NULL;

    ret = EXIT_SUCCESS;
done:
    return ret;
}

static
int stek_server_terminate_session(struct stek_server_session *sess, bool *p_reap)
{
    int ret = EXIT_FAILURE;

    int ssl_ret = 0,
        ssl_err = SSL_ERROR_NONE;

    if (NULL == sess || NULL == sess->conn) {
        goto done;
    }

    sess->st = STEK_SERVER_SESSION_STATE_CLOSING;
    if (0 >= (ssl_ret = SSL_shutdown(sess->conn))) {
        if (SSL_ERROR_NONE != (ssl_err = SSL_get_error(sess->conn, ssl_ret))) {
            switch (ssl_err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                /* Do nothing. We'll need to call SSL_shutdown yet again when data becomes available. */
                MESSAGE("Still waiting on data for SSL_shutdown!");
                break;
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                MESSAGE("Fatal internal error, marking for quick reap.");
            default:
                ERR_print_errors_fp(stderr);
                /* Fatal error. Mark the session to be reaped. */
                *p_reap = true;
                break;
            }
        }
    }

    ret = EXIT_SUCCESS;
done:
    return ret;
}

/**
 * Consume any pending I/O event. This is also where we get a hint as to whether or not a session
 * should be considered closed and purged from our session list. This is our baseline continuiation
 * function for any deferred event due to an I/O wait.
 */
static
int stek_server_handle_io_event(struct stek_server_session *sess, bool write_ready, bool *p_reap)
{
    int ret = EXIT_FAILURE;

    int ssl_ret = 0;

    *p_reap = false;

    switch (sess->st) {
    case STEK_SERVER_SESSION_STATE_STARTING: {
            int ssl_err = 0;
            /* Run SSL_accept */
            ssl_ret = SSL_accept(sess->conn);
            if (SSL_ERROR_NONE != (ssl_err = SSL_get_error(sess->conn, ssl_ret))) {
                switch (ssl_err) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    /* Do nothing. We'll need to call SSL_accept yet again. */
                    MESSAGE("Still waiting on data for SSL_accept!");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    MESSAGE("Fatal internal error, abort.");
                default:
                    ERR_print_errors_fp(stderr);
                    /* Fatal error. Mark the session to terminate. */
                    *p_reap = true;
                }
            } else {
                /* We can move on with life */
                sess->st = STEK_SERVER_SESSION_STATE_RUNNING;
            }
        }
        break;
    case STEK_SERVER_SESSION_STATE_RUNNING:

        break;
    case STEK_SERVER_SESSION_STATE_CLOSING:
        /* Re-run the terminate command */
        if (0 >= (ssl_ret = SSL_shutdown(sess->conn))) {
            int ssl_err = SSL_ERROR_NONE;
            if (SSL_ERROR_NONE != (ssl_err = SSL_get_error(sess->conn, ssl_ret))) {
                switch (ssl_err) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    /* Do nothing. We'll need to call SSL_shutdown yet again. */
                    MESSAGE("Still waiting on data for SSL_shutdown!");
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    MESSAGE("Fatal internal error, marking for quick reap.");
                default:
                    ERR_print_errors_fp(stderr);
                    /* Fatal error. Mark the session to be reaped. */
                    *p_reap = true;
                    break;
                }
            }
        } else {
            sess->st = STEK_SERVER_SESSION_STATE_CLOSED;
        }
        break;
    case STEK_SERVER_SESSION_STATE_CLOSED:
        /* Signal the caller should terminate */
        MESSAGE("An I/O event on a closed session is a bit weird?");
        break;
    }

    ret = EXIT_SUCCESS;
done:
    return ret;
}

static
int stek_server_loop(SSL_CTX *ctx, int listen_fd)
{
    int ret = EXIT_FAILURE;

    static const unsigned STEK_SERVER_MAX_EVENTS = 10;
    struct epoll_event epev,
                       epevs[STEK_SERVER_MAX_EVENTS];
    int epfd = -1,
        nr_sessions = 0;
    LIST_HEAD(sess_terminate_pending);
    LIST_HEAD(sess_reap);

    if (0 > (epfd = epoll_create1(0))) {
        MESSAGE("Failed to create epoll file descriptor, aborting. %s (%d)",
                strerror(errno), errno);
        goto done;
    }

    /* Add the listener socket to the epoll fd */
    epev.events = EPOLLIN;
    epev.data.fd = listen_fd;
    if (0 > epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &epev)) {
        MESSAGE("Failed to add listener fd to epoll, aborting. %s (%d)",
                strerror(errno), errno);
        goto done;
    }

    MESSAGE("The server is on the air!");

    while (true == running || 0 != nr_sessions) {
        int nr_fd = 0;
        if (0 > (nr_fd = epoll_wait(epfd, epevs, STEK_SERVER_MAX_EVENTS, -1))) {
            if (EINTR != errno) {
                MESSAGE("Failed to get epoll(7) events, aborting. %s (%d)",
                        strerror(errno), errno);
                running = false;
                goto done;
            }
        }

        for (int i = 0; i < nr_fd; i++) {
            struct epoll_event *evt = &epevs[i];
            if (listen_fd == epevs[i].data.fd) {
                struct sockaddr_in addr = { 0 };
                socklen_t addr_len = sizeof(addr);
                struct epoll_event epev = { 0 };
                int new_conn = -1;
                struct stek_server_session *sess = NULL;

                /* We have a new connection to accept. */
                if (0 > (new_conn = accept4(listen_fd, (struct sockaddr *)&addr, &addr_len,
                                SOCK_NONBLOCK)))
                {
                    MESSAGE("Error while accept(2)'ing on listening socket. %s (%d)",
                            strerror(errno), errno);
                    /* Fail. This might be too brutal for a production use case. */
                    running = false;
                    goto done;
                }

                MESSAGE("New incoming connection from %s:%u",
                        inet_ntoa(addr.sin_addr), (unsigned)htons(addr.sin_port));

                /* Initialize a new SSL session */
                if (stek_server_new_session(&sess, new_conn, ctx, &addr)) {
                    /* TODO: Fixme, fail gracefully if this is non-fatal for other sessions */
                    MESSAGE("Failure while setting up new TLS session, aborting.");
                    running = false;
                    goto done;
                }

                /* Add socket, edge triggered on data to read or ready for write */
                epev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
                epev.data.ptr = sess;
                if (0 > epoll_ctl(epfd, EPOLL_CTL_ADD, new_conn, &epev)) {
                    MESSAGE("Error while adding socket to listening group. %s (%d)",
                            strerror(errno), errno);
                    running = false;
                    goto done;
                }

                nr_sessions++;
            } else {
                struct stek_server_session *ev_sess = (struct stek_server_session *)evt->data.ptr;
                bool reap = false;

                if (evt->events & EPOLLRDHUP || evt->events & EPOLLERR) {
                    /* Remove from epoll waiters */
                    if (0 > epoll_ctl(epfd, EPOLL_CTL_DEL, ev_sess->sess_fd, NULL)) {
                        MESSAGE("Error while removing file descriptor: %s (%d)",
                                strerror(errno), errno);
                        running = false;
                        goto done;
                    }

                    /* Prepare to move the session to an action list */
                    list_del(&ev_sess->s_node);

                    stek_server_terminate_session(ev_sess, &reap);
                    if (true == reap) {
                        list_append(&sess_reap, &ev_sess->s_node);
                    } else {
                        list_append(&sess_terminate_pending, &ev_sess->s_node);
                    }

                    /* Don't process any other events */
                    continue;
                }

                if (evt->events & EPOLLIN || evt->events & EPOLLOUT) {
                    if (stek_server_handle_io_event(ev_sess, !!(evt->events & EPOLLIN), &reap)) {
                        MESSAGE("Error while handling I/O event, terminating.");
                    }
                }
            }


        }

        /* We've been asked to terminate, so clean things up. By the time we get through all
         * this, the sessions that are active are all in either the reap or terminate pending
         * list, and the acceptor socket will be removed from the epoll group. We will just
         * need to wait for all the sessions to terminate gracefully, now.
         */
        if (true == terminating && true == running) {
            struct stek_server_session *sess = NULL;

            MESSAGE("We were asked to terminate, start cleanup.");
            running = false;

            /* Go through each session and push to terminate */
            list_for_each_type(sess, &active_sessions, s_node) {
                bool reap = false;
                /* Signal each session should terminate */
                stek_server_terminate_session(sess, &reap);

                if (true == reap) {
                    list_append(&sess_reap, &sess->s_node);
                } else {
                    list_append(&sess_terminate_pending, &sess->s_node);
                }
            }

            /* Remove the acceptor socket from epoll */
            MESSAGE("Removing the session acceptor from epoll list.");
            if (0 > epoll_ctl(epfd, EPOLL_CTL_DEL, listen_fd, NULL)) {
                MESSAGE("Failed to remove acceptor fd from epoll group, aborting. %s (%d)",
                        strerror(errno), errno);
                goto done;
            }
        }

        /* Reap any sessions marked to be reaped */
        struct stek_server_session *sess = NULL,
                                   *temp = NULL;

        list_for_each_type_safe(sess, temp, &sess_reap, s_node) {
            /* TODO: better error handling */
            MESSAGE("Found session in reap list for %s:%u", inet_ntoa(sess->remote.sin_addr),
                    (unsigned)htons(sess->remote.sin_port));
            stek_server_delete_session(&sess);

            if (0 > epoll_ctl(epfd, EPOLL_CTL_DEL, listen_fd, NULL)) {
                MESSAGE("Failed to remove acceptor fd from epoll group, aborting. %s (%d)",
                        strerror(errno), errno);
                goto done;
            }
            nr_sessions--;
        }

    }

    MESSAGE("Starting graceful server shutdown.");

    ret = EXIT_SUCCESS;
done:
    if (0 <= epfd) {
        close(epfd);
        epfd = -1;
    }

    return ret;
}

int main(int argc, const char *argv[])
{
    int ret = EXIT_FAILURE;

    SSL_CTX *ctx = NULL;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    EVP_PKEY *server_key = NULL;
    X509 *server_crt = NULL;
    int l_fd = -1;
    struct stek_common_keys *stek = NULL;

    MESSAGE("stek_test server... starting up!");

    /* Ignore SIGPIPE; we'll act on EPIPE instead */
    signal(SIGPIPE, SIG_IGN);

    /* Give us a chance to exit cleanly */
    signal(SIGINT, _handle_sigint);

    handle_args(argc, (char * const *)argv);

    /* Load Session Ticket encryption keyfile */
    if (STEK_IS_ERROR(stek_common_load_encryption_keys(&stek, stek_file))) {
        MESSAGE("Failed to load STEKs from disk, aborting.");
        goto done;
    }

    /* Load up the cert chain */
    if (STEK_IS_ERROR(stek_common_load_pem_cert(&server_crt, server_cert_file))) {
        MESSAGE("Failed to load server certificate chain from %s, aborting.",
                server_cert_file);
        goto done;
    }

    /* Load private key file */
    if (STEK_IS_ERROR(stek_common_load_pem_privkey(&server_key, private_key_file))) {
        MESSAGE("Failed to load private key from file %s, aborting.",
                private_key_file);
        goto done;
    }

    /* Create the TLS server context */
    if (STEK_IS_ERROR(stek_common_create_ssl_server_ctx(&ctx, stek))) {
        MESSAGE("Failed to create SSL server context, aborting.");
        goto done;
    }

    /* Attach the private key and certs */
    if (!SSL_CTX_use_PrivateKey(ctx, server_key)) {
        MESSAGE("Failed to attach private key to SSL_CTX, aborting.");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    if (!SSL_CTX_use_certificate(ctx, server_crt)) {
        MESSAGE("Failed to attach certificate to SSL_CTX, aborting.");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /* Bind to the appropriate port */
    addr.sin_port = htons(port);
    /* FIXME: force this to be specified on command line */
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (0 > (l_fd = socket(AF_INET, SOCK_STREAM, 0))) {
        MESSAGE("Failed to create socket: %s (%d)", strerror(errno), errno);
        goto done;
    }

    if (0 > (bind(l_fd, (struct sockaddr *)&addr, sizeof(addr)))) {
        MESSAGE("Failed to bind to port %u! %s (%d)", (unsigned)port,
                strerror(errno), errno);
        goto done;
    }

    if (0 > listen(l_fd, 10)) {
        MESSAGE("Failed to listen to bound socket. Reason: %s (%d)",
                strerror(errno), errno);
        goto done;
    }

    /* Kick off the main loop */
    stek_server_loop(ctx, l_fd);

    ret = EXIT_SUCCESS;
done:
    /* Clean up after ourselves */
    if (0 <= l_fd) {
        close(l_fd);
        l_fd = -1;
    }

    if (NULL != ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

    if (NULL != server_crt) {
        X509_free(server_crt);
        server_crt = NULL;
    }

    if (NULL != server_key) {
        EVP_PKEY_free(server_key);
        server_key = NULL;
    }
    return ret;
}

