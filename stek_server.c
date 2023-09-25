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
        fprintf(stderr, "User insisted we terminate ASAP, aborting.\n");
        exit(EXIT_FAILURE);
    }

    terminating = true;
    fprintf(stderr, "User asked that we terminate, trying to do so cleanly.\n");
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
            printf("Server certificate chain file: [%s]\n", server_cert_file);
            break;
        case 'c':
            client_cert_file = strdup(optarg);
            printf("Client certificate roots file: [%s]\n", client_cert_file);
            break;
        case 'S':
            stek_file = strdup(optarg);
            printf("Session Ticket Encryption Key file: [%s]\n", stek_file);
            break;
        case 'P':
            private_key_file = strdup(optarg);
            printf("Private key file: [%s]\n", private_key_file);
            break;
        case 'p':
            port = strtoul(optarg, NULL, 0);
            break;
        case 'v':
            stek_common_set_verbose(true);
            break;
        case 'h':
            show_help(argv[0]);
            break;
        default:
            printf("Unknown argument: %s\n", argv[opterr]);
            show_help(argv[0]);
        }
    }

    if (NULL == private_key_file) {
        printf("You must specify a private key file (-P)\n");
        show_help(argv[0]);
    }

    if (NULL == server_cert_file) {
        printf("You must specify a server certificate chain (-s)\n");
        show_help(argv[0]);
    }

    printf("Provisioned to listen  on TCP port %u\n", (unsigned)port);
}

static
int stek_server_new_session(struct stek_server_session **p_sess, int sess_fd, SSL_CTX *ctx)
{
    int ret = EXIT_FAILURE;

    struct stek_server_session *sess = NULL;
    BIO *s_bio = NULL;

    if (NULL == (sess = calloc(1, sizeof(struct stek_server_session)))) {
        printf("Out of memory during calloc(3), unable to allocate state for new session.\n");
        /* TODO: think about error handling */
        exit(ret);
    }

    if (NULL == (s_bio = BIO_new_socket(sess_fd, BIO_NOCLOSE))) {
        printf("Failed to create socket BIO. Aborting.\n");
        /* TODO: think about error handling */
        exit(ret);
    }

    sess->conn = SSL_new(ctx);

    SSL_set_bio(sess->conn, s_bio, s_bio);

    sess->st = STEK_SERVER_SESSION_STATE_STARTING;
    sess->sess_fd = sess_fd;
    list_append(&active_sessions, &sess->s_node);

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

/**
 * Consume any pending I/O event. This is also where we get a hint as to whether or not a session
 * should be considered closed and purged from our session list.
 */
static
int stek_server_handle_io_event(struct stek_server_session *sess, bool write_ready)
{
    int ret = EXIT_FAILURE;

    int ssl_ret = 0;

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
                    printf("Still waiting on data for SSL_accept!\n");
                    ERR_print_errors_fp(stderr);
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    printf("Fatal internal error, abort.\n");
                    ERR_print_errors_fp(stderr);
                    /* Fatal error. Mark the session to terminate. */
                    break;
                default:
                    printf("Weird out of state error code from OpenSSL: %d\n", ssl_err);
                }
            } else {
                /* We can move on with life */
                sess->st = STEK_SERVER_SESSION_STATE_RUNNING;
            }
        }
        break;
    case STEK_SERVER_SESSION_STATE_RUNNING:
        /* Re-run last command */
        break;
    case STEK_SERVER_SESSION_STATE_CLOSING:
        /* Re-run the terminate command */
        break;
    case STEK_SERVER_SESSION_STATE_CLOSED:
        /* Signal the caller should terminate */
        break;
    }

    ret = EXIT_SUCCESS;
done:
    return ret;
}

static
int stek_server_terminate_session(struct stek_server_session *sess)
{
    int ret = EXIT_FAILURE;

    int ssl_ret = 0;

    if (NULL == sess || NULL == sess->conn) {
        goto done;
    }

    sess->st = STEK_SERVER_SESSION_STATE_CLOSING;
    if (0 >= (ssl_ret = SSL_shutdown(sess->conn))) {
        
    }

    ret = EXIT_SUCCESS;
done:
    return ret;
}

static
int stek_server_delete_session(struct stek_server_session **p_sess)
{
    int ret = EXIT_FAILURE;

    struct stek_server_session *sess = NULL;

    if (NULL == p_sess) {
        printf("Tried to destroy NULL session, aborting.\n");
        goto done;
    }

    sess = *p_sess;

    if (STEK_SERVER_SESSION_STATE_CLOSED != sess->st) {
        printf("Tried to kill a session in flight, aborting.\n");
        goto done;
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
int stek_server_loop(SSL_CTX *ctx, int listen_fd)
{
    int ret = EXIT_FAILURE;

    static const unsigned STEK_SERVER_MAX_EVENTS = 10;
    struct epoll_event epev,
                       epevs[STEK_SERVER_MAX_EVENTS];
    int epfd = -1,
        nr_sessions = 0;

    if (0 > (epfd = epoll_create1(0))) {
        fprintf(stderr, "Failed to create epoll file descriptor, aborting. %s (%d)\n",
                strerror(errno), errno);
        goto done;
    }

    /* Add the listener socket to the epoll fd */
    epev.events = EPOLLIN;
    epev.data.fd = listen_fd;
    if (0 > epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &epev)) {
        fprintf(stderr, "Failed to add listener fd to epoll, aborting. %s (%d)\n",
                strerror(errno), errno);
        goto done;
    }

    fprintf(stderr, "The server is on the air!\n");

    while (true == running || 0 != nr_sessions) {
        int nr_fd = 0;
        if (0 > (nr_fd = epoll_wait(epfd, epevs, STEK_SERVER_MAX_EVENTS, -1))) {
            if (EINTR != errno) {
                fprintf(stderr, "Failed to get epoll(7) events, aborting. %s (%d)\n",
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
                    fprintf(stderr, "Error while accept(2)'ing on listening socket. %s (%d)\n",
                            strerror(errno), errno);
                    /* Fail. This might be too brutal for a production use case. */
                    running = false;
                    goto done;
                }

                fprintf(stderr, "New incoming connection from %s:%u\n",
                        inet_ntoa(addr.sin_addr), (unsigned)htons(addr.sin_port));

                /* Initialize a new SSL session */
                if (stek_server_new_session(&sess, new_conn, ctx)) {
                    /* TODO: Fixme, fail gracefully if this is non-fatal for other sessions */
                    fprintf(stderr, "Failure while setting up new TLS session, aborting.\n");
                    running = false;
                    goto done;
                }

                /* Add socket, edge triggered on data to read or ready for write */
                epev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
                epev.data.ptr = sess;
                if (0 > epoll_ctl(epfd, EPOLL_CTL_ADD, new_conn, &epev)) {
                    fprintf(stderr, "Error while adding socket to listening group. %s (%d)\n",
                            strerror(errno), errno);
                    running = false;
                    goto done;
                }
            } else {
                struct stek_server_session *ev_sess = (struct stek_server_session *)evt->data.ptr;

                if (evt->events & EPOLLRDHUP) {
                    /* Remove from epoll waiters */
                    if (0 > epoll_ctl(epfd, EPOLL_CTL_DEL, ev_sess->sess_fd, NULL)) {
                        fprintf(stderr, "Error while removing file descriptor: %s (%d)\n",
                                strerror(errno), errno);
                        running = false;
                        goto done;
                    }

                    stek_server_delete_session(&ev_sess);

                    /* Don't process any other events */
                    continue;
                }

                if (evt->events & EPOLLERR) {

                }

                if (evt->events & EPOLLIN || evt->events & EPOLLOUT) {
                    if (stek_server_handle_io_event(ev_sess, !!(evt->events & EPOLLIN))) {
                        fprintf(stderr, "Error while handling I/O event, terminating.\n");
                    }
                }
            }

            if (true == terminating) {
                struct stek_server_session *sess = NULL;

                fprintf(stderr, "We were asked to terminate.\n");
                running = false;

                /* Go through each session and push to terminate */
                list_for_each_type(sess, &active_sessions, s_node) {
                    /* Signal each session should terminate */
                    stek_server_terminate_session(sess);
                }
            }
        }
    }

    fprintf(stderr, "Starting graceful server shutdown.\n");

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

    printf("stek_test server... starting up!\n");

    /* Ignore SIGPIPE; we'll act on EPIPE instead */
    signal(SIGPIPE, SIG_IGN);

    /* Give us a chance to exit cleanly */
    signal(SIGINT, _handle_sigint);

    handle_args(argc, (char * const *)argv);

    if (STEK_IS_ERROR(stek_common_create_ssl_server_ctx(&ctx, NULL))) {
        fprintf(stderr, "Failed to create SSL server context, aborting.\n");
        goto done;
    }

    /* Load up the cert chain */
    if (STEK_IS_ERROR(stek_common_load_pem_cert(&server_crt, server_cert_file))) {
        fprintf(stderr, "Failed to load server certificate chain from %s, aborting.\n",
                server_cert_file);
        goto done;
    }

    /* Load private key file */
    if (STEK_IS_ERROR(stek_common_load_pem_privkey(&server_key, private_key_file))) {
        fprintf(stderr, "Failed to load private key from file %s, aborting.\n",
                private_key_file);
        goto done;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, server_key)) {
        fprintf(stderr, "Failed to attach private key to SSL_CTX, aborting.\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    if (!SSL_CTX_use_certificate(ctx, server_crt)) {
        fprintf(stderr, "Failed to attach certificate to SSL_CTX, aborting.\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /* TODO: Load Session Ticket encryption keyfile */

    addr.sin_port = htons(port);
    /* FIXME: force this to be specified on command line */
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (0 > (l_fd = socket(AF_INET, SOCK_STREAM, 0))) {
        fprintf(stderr, "Failed to create socket: %s (%d)\n", strerror(errno), errno);
        goto done;
    }

    if (0 > (bind(l_fd, (struct sockaddr *)&addr, sizeof(addr)))) {
        fprintf(stderr, "Failed to bind to port %u! %s (%d)\n", (unsigned)port,
                strerror(errno), errno);
        goto done;
    }

    if (0 > listen(l_fd, 10)) {
        fprintf(stderr, "Failed to listen to bound socket. Reason: %s (%d)\n",
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

