#include "stek_common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

#include <stdbool.h>
#include <stdio.h>

/**
 * Structure representing a set of STEKs
 */
struct stek_keys {

};

#define OSSL_ERRS() do { if (true == _stek_common_verbose) { \
    ERR_print_errors_fp(stderr); } } while (0);

#define MSG(x, ...) do { if (true == _stek_common_verbose) { \
    fprintf(stderr, x "\n", ##__VA_ARGS__); } } while (0);

#define STEK_ASSERT_ARG(_ast) do { if (!((_ast))) { \
    MSG("Argument assertion failed: " #_ast " is false."); \
    return STEK_ERROR_BAD_PARAM; } } while (0);

static
bool _stek_common_verbose = false;

void stek_common_set_verbose(bool verbose)
{
    _stek_common_verbose = verbose;
}

sresult_t stek_common_load_encryption_keys(struct stek_keys **p_stek, const char *filename)
{
    sresult_t ret = STEK_OK;

    struct stek_keys *stek = NULL;

    STEK_ASSERT_ARG(NULL != p_stek);
    STEK_ASSERT_ARG(NULL != filename);

    *p_stek = NULL;

    if (NULL == (stek = calloc(1, sizeof(struct stek_keys)))) {
        MSG("Failed to allocate %zu bytes for STEK structure", sizeof(struct stek_keys));
        ret = STEK_ERROR_NO_MEMORY;
        goto done;
    }

done:
    return ret;
}

sresult_t stek_common_load_pem_cert(X509 **p_crt, const char *filename)
{
    sresult_t ret = STEK_OK;

    X509 *crt = NULL;
    FILE *fp = NULL;

    STEK_ASSERT_ARG(NULL != p_crt);
    STEK_ASSERT_ARG(NULL != filename);

    *p_crt = NULL;

    if (NULL == (fp = fopen(filename, "rb"))) {
        MSG("Failed to open file %s to read key in. %s (%d)", filename, strerror(errno), errno);
        ret = STEK_ERROR_BAD_FILE;
        goto done;
    }

    if (NULL == (PEM_read_X509(fp, &crt, NULL, NULL))) {
        MSG("Failed to read X.509 cert from file %s, aborting.", filename);
        ERR_print_errors_fp(stderr);
        ret = STEK_ERROR_READ_CERT;
        goto done;
    }

    *p_crt = crt;

done:
    if (NULL != fp) {
        fclose(fp);
        fp = NULL;
    }

    if (STEK_IS_ERROR(ret)) {
        if (NULL != crt) {
            X509_free(crt);
            crt = NULL;
        }
    }
    return ret;
}

sresult_t stek_common_load_pem_privkey(EVP_PKEY **p_key, const char *filename)
{
    sresult_t ret = STEK_OK;

    EVP_PKEY *key = NULL;
    FILE *fp = NULL;

    STEK_ASSERT_ARG(NULL != p_key);
    STEK_ASSERT_ARG(NULL != filename);

    *p_key = NULL;

    if (NULL == (fp = fopen(filename, "rb"))) {
        MSG("Failed to open file %s to read key in. %s (%d)", filename, strerror(errno), errno);
        ret = STEK_ERROR_BAD_FILE;
        goto done;
    }

    if (NULL == (key = PEM_read_PrivateKey(fp, &key, NULL, NULL))) {
        MSG("Failure while reading in private key from %s", filename);
        OSSL_ERRS();
        ret = STEK_ERROR_READ_PRIV_KEY;
        goto done;
    }

    *p_key = key;

done:
    if (NULL != fp) {
        fclose(fp);
        fp = NULL;
    }

    if (STEK_IS_ERROR(ret)) {
        if (NULL != key) {
            EVP_PKEY_free(key);
            key = NULL;
        }
    }

    return ret;
}

sresult_t stek_common_create_ssl_server_ctx(SSL_CTX **p_ctx, struct stek_keys *stek)
{
    sresult_t ret = STEK_OK;

    SSL_CTX *ctx = NULL;

    if (NULL == p_ctx) {
        ret = STEK_ERROR_BAD_PARAM;
        goto done;
    }

    if (NULL == (ctx = SSL_CTX_new(TLS_server_method()))) {
        OSSL_ERRS();
        ret = STEK_ERROR_CREATE_CTX;
        MSG("Error while creating SSL_CTX for server, aborting.");
        goto done;
    }

    /* Ensure we only support TLS 1.3 or later */
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        OSSL_ERRS();
        ret = STEK_ERROR_CREATE_CTX;
        goto done;
    }

    /* Set the STEK handling callback */

done:
    if (STEK_IS_ERROR(ret)) {
        if (NULL != ctx) {
            SSL_CTX_free(ctx);
            ctx = NULL;
        }
    }

    *p_ctx = ctx;

    return ret;
}


