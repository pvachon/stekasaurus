#include "stek_common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <cbor.h>

#include <stdbool.h>
#include <stdio.h>

#define AES256_KEY_LENGTH       32
#define HMAC_KEY_LENGTH         32

/**
 * Structure representing a set of STEKs
 */
struct stek_common_keys {
    uint64_t valid_to_epoch;
    uint64_t valid_from_epoch;
    uint8_t wrap_key[AES256_KEY_LENGTH];
    uint8_t hmac_key[HMAC_KEY_LENGTH];
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

static
struct stek_common_keys *_g_stek_common_current = NULL;

void stek_common_set_verbose(bool verbose)
{
    _stek_common_verbose = verbose;
}

static
int _stek_common_ssl_ticket_encrypt(unsigned char *iv, EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx)
{
    int ret = -1;

    OSSL_PARAM hctx_params[3];

    if (1 != RAND_bytes(iv, 16)) {
        MSG("Insufficient entropy, aborting.");
        ret = 0;
        goto done;
    }

    /* Set up encryption */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, _g_stek_common_current->wrap_key, iv)) {
        MSG("Failed to intialize encryption context, aborting.");
        OSSL_ERRS();
        ret = 0;
        goto done;
    }

    /* Set up HMAC calculation */
    hctx_params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, _g_stek_common_current->hmac_key, 32);
    hctx_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "sha256", 0);
    hctx_params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_CTX_set_params(hctx, hctx_params)) {
        MSG("Error while setting up HMAC context, aborting.");
        OSSL_ERRS();
        ret = 0;
        goto done;
    }

    ret = 1;
done:
    return ret;
}

static
int _stek_common_ssl_ticket_decrypt(unsigned char *iv, EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx)
{
    int ret = -1;

    OSSL_PARAM hctx_params[3];

    /* Set up decryption */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, _g_stek_common_current->wrap_key, iv)) {
        MSG("Failed to intialize encryption context, aborting.");
        OSSL_ERRS();
        ret = 0;
        goto done;
    }

    /* Set up HMAC calculation */
    hctx_params[0] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, _g_stek_common_current->hmac_key, 32);
    hctx_params[1] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "sha256", 0);
    hctx_params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_CTX_set_params(hctx, hctx_params)) {
        MSG("Error while setting up HMAC context, aborting.");
        OSSL_ERRS();
        ret = 0;
        goto done;
    }

    ret = 1;
done:
    return ret;
}

static
int _stek_common_ssl_ticket_encrypt_cb(SSL *s, unsigned char key_name[16], unsigned char *iv,
                                       EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx, int enc)
{
    if (NULL == _g_stek_common_current) {
        MSG("No STEKs configured, failing.");
        return -1;
    }

    if (1 == enc) {
        memset(key_name, 0, 16);
        return _stek_common_ssl_ticket_encrypt(iv, ctx, hctx);
    } else {
        return _stek_common_ssl_ticket_decrypt(iv, ctx, hctx);
    }
}

sresult_t stek_common_free_encryption_keys(struct stek_common_keys **p_stek)
{
    sresult_t ret = STEK_OK;

    struct stek_common_keys *stek = NULL;

    STEK_ASSERT_ARG(NULL != p_stek);

    stek = *p_stek;
    free(stek);

    *p_stek = NULL;

    return ret;
}

sresult_t stek_common_load_encryption_keys(struct stek_common_keys **p_stek, const char *filename)
{
    sresult_t ret = STEK_OK;

    struct stek_common_keys *stek = NULL;
    FILE *fp = NULL;
    long len = 0;
    uint8_t *raw_cbor = NULL;
    cbor_item_t *root = NULL;
    struct cbor_load_result raw_stek_cbor_ret = { 0 };

    STEK_ASSERT_ARG(NULL != p_stek);
    STEK_ASSERT_ARG(NULL != filename);

    *p_stek = NULL;

    if (NULL == (fp = fopen(filename, "rb"))) {
        MSG("Failed to open file [%s] to read STEKs, aborting.", filename);
        ret = STEK_ERROR_BAD_FILE;
        goto done;
    }

    if (0 > (fseek(fp, 0, SEEK_END))) {
        MSG("Failed to seek to end of file [%s], aborting.", filename);
        ret = STEK_ERROR_BAD_FILE;
        goto done;
    }

    if (0 > (len = ftell(fp))) {
        MSG("Error while getting file length of [%s], aborting.", filename);
        ret = STEK_ERROR_BAD_FILE;
        goto done;
    }

    rewind(fp);

    if (NULL == (raw_cbor = calloc(1, len))) {
        MSG("Failed to allocate %ld bytes for raw STEK CBOR, aborting.", len);
        ret = STEK_ERROR_NO_MEMORY;
        goto done;
    }

    if (len != fread(raw_cbor, 1, len, fp)) {
        MSG("Failed to read full %ld bytes from STEK CBOR, aborting.", len);
        ret = STEK_ERROR_NO_MEMORY;
        goto done;
    }

    /* Decode the CBOR */
    root = cbor_load(raw_cbor, len, &raw_stek_cbor_ret);
    /* TODO: error check on our attempt to load the CBOR data */
    if  (true == _stek_common_verbose) {
        fprintf(stderr, "CBOR dump of STEK file: \n");
        cbor_describe(root, stderr);
    }

    /* Now populate the STEK structure */
    if (NULL == (stek = calloc(1, sizeof(struct stek_common_keys)))) {
        MSG("Failed to allocate %zu bytes for STEK structure", sizeof(struct stek_common_keys));
        ret = STEK_ERROR_NO_MEMORY;
        goto done;
    }

    if (false == cbor_isa_map(root)) {
        MSG("STEK file root should be a map, aborting.");
        ret = STEK_ERROR_FACIL_CBOR;
        goto done;
    }

    struct cbor_pair *stek_map = cbor_map_handle(root);

    bool have_valid_from = false,
         have_valid_to = false,
         have_service_name = false,
         have_hmac_key = false,
         have_wrap_key = false;

    int stek_version = -1;

    for (size_t i = 0; i < cbor_map_size(root); i++) {
        struct cbor_pair *it = &stek_map[i];
        char *key = NULL;

        /* Extract the name of this key */
        if (!cbor_isa_string(it->key)) {
            MSG("Item %zu has a key that is not a string, aborting.", i);
            ret = STEK_ERROR_MALFORMED_STEK;
            goto done;
        }

        key = (char *)cbor_string_handle(it->key);

        /* Now get the value */
        if (!strcmp("version", key)) {
            if (!cbor_isa_uint(it->value)) {
                MSG("The 'version' field must be an unsigned integer");
                ret = STEK_ERROR_MALFORMED_STEK;
                goto done;
            }

            stek_version = cbor_get_int(it->value);
        } else if (!strcmp("serviceName", key)) {
            if (!cbor_isa_string(it->value)) {
                MSG("The 'serviceName' field must be a string");
                ret = STEK_ERROR_MALFORMED_STEK;
                goto done;
            }

            have_service_name = true;
            /* TODO: we should capture this so the caller can map its keys properly */
        } else if (!strcmp("validFrom", key)) {
            if (!(cbor_isa_uint(it->value)) ||
                    (CBOR_INT_32 != cbor_int_get_width(it->value)))
            {
                MSG("The 'validFrom' field must be an unsigned 32-bit integer");
                ret = STEK_ERROR_MALFORMED_STEK;
                goto done;
            }

            have_valid_from = true;
            stek->valid_from_epoch = cbor_get_uint32(it->value);
        } else if (!strcmp("validTo", key)) {
            if ((!cbor_isa_uint(it->value)) ||
                    (CBOR_INT_32 != cbor_int_get_width(it->value)))
            {
                MSG("The 'validTo' field must be an unsigned 32-bit integer");
                ret = STEK_ERROR_MALFORMED_STEK;
                goto done;
            }

            have_valid_to = true;
            stek->valid_to_epoch = cbor_get_uint32(it->value);
        } else if (!strcmp("wrapKey", key)) {
            if ((!cbor_isa_bytestring(it->value)) ||
                    (AES256_KEY_LENGTH != cbor_bytestring_length(it->value)))
            {
                MSG("The 'wrapKey' must be a valid bytestring of length 32");
                ret = STEK_ERROR_MALFORMED_STEK;
                goto done;
            }

            have_wrap_key = true;
            memcpy(stek->wrap_key, cbor_bytestring_handle(it->value), AES256_KEY_LENGTH);
        } else if (!strcmp("hmacKey", key)) {
            if ((!cbor_isa_bytestring(it->value)) ||
                    (HMAC_KEY_LENGTH != cbor_bytestring_length(it->value)))
            {
                MSG("The 'hmacKey' must be a valid bytestring of length 32");
                ret = STEK_ERROR_MALFORMED_STEK;
                goto done;
            }

            have_hmac_key = true;
            memcpy(stek->hmac_key, cbor_bytestring_handle(it->value), HMAC_KEY_LENGTH);
        } else {
            MSG("WARNING: Unknown field name: [%s]", key);
        }
    }

    /* Check STEK version matches what we support */
    if (stek_version != 1) {
        MSG("We only can handle version 1 STEK files, aborting.");
        ret = STEK_ERROR_MALFORMED_STEK;
        goto done;
    }

    /* Make sure all relevant fields are populated */
    if (!(have_valid_from || have_valid_to || have_service_name || have_hmac_key || have_wrap_key)) {
        MSG("Error: missing required field from STEK, aborting.");
        ret = STEK_ERROR_MALFORMED_STEK;
        goto done;
    }

    *p_stek = stek;
done:
    if (NULL != root) {
        cbor_decref(&root);
        root = NULL;
    }

    free(raw_cbor);
    raw_cbor = NULL;

    if (NULL != fp) {
        fclose(fp);
        fp = NULL;
    }

    if (STEK_IS_ERROR(ret)) {
        if (NULL != stek) {
            free(stek);
        }
    }

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

sresult_t stek_common_create_ssl_server_ctx(SSL_CTX **p_ctx, struct stek_common_keys *stek)
{
    sresult_t ret = STEK_OK;

    SSL_CTX *ctx = NULL;

    STEK_ASSERT_ARG(NULL != p_ctx);
    STEK_ASSERT_ARG(NULL != stek);

    *p_ctx = NULL;

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

    /* Keep the STEK as a global value (yeah, this is crap) */
    _g_stek_common_current = stek;

    /* Set the STEK handling callback */
    if (!SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, _stek_common_ssl_ticket_encrypt_cb)) {
        OSSL_ERRS();
        ret = STEK_ERROR_CREATE_CTX;
        goto done;
    }

    *p_ctx = ctx;
done:
    if (STEK_IS_ERROR(ret)) {
        if (NULL != ctx) {
            SSL_CTX_free(ctx);
            ctx = NULL;
        }
    }

    return ret;
}

