#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * Every STEK library related function returns an sresult_t
 */
typedef uint32_t sresult_t;

/*
 * Set up error code definition
 */
#define STEK_ERROR_BIT                      (sresult_t)(0x80000000ul)
#define STEK_ERROR(_f, _c)                  (sresult_t)(((_f) & 0x7fff) << 16 | (_c) & 0xffff | STEK_ERROR_BIT)
#define STEK_IS_ERROR(_x)                   (!!((_x) & STEK_ERROR_BIT))

#define STEK_ERROR_FACIL_CORE               0
#define STEK_ERROR_FACIL_OPENSSL            1
#define STEK_ERROR_FACIL_CBOR               2

#define STEK_OK                             0

/*
 * Generic error codes
 */
#define STEK_ERROR_BAD_PARAM                STEK_ERROR(STEK_ERROR_FACIL_CORE, 1)
#define STEK_ERROR_NO_MEMORY                STEK_ERROR(STEK_ERROR_FACIL_CORE, 2)
#define STEK_ERROR_BAD_FILE                 STEK_ERROR(STEK_ERROR_FACIL_CORE, 3)

/*
 * Specific error codes for errors that surface from OpenSSL
 */
#define STEK_ERROR_CREATE_CTX               STEK_ERROR(STEK_ERROR_FACIL_OPENSSL, 1)
#define STEK_ERROR_READ_PRIV_KEY            STEK_ERROR(STEK_ERROR_FACIL_OPENSSL, 2)
#define STEK_ERROR_READ_CERT                STEK_ERROR(STEK_ERROR_FACIL_OPENSSL, 3)

/*
 * CBOR load/decode error codes
 */
#define STEK_ERROR_MALFORMED_STEK           STEK_ERROR(STEK_ERROR_FACIL_CBOR, 1)

/*
 * Forward declarations for various OpenSSL structs we expose in the library interface.
 */
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;

struct stek_common_keys;

/**
 * Set verbose output on errors
 */
void stek_common_set_verbose(bool verbose);

/**
 * Given a CBOR file containing the STEKs, load it into the stek_keys structure for use during
 * server handshakes.
 */
sresult_t stek_common_load_encryption_keys(struct stek_common_keys **p_stek, const char *filename);

/**
 * Free the STEK data held in memory.
 */
sresult_t stek_common_free_encryption_keys(struct stek_common_keys **p_stek);

/**
 * Given a PEM file containing a certificate chain, load it up into the specified X509
 */
sresult_t stek_common_load_pem_cert(X509 **p_crt, const char *filename);

/**
 * Given a PEM file containing a private key, load it up into the specified SSL_CTX
 */
sresult_t stek_common_load_pem_privkey(EVP_PKEY **p_key, const char *filename);

/**
 * Create a new SSL_CTX for TLSv1.3 that is properly configured.
 */
sresult_t stek_common_create_ssl_server_ctx(SSL_CTX **p_ctx, struct stek_common_keys *stek);

/**
 * Create a new SSL_CTX for TLSv1.3 that is properly configured.
 */
sresult_t stek_common_create_ssl_client_ctx(SSL_CTX **p_ctx);

