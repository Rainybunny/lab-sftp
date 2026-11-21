/**
 * @file dh.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Diffie-Hellman key exchange functionalities.
 * @version 0.1
 * @date 2022-10-06
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/dh.h"

#include "libsftp/bignum.h"
#include "libsftp/buffer.h"
#include "libsftp/crypto.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/pki.h"
#include "libsftp/session.h"
#include "libsftp/util.h"

struct dh_keypair {
    bignum priv_key;
    bignum pub_key;
};

struct dh_ctx {
    /* 0 is client, 1 is server */
    struct dh_keypair keypair[2];
    bignum generator;
    bignum modulus;
};

static int dh_keypair_gen_keys(struct dh_ctx *ctx, int peer);
static int dh_keypair_get_keys(struct dh_ctx *ctx, int peer, const_bignum *priv,
                               const_bignum *pub);
static int dh_keypair_set_keys(struct dh_ctx *ctx, int peer, bignum priv,
                               bignum pub);
static int dh_init_keypair(struct dh_keypair *keypair);
static void dh_free_keypair(struct dh_keypair *keypair);

static int dh_init(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    struct dh_ctx *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL) return SSH_ERROR;
    crypto->dh_ctx = ctx;

    /* SSH group1 uses the 1024-bit Oakley Group 2 prime. */
    ctx->modulus = BN_get_rfc2409_prime_1024(NULL);
    ctx->generator = bignum_new();
    if (ctx->modulus == NULL || ctx->generator == NULL ||
        bignum_set_word(ctx->generator, 2) != 1 ||
        dh_init_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]) != SSH_OK) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

void dh_cleanup(struct ssh_crypto_struct *crypto) {
    struct dh_ctx *ctx = crypto->dh_ctx;

    if (ctx == NULL) {
        return;
    }

    dh_free_keypair(&ctx->keypair[DH_CLIENT_KEYPAIR]);
    dh_free_keypair(&ctx->keypair[DH_SERVER_KEYPAIR]);

    bignum_safe_free(ctx->modulus);
    bignum_safe_free(ctx->generator);
    SAFE_FREE(crypto->dh_ctx);
}

static int dh_keypair_gen_keys(struct dh_ctx *dh_ctx, int peer) {
    struct dh_keypair *keys = &dh_ctx->keypair[peer];
    bignum q = bignum_new();
    bignum_CTX ctx = bignum_ctx_new();
    int rc = SSH_ERROR;

    if (q == NULL || ctx == NULL ||
        bignum_rshift1(q, dh_ctx->modulus) != 1) {
        goto done;
    }

    /* q = (p - 1) / 2. The private exponent must satisfy 1 < x < q. */
    do {
        if (bignum_rand_range(keys->priv_key, q) != 1) goto done;
    } while (bignum_cmp(keys->priv_key, BN_value_one()) <= 0);

    if (bignum_mod_exp(keys->pub_key, dh_ctx->generator, keys->priv_key,
                       dh_ctx->modulus, ctx) == 1) {
        rc = SSH_OK;
    }

done:
    bignum_safe_free(q);
    bignum_ctx_free(ctx);
    return rc;
}

static int dh_keypair_get_keys(struct dh_ctx *ctx, int peer, const_bignum *priv,
                               const_bignum *pub) {
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        /* check that we have something in it */
        if (bignum_num_bits(ctx->keypair[peer].priv_key)) {
            *priv = ctx->keypair[peer].priv_key;
        } else {
            return SSH_ERROR;
        }
    }

    if (pub) {
        /* check that we have something in it */
        if (bignum_num_bits(ctx->keypair[peer].pub_key)) {
            *pub = ctx->keypair[peer].pub_key;
        } else {
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

static int dh_keypair_set_keys(struct dh_ctx *ctx, int peer, bignum priv,
                               bignum pub) {
    if (((peer != DH_CLIENT_KEYPAIR) && (peer != DH_SERVER_KEYPAIR)) ||
        ((priv == NULL) && (pub == NULL)) || (ctx == NULL)) {
        return SSH_ERROR;
    }

    if (priv) {
        bignum_safe_free(ctx->keypair[peer].priv_key);
        ctx->keypair[peer].priv_key = priv;
    }
    if (pub) {
        bignum_safe_free(ctx->keypair[peer].pub_key);
        ctx->keypair[peer].pub_key = pub;
    }
    return SSH_OK;
}

static void dh_free_keypair(struct dh_keypair *keypair) {
    bignum_safe_free(keypair->priv_key);
    bignum_safe_free(keypair->pub_key);
}

static int dh_init_keypair(struct dh_keypair *keypair) {
    keypair->priv_key = bignum_new();
    if (keypair->priv_key == NULL) goto error;

    keypair->pub_key = bignum_new();
    if (keypair->pub_key == NULL) goto error;

    return SSH_OK;

error:
    dh_free_keypair(keypair);
    return SSH_ERROR;
}

/**
 * @brief Compute shared secret K in key exchange procedure.
 *
 * @param dh_ctx
 * @param local
 * @param remote
 * @param dest
 * @return int
 */
static int dh_compute_shared_secret(struct dh_ctx *dh_ctx, int local,
                                    int remote, bignum *dest) {
    int rc;
    bignum_CTX ctx = bignum_ctx_new();
    if (bignum_ctx_invalid(ctx)) {
        return SSH_ERROR;
    }

    if (*dest == NULL) {
        *dest = bignum_new();
        if (*dest == NULL) {
            rc = 0;
            goto done;
        }
    }

    rc = bignum_mod_exp(*dest, dh_ctx->keypair[remote].pub_key,
                        dh_ctx->keypair[local].priv_key, dh_ctx->modulus, ctx);

done:
    bignum_ctx_free(ctx);
    if (rc != 1) {
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Compute session identifier H in key exchange procedure.
 *
 * @param session
 * @return int
 */
static int dh_compute_session_id(ssh_session session) {
    ssh_buffer server_hash = session->in_hashbuf;
    ssh_buffer client_hash = session->out_hashbuf;
    uint32_t server_hash_len = ssh_buffer_get_len(server_hash);
    uint32_t client_hash_len = ssh_buffer_get_len(client_hash);
    ssh_buffer buf = ssh_buffer_new();
    const_bignum client_pubkey, server_pubkey;
    int rc;

    if (buf == NULL) return SSH_ERROR;

    rc = ssh_buffer_pack(buf, "ss", session->client_id_str,
                         session->server_id_str);
    if (rc != SSH_OK) goto error;

    rc = ssh_buffer_pack(buf, "dPdPS",
                         client_hash_len, (size_t)client_hash_len,
                         ssh_buffer_get(client_hash),
                         server_hash_len, (size_t)server_hash_len,
                         ssh_buffer_get(server_hash),
                         session->next_crypto->server_pubkey_blob);
    if (rc != SSH_OK) goto error;

    rc = dh_keypair_get_keys(session->next_crypto->dh_ctx, DH_CLIENT_KEYPAIR,
                             NULL, &client_pubkey);
    rc |= dh_keypair_get_keys(session->next_crypto->dh_ctx, DH_SERVER_KEYPAIR,
                              NULL, &server_pubkey);
    if (rc != SSH_OK) goto error;

    rc = ssh_buffer_pack(buf, "BBB", client_pubkey, server_pubkey,
                         session->next_crypto->shared_secret);
    if (rc != SSH_OK) goto error;

    session->next_crypto->digest_len = SHA_DIGEST_LENGTH;
    session->next_crypto->digest_type = SSH_KDF_SHA1;
    session->next_crypto->secret_hash =
        malloc(session->next_crypto->digest_len);
    if (session->next_crypto->secret_hash == NULL) goto error;
    sha1(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
         session->next_crypto->secret_hash);

    if (session->next_crypto->session_id == NULL) {
        session->next_crypto->session_id_len = session->next_crypto->digest_len;
        session->next_crypto->session_id =
            malloc(session->next_crypto->session_id_len);
        if (session->next_crypto->session_id == NULL) goto error;
        memcpy(session->next_crypto->session_id,
               session->next_crypto->secret_hash,
               session->next_crypto->session_id_len);
    }

    ssh_buffer_free(buf);
    return SSH_OK;
error:
    ssh_buffer_free(buf);
    return SSH_ERROR;
}

/**
 * @brief Derive and set session keys from shared secret K and session
 * identifier H.
 * @see RFC4253 section 7.1
 * @param session
 * @return int
 */
static int dh_gen_session_keys(ssh_session session) {
    ssh_string k_string = NULL;
    struct ssh_crypto_struct *crypto = session->next_crypto;
    unsigned char *key = NULL;
    unsigned char *IV_cli_to_srv = NULL;
    unsigned char *IV_srv_to_cli = NULL;
    unsigned char *enckey_cli_to_srv = NULL;
    unsigned char *enckey_srv_to_cli = NULL;
    unsigned char *intkey_cli_to_srv = NULL;
    unsigned char *intkey_srv_to_cli = NULL;
    size_t key_len = 0;
    size_t IV_len = 0;
    size_t enckey_cli_to_srv_len = 0;
    size_t enckey_srv_to_cli_len = 0;
    size_t intkey_cli_to_srv_len = 0;
    size_t intkey_srv_to_cli_len = 0;
    int rc = -1;

    k_string = ssh_make_bignum_string(crypto->shared_secret);
    if (k_string == NULL) goto error;
    /* See RFC4251 Section 5 for the definition of mpint which is the
     * encoding we need to use for key in the SSH KDF */
    key = (unsigned char *)k_string;
    key_len = ssh_string_len(k_string) + 4;

    IV_len = crypto->digest_len;

    enckey_cli_to_srv_len = crypto->out_cipher->keysize / 8;
    enckey_srv_to_cli_len = crypto->in_cipher->keysize / 8;
    intkey_cli_to_srv_len = hmac_digest_len(crypto->out_hmac);
    intkey_srv_to_cli_len = hmac_digest_len(crypto->in_hmac);

    IV_cli_to_srv = malloc(IV_len);
    IV_srv_to_cli = malloc(IV_len);
    enckey_cli_to_srv = malloc(enckey_cli_to_srv_len);
    enckey_srv_to_cli = malloc(enckey_srv_to_cli_len);
    intkey_cli_to_srv = malloc(intkey_cli_to_srv_len);
    intkey_srv_to_cli = malloc(intkey_srv_to_cli_len);
    if (IV_cli_to_srv == NULL || IV_srv_to_cli == NULL ||
        enckey_cli_to_srv == NULL || enckey_srv_to_cli == NULL ||
        intkey_cli_to_srv == NULL || intkey_srv_to_cli == NULL) {
        goto error;
    }

    /* IV */
    rc = ssh_kdf(crypto, key, key_len, 'A', IV_cli_to_srv, IV_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'B', IV_srv_to_cli, IV_len);
    if (rc < 0) {
        goto error;
    }
    /* Encryption Key */
    rc = ssh_kdf(crypto, key, key_len, 'C', enckey_cli_to_srv,
                 enckey_cli_to_srv_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'D', enckey_srv_to_cli,
                 enckey_srv_to_cli_len);
    if (rc < 0) {
        goto error;
    }
    /* Integrity Key */
    rc = ssh_kdf(crypto, key, key_len, 'E', intkey_cli_to_srv,
                 intkey_cli_to_srv_len);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_kdf(crypto, key, key_len, 'F', intkey_srv_to_cli,
                 intkey_srv_to_cli_len);
    if (rc < 0) {
        goto error;
    }

    ssh_string_burn(k_string);
    ssh_string_free(k_string);
    crypto->encryptIV = IV_cli_to_srv;
    crypto->decryptIV = IV_srv_to_cli;
    crypto->encryptkey = enckey_cli_to_srv;
    crypto->decryptkey = enckey_srv_to_cli;
    crypto->encryptMAC = intkey_cli_to_srv;
    crypto->decryptMAC = intkey_srv_to_cli;

    /* Initialize the encryption and decryption keys in next_crypto */
    rc = session->next_crypto->in_cipher->set_decrypt_key(
        session->next_crypto->in_cipher, session->next_crypto->decryptkey,
        session->next_crypto->decryptIV);
    if (rc != SSH_OK) {
        /* On error, make sure it is not used */
        session->next_crypto->used = 0;
        return SSH_ERROR;
    }

    rc = session->next_crypto->out_cipher->set_encrypt_key(
        session->next_crypto->out_cipher, session->next_crypto->encryptkey,
        session->next_crypto->encryptIV);
    if (rc != SSH_OK) {
        /* On error, make sure it is not used */
        session->next_crypto->used = 0;
        return SSH_ERROR;
    }

    return SSH_OK;

error:
    if (k_string != NULL) ssh_string_burn(k_string);
    ssh_string_free(k_string);
    SAFE_FREE(IV_cli_to_srv);
    SAFE_FREE(IV_srv_to_cli);
    SAFE_FREE(enckey_cli_to_srv);
    SAFE_FREE(enckey_srv_to_cli);
    SAFE_FREE(intkey_cli_to_srv);
    SAFE_FREE(intkey_srv_to_cli);

    return SSH_ERROR;
}

/**
 * @brief Send client DH initialization message.
 *  byte      SSH_MSG_KEXDH_INIT
 *  mpint     e
 *
 * @see RFC 4253 section 8
 *
 * @param session
 * @return int
 */
static int dh_send_init(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    const_bignum pubkey;
    int rc;

    rc = dh_keypair_gen_keys(crypto->dh_ctx, DH_CLIENT_KEYPAIR);
    if (rc != SSH_OK) return rc;

    rc = dh_keypair_get_keys(crypto->dh_ctx, DH_CLIENT_KEYPAIR, NULL, &pubkey);
    if (rc != SSH_OK) return rc;

    rc = ssh_buffer_pack(session->out_buffer, "bB", SSH_MSG_KEXDH_INIT, pubkey);
    if (rc != SSH_OK) return rc;

    rc = ssh_packet_send(session);
    if (rc != SSH_OK) return rc;

    return SSH_OK;
}

/**
 * @brief Wait for DH server reply and get session keys.
 * @see RFC 4253 section 8
 * @param session
 * @return int
 */
static int dh_receive_reply(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    ssh_string encoded_pubkey = NULL;
    bignum server_pubkey = NULL;
    uint8_t type;
    int rc;

    if (ssh_packet_receive(session) != SSH_OK ||
        ssh_buffer_get_u8(session->in_buffer, &type) != 1 ||
        type != SSH_MSG_KEXDH_REPLY) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_unpack(session->in_buffer, "SSS",
                           &crypto->server_pubkey_blob, &encoded_pubkey,
                           &crypto->dh_server_signature);
    if (rc != SSH_OK) return SSH_ERROR;

    if (ssh_string_len(encoded_pubkey) != 0 &&
        (encoded_pubkey->data[0] & 0x80) == 0) {
        server_pubkey = ssh_make_string_bn(encoded_pubkey);
    }
    ssh_string_free(encoded_pubkey);

    /* The server DH value f must be in [1, p - 1]. */
    if (server_pubkey == NULL || BN_is_zero(server_pubkey) ||
        bignum_cmp(server_pubkey, crypto->dh_ctx->modulus) >= 0) {
        bignum_safe_free(server_pubkey);
        return SSH_ERROR;
    }

    rc = dh_keypair_set_keys(crypto->dh_ctx, DH_SERVER_KEYPAIR, NULL,
                            server_pubkey);
    if (rc != SSH_OK) {
        bignum_safe_free(server_pubkey);
        return rc;
    }

    /* The lab does not verify the server host key or its signature. */
    rc = dh_compute_shared_secret(crypto->dh_ctx, DH_CLIENT_KEYPAIR,
                                  DH_SERVER_KEYPAIR, &crypto->shared_secret);
    if (rc != SSH_OK) return rc;

    rc = dh_compute_session_id(session);
    if (rc != SSH_OK) return rc;

    rc = ssh_crypto_set_algo(session);
    if (rc != SSH_OK || crypto->in_cipher == NULL || crypto->out_cipher == NULL)
        return SSH_ERROR;

    return dh_gen_session_keys(session);
}

/**
 * @brief Exchange NEWKEYS and activate the keys in each direction.
 */
static int dh_set_new_keys(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    uint8_t type;

    if (ssh_buffer_add_u8(session->out_buffer, SSH_MSG_NEWKEYS) != SSH_OK ||
        ssh_packet_send(session) != SSH_OK) {
        return SSH_ERROR;
    }

    session->current_crypto = crypto;
    session->next_crypto = NULL;
    crypto->used = SSH_DIRECTION_OUT;

    if (ssh_packet_receive(session) != SSH_OK ||
        ssh_buffer_get_u8(session->in_buffer, &type) != 1 ||
        type != SSH_MSG_NEWKEYS ||
        ssh_buffer_get_len(session->in_buffer) != 0) {
        return SSH_ERROR;
    }

    crypto->used = SSH_DIRECTION_BOTH;
    return SSH_OK;
}

/**
 * @brief Perform Diffie-Hellman key exchange procedure. 
 * 
 * @param session 
 * @return int 
 */
int ssh_dh_handshake(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;
    int rc;

    rc = dh_init(session);
    if (rc != SSH_OK) goto error;

    /* send KEXDH_INIT */
    rc = dh_send_init(session);
    if (rc != SSH_OK) goto error;

    /* receive KEXDH_REPLY */
    rc = dh_receive_reply(session);
    if (rc != SSH_OK) goto error;

    /* Exchange NEWKEYS. */
    rc = dh_set_new_keys(session);
    if (rc != SSH_OK) goto error;

    return SSH_OK;
error:
    dh_cleanup(crypto);
    return SSH_ERROR;
}
