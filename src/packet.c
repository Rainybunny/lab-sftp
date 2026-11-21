/**
 * @file packet.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH packet IO functionalities.
 * This file handles packet encryption and decryption, as well as MAC
 * verification.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/packet.h"

#include "libsftp/crypto.h"
#include "libsftp/error.h"
#include "libsftp/logger.h"
#include "libsftp/session.h"
#include "libsftp/socket.h"

#define SSH_WIRE_PACKET_MAX 35000

/**
 * RFC 4253 section 6 SSH packet format
 *
 * uint32    packet_length
 * byte      padding_length
 * byte[n1]  payload; n1 = packet_length - padding_length - 1
 * byte[n2]  random padding; n2 = padding_length
 * byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 */

/**
 * @brief Encrypt a packet.
 *
 * @param session
 * @param data
 * @param len
 * @return unsigned char* computed MAC
 */
static unsigned char *packet_encrypt(ssh_session session, void *data,
                                     uint32_t len) {
    struct ssh_crypto_struct *crypto = NULL;
    struct ssh_cipher_struct *cipher = NULL;
    HMACCTX ctx = NULL;
    char *out = NULL;
    unsigned int finallen = 0, blocksize;
    uint32_t seq, lenfield_blocksize;
    enum ssh_hmac_e type;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_OUT);
    if (crypto == NULL) {
        return NULL; /* nothing to do here */
    }

    blocksize = crypto->out_cipher->blocksize;
    lenfield_blocksize = crypto->out_cipher->lenfield_blocksize;
    type = crypto->out_hmac;

    if ((len - lenfield_blocksize) % blocksize != 0) {
        ssh_set_error(SSH_FATAL,
                      "Cryptographic functions must be set"
                      " on at least one blocksize (received %d)",
                      len);
        return NULL;
    }
    out = calloc(1, len);
    if (out == NULL) {
        return NULL;
    }

    seq = htonl(session->send_seq);
    cipher = crypto->out_cipher;

    ctx = hmac_init(crypto->encryptMAC, hmac_digest_len(type), type);
    if (ctx == NULL) {
        SAFE_FREE(out);
        return NULL;
    }

    hmac_update(ctx, (unsigned char *)&seq, sizeof(uint32_t));
    hmac_update(ctx, data, len);
    hmac_final(ctx, crypto->hmacbuf, &finallen);
    if (finallen != hmac_digest_len(type)) {
        free(out);
        return NULL;
    }

    cipher->encrypt(cipher, (uint8_t *)data, out, len);
    memcpy((uint8_t *)data, out, len);

    explicit_bzero(out, len);
    SAFE_FREE(out);

    return crypto->hmacbuf;
}

/**
 * @brief Integrity check.
 *
 * @param session
 * @param data
 * @param len
 * @param mac
 * @param type
 * @return int
 */
static int packet_hmac_verify(ssh_session session, const void *data, size_t len,
                              uint8_t *mac, enum ssh_hmac_e type) {
    struct ssh_crypto_struct *crypto = NULL;
    unsigned char hmacbuf[DIGEST_MAX_LEN] = {0};
    HMACCTX ctx;
    unsigned int hmaclen = 0;
    uint32_t seq;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_IN);
    if (crypto == NULL) {
        return SSH_ERROR;
    }

    ctx = hmac_init(crypto->decryptMAC, hmac_digest_len(type), type);
    if (ctx == NULL) {
        return SSH_ERROR;
    }

    seq = htonl(session->recv_seq);

    hmac_update(ctx, (unsigned char *)&seq, sizeof(uint32_t));
    hmac_update(ctx, data, len);
    hmac_final(ctx, hmacbuf, &hmaclen);

    if (hmaclen == hmac_digest_len(type) &&
        CRYPTO_memcmp(mac, hmacbuf, hmaclen) == 0) {
        return SSH_OK;
    }

    return SSH_ERROR;
}

/* Message types that the protocol layers know how to consume. */
static bool packet_type_known(uint8_t type) {
    switch (type) {
        case SSH_MSG_DISCONNECT:
        case SSH_MSG_SERVICE_REQUEST:
        case SSH_MSG_SERVICE_ACCEPT:
        case SSH_MSG_KEXINIT:
        case SSH_MSG_NEWKEYS:
        case SSH_MSG_KEXDH_INIT:
        case SSH_MSG_KEXDH_REPLY:
        case SSH_MSG_USERAUTH_REQUEST:
        case SSH_MSG_USERAUTH_FAILURE:
        case SSH_MSG_USERAUTH_SUCCESS:
        case SSH_MSG_USERAUTH_BANNER:
        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
        case SSH_MSG_GLOBAL_REQUEST:
        case SSH_MSG_REQUEST_SUCCESS:
        case SSH_MSG_REQUEST_FAILURE:
            return true;
        default:
            return type >= SSH_MSG_CHANNEL_OPEN &&
                   type <= SSH_MSG_CHANNEL_FAILURE;
    }
}

/**
 * @brief Read a binary packet from socket and decrypt it if key exchange is
 * completed. Extract the SSH message packet and store it in the session's
 * in_buffer
 * @param session
 * @return success or not
 */
int ssh_packet_receive(ssh_session session) {
    struct ssh_crypto_struct *crypto = ssh_get_crypto(session, SSH_DIRECTION_IN);
    struct ssh_cipher_struct *cipher = crypto ? crypto->in_cipher : NULL;
    uint32_t blocksize = cipher ? cipher->blocksize : 8;
    size_t macsize = crypto ? hmac_digest_len(crypto->in_hmac) : 0;
    uint8_t first_block[EVP_MAX_BLOCK_LENGTH];
    uint8_t decrypted_block[EVP_MAX_BLOCK_LENGTH] = {0};
    uint8_t *rest = NULL;
    uint8_t *packet;
    uint32_t packet_len;
    size_t packet_size, remaining;
    uint8_t padding;
    uint8_t type;

retry:
    if (ssh_buffer_reinit(session->in_buffer) != SSH_OK ||
        ssh_socket_read(session->socket, first_block, blocksize) != SSH_OK) {
        goto error;
    }

    if (cipher != NULL) {
        cipher->decrypt(cipher, first_block, decrypted_block, blocksize);
    } else {
        memcpy(decrypted_block, first_block, blocksize);
    }
    memcpy(&packet_len, decrypted_block, sizeof(packet_len));
    packet_len = ntohl(packet_len);

    if (packet_len < 16 - sizeof(packet_len) ||
        packet_len > SSH_WIRE_PACKET_MAX - sizeof(packet_len) - macsize) {
        goto error;
    }
    packet_size = sizeof(packet_len) + packet_len;
    if (packet_size < blocksize || packet_size % blocksize != 0) goto error;
    remaining = packet_size - blocksize;

    packet = ssh_buffer_allocate(session->in_buffer, packet_size);
    if (packet == NULL) goto error;
    memcpy(packet, decrypted_block, blocksize);

    rest = malloc(remaining + macsize);
    if (rest == NULL ||
        ssh_socket_read(session->socket, rest, remaining + macsize) != SSH_OK) {
        goto error;
    }

    if (cipher != NULL) {
        if (remaining > 0) {
            cipher->decrypt(cipher, rest, packet + blocksize, remaining);
        }
        if (packet_hmac_verify(session, packet, packet_size, rest + remaining,
                               crypto->in_hmac) != SSH_OK) {
            ssh_set_error(SSH_FATAL, "hmac error");
            LOG_ERROR("hmac error");
            goto error;
        }
    } else {
        memcpy(packet + blocksize, rest, remaining);
    }

    padding = packet[sizeof(packet_len)];
    if (padding < 4 || padding >= packet_len - 1) {
        ssh_set_error(SSH_FATAL, "Invalid padding: %u", padding);
        goto error;
    }

    ssh_buffer_pass_bytes(session->in_buffer, sizeof(packet_len) + 1);
    ssh_buffer_pass_bytes_end(session->in_buffer, padding);
    session->recv_seq++;
    SAFE_FREE(rest);

    type = ((uint8_t *)ssh_buffer_get(session->in_buffer))[0];
    if (type == SSH_MSG_IGNORE || type == SSH_MSG_DEBUG) {
        LOG_DEBUG("packet: ignored message type %u", type);
        goto retry;
    }
    if (type == SSH_MSG_UNIMPLEMENTED) {
        LOG_DEBUG("packet: ignored SSH_MSG_UNIMPLEMENTED");
        goto retry;
    }
    if (!packet_type_known(type)) {
        if (ssh_buffer_pack(session->out_buffer, "bd",
                            SSH_MSG_UNIMPLEMENTED,
                            session->recv_seq - 1) != SSH_OK ||
            ssh_packet_send(session) != SSH_OK) {
            ssh_set_error(SSH_FATAL,
                          "cannot respond to unrecognized message type %u",
                          type);
            goto error;
        }
        LOG_DEBUG("packet: sent SSH_MSG_UNIMPLEMENTED for type %u", type);
        goto retry;
    }

    LOG_DEBUG("packet: received [type=%u, len=%u, padding_size=%u, payload=%u]",
              packet[sizeof(packet_len) + 1], packet_len, padding,
              ssh_buffer_get_len(session->in_buffer));
    return SSH_OK;

error:
    free(rest);
    ssh_buffer_reinit(session->in_buffer);
    LOG_ERROR("packet receive error");
    return SSH_ERROR;
}

/**
 * @brief Encapsulate a binary packet from payload and encrypt it if key
 * exchange is completed. Send the encrypted packet to the socket.
 *
 * @param session
 * @return int
 */
int ssh_packet_send(ssh_session session) {
    unsigned int blocksize = 8;
    unsigned int lenfield_blocksize = 0;
    enum ssh_hmac_e hmac_type = SSH_HMAC_NONE;
    struct ssh_crypto_struct *crypto = NULL;
    unsigned char *hmac = NULL;
    uint8_t padding_data[32] = {0};
    uint8_t padding_size;
    uint32_t finallen, payload_size, wire_length;
    uint8_t header[5];
    uint8_t type, *payload;
    int rc;

    crypto = ssh_get_crypto(session, SSH_DIRECTION_OUT);
    if (crypto) {
        blocksize = crypto->out_cipher->blocksize;
        lenfield_blocksize = crypto->out_cipher->lenfield_blocksize;
        hmac_type = crypto->out_hmac;
    }

    payload_size = ssh_buffer_get_len(session->out_buffer);
    if (payload_size < 1 || payload_size > SSH_WIRE_PACKET_MAX) {
        return SSH_ERROR;
    }

    payload = (uint8_t *)ssh_buffer_get(session->out_buffer);
    type = payload[0]; /* type is the first byte of the packet now */

    padding_size =
        (blocksize -
         ((blocksize - lenfield_blocksize + payload_size + 5) % blocksize));
    if (padding_size < 4) {
        padding_size += blocksize;
    }

    finallen = payload_size + padding_size + 1;
    if (finallen + sizeof(wire_length) + hmac_digest_len(hmac_type) >
        SSH_WIRE_PACKET_MAX) {
        return SSH_ERROR;
    }
    if (!ssh_get_random(padding_data, padding_size, 0)) {
        ssh_set_error(SSH_FATAL, "PRNG error");
        return SSH_ERROR;
    }

    wire_length = htonl(finallen);
    memcpy(header, &wire_length, sizeof(wire_length));
    header[4] = padding_size;

    rc = ssh_buffer_prepend_data(session->out_buffer, header, sizeof(header));
    if (rc < 0) return SSH_ERROR;
    rc = ssh_buffer_add_data(session->out_buffer, padding_data, padding_size);
    if (rc < 0) return SSH_ERROR;

    if (crypto != NULL) {
        hmac = packet_encrypt(session, ssh_buffer_get(session->out_buffer),
                              ssh_buffer_get_len(session->out_buffer));
        if (hmac == NULL) return SSH_ERROR;

        rc = ssh_buffer_add_data(session->out_buffer, hmac,
                                 hmac_digest_len(hmac_type));
        if (rc < 0) return SSH_ERROR;
    }

    rc = ssh_socket_write(session->socket, ssh_buffer_get(session->out_buffer),
                          ssh_buffer_get_len(session->out_buffer));
    if (rc < 0) return SSH_ERROR;

    session->send_seq++;

    LOG_DEBUG(
        "packet: wrote [type=%u, len=%u, padding_size=%u,"
        "payload=%u]",
        type, finallen, padding_size, payload_size);

    /* be ready for next packet */
    rc = ssh_buffer_reinit(session->out_buffer);
    if (rc < 0) {
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    return SSH_OK;
}
