/**
 * @file kex.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH transport layer key exchange functionalities.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "libsftp/kex.h"

#include "libsftp/error.h"
#include "libsftp/libcrypto.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/* The lab advertises one method for each required KEXINIT name-list. */
static const char *const supported_methods[SSH_KEX_METHODS] = {
    [SSH_KEX] = "diffie-hellman-group1-sha1",
    [SSH_HOSTKEYS] = "ssh-rsa",
    [SSH_CRYPT_C_S] = "aes256-cbc",
    [SSH_CRYPT_S_C] = "aes256-cbc",
    [SSH_MAC_C_S] = "hmac-sha1",
    [SSH_MAC_S_C] = "hmac-sha1",
    [SSH_COMP_C_S] = "none",
    [SSH_COMP_S_C] = "none",
    [SSH_LANG_C_S] = "",
    [SSH_LANG_S_C] = "",
};

int ssh_set_client_kex(ssh_session session) {
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;

    if (!ssh_get_random(client->cookie, sizeof(client->cookie), 0)) {
        LOG_ERROR("PRNG error");
        return SSH_ERROR;
    }

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        client->methods[i] = strdup(supported_methods[i]);
        if (client->methods[i] == NULL) return SSH_ERROR;
    }
    return SSH_OK;
}

int ssh_send_kex(ssh_session session) {
    struct ssh_kex_struct *kex = &session->next_crypto->client_kex;

    if (ssh_buffer_pack(session->out_buffer, "bP", SSH_MSG_KEXINIT,
                        sizeof(kex->cookie), kex->cookie) != SSH_OK) {
        goto error;
    }

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        if (ssh_buffer_pack(session->out_buffer, "s", kex->methods[i])
                != SSH_OK) {
            goto error;
        }
    }

    if (ssh_buffer_pack(session->out_buffer, "bd", 0, 0) != SSH_OK) {
        goto error;
    }

    session->out_hashbuf = ssh_buffer_new();
    if (session->out_hashbuf == NULL ||
        ssh_buffer_add_buffer(session->out_hashbuf, session->out_buffer)
            != SSH_OK) {
        goto error;
    }

    if (ssh_packet_send(session) == SSH_OK) return SSH_OK;

error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

static bool method_matches(const char *list, size_t len, const char *method) {
    return strlen(method) == len && memcmp(list, method, len) == 0;
}

int ssh_receive_kex(ssh_session session) {
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    uint8_t type, first_kex_follows;
    uint32_t reserved;

    if (ssh_packet_receive(session) != SSH_OK) return SSH_ERROR;

    session->in_hashbuf = ssh_buffer_new();
    if (session->in_hashbuf == NULL ||
        ssh_buffer_add_buffer(session->in_hashbuf, session->in_buffer)
            != SSH_OK) {
        return SSH_ERROR;
    }

    if (ssh_buffer_get_u8(session->in_buffer, &type) != 1 ||
        type != SSH_MSG_KEXINIT ||
        ssh_buffer_get_data(session->in_buffer, server->cookie,
                            sizeof(server->cookie)) != sizeof(server->cookie)) {
        return SSH_ERROR;
    }

    for (int i = 0; i < SSH_KEX_METHODS; i++) {
        if (ssh_buffer_unpack(session->in_buffer, "s", &server->methods[i])
                != SSH_OK) {
            return SSH_ERROR;
        }
    }

    if (ssh_buffer_unpack(session->in_buffer, "bd", &first_kex_follows,
                          &reserved) != SSH_OK) {
        return SSH_ERROR;
    }

    const char *kex_guess = server->methods[SSH_KEX];
    const char *hostkey_guess = server->methods[SSH_HOSTKEYS];
    session->first_kex_follows_guess_wrong =
        first_kex_follows &&
        (!method_matches(kex_guess, strcspn(kex_guess, ","),
                         client->methods[SSH_KEX]) ||
         !method_matches(hostkey_guess, strcspn(hostkey_guess, ","),
                         client->methods[SSH_HOSTKEYS]));
    return SSH_OK;
}

int ssh_select_kex(ssh_session session) {
    struct ssh_crypto_struct *crypto = session->next_crypto;

    for (int i = SSH_KEX; i <= SSH_COMP_S_C; i++) {
        const char *method = crypto->client_kex.methods[i];
        const char *name = crypto->server_kex.methods[i];

        for (;;) {
            size_t len = strcspn(name, ",");
            if (method_matches(name, len, method)) break;
            if (name[len] == '\0') {
                LOG_ERROR("no common algorithm for KEXINIT list %d", i);
                return SSH_ERROR;
            }
            name += len + 1;
        }

        crypto->kex_methods[i] = strdup(method);
        if (crypto->kex_methods[i] == NULL) return SSH_ERROR;
    }
    crypto->kex_type = SSH_KEX_DH_GROUP1_SHA1;

    if (session->first_kex_follows_guess_wrong) {
        if (ssh_packet_receive(session) != SSH_OK) return SSH_ERROR;
        session->first_kex_follows_guess_wrong = 0;
    }

    LOG_NOTICE("negotiated KEX=%s hostkey=%s "
               "client-to-server=%s/%s/%s server-to-client=%s/%s/%s",
               crypto->kex_methods[SSH_KEX], crypto->kex_methods[SSH_HOSTKEYS],
               crypto->kex_methods[SSH_CRYPT_C_S],
               crypto->kex_methods[SSH_MAC_C_S],
               crypto->kex_methods[SSH_COMP_C_S],
               crypto->kex_methods[SSH_CRYPT_S_C],
               crypto->kex_methods[SSH_MAC_S_C],
               crypto->kex_methods[SSH_COMP_S_C]);
    return SSH_OK;
}
