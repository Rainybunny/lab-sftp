/**
 * @file channel.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH connection layer channel abstraction.
 * This file handles open, close, and data transfer on a virtual channel.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/channel.h"

#include <limits.h>

#include "libsftp/error.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

#define CHANNEL_MAX_PACKET 32768U
#define CHANNEL_INITIAL_WINDOW 64000U

static int channel_send(ssh_channel channel, int packed) {
    ssh_session session = channel->session;

    if (packed == SSH_OK && ssh_packet_send(session) == SSH_OK) {
        return SSH_OK;
    }
    ssh_buffer_reinit(session->out_buffer);
    channel->opened = 0;
    ssh_set_error(SSH_FATAL, "cannot send SSH channel message");
    return SSH_ERROR;
}

static int channel_send_control(ssh_channel channel, uint8_t type) {
    return channel_send(channel, ssh_buffer_pack(channel->session->out_buffer,
                                                "bd", type, channel->remote_channel));
}

static int reject_request(ssh_channel channel, int global) {
    ssh_session session = channel->session;
    char *name = NULL;
    uint8_t want_reply;

    if (ssh_buffer_unpack(session->in_buffer, "sb", &name, &want_reply) != SSH_OK) {
        ssh_set_error(SSH_FATAL, "invalid SSH request");
        return SSH_ERROR;
    }
    free(name);
    if (!want_reply) {
        return SSH_OK;
    }
    if (global) {
        return channel_send(channel, ssh_buffer_pack(session->out_buffer,
                                                    "b", SSH_MSG_REQUEST_FAILURE));
    }
    return channel_send_control(channel, SSH_MSG_CHANNEL_FAILURE);
}

static int reject_open(ssh_channel channel) {
    ssh_session session = channel->session;
    char *kind = NULL;
    uint32_t sender, window, maxpacket;

    if (ssh_buffer_unpack(session->in_buffer, "sddd", &kind, &sender, &window,
                          &maxpacket) != SSH_OK) {
        ssh_set_error(SSH_FATAL, "invalid server-initiated channel open");
        return SSH_ERROR;
    }
    free(kind);
    return channel_send(channel, ssh_buffer_pack(session->out_buffer, "bddss",
                                                SSH_MSG_CHANNEL_OPEN_FAILURE,
                                                sender, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                                                "server-initiated channels are disabled", ""));
}

/* Receive a message addressed to this channel, handling transport-wide requests. */
static int channel_next(ssh_channel channel, uint8_t *type) {
    ssh_session session = channel->session;
    uint32_t recipient;

    while (ssh_packet_receive(session) == SSH_OK) {
        if (ssh_buffer_get_u8(session->in_buffer, type) != 1) {
            ssh_set_error(SSH_FATAL, "missing SSH message type");
            break;
        }
        switch (*type) {
            case SSH_MSG_IGNORE:
            case SSH_MSG_DEBUG:
                continue;
            case SSH_MSG_GLOBAL_REQUEST:
                if (reject_request(channel, 1) == SSH_OK) {
                    continue;
                }
                break;
            case SSH_MSG_CHANNEL_OPEN:
                if (reject_open(channel) == SSH_OK) {
                    continue;
                }
                break;
            case SSH_MSG_DISCONNECT:
                ssh_set_error(SSH_REQUEST_DENIED, "server disconnected");
                break;
            default:
                if (*type < SSH_MSG_CHANNEL_OPEN_CONFIRMATION ||
                    *type > SSH_MSG_CHANNEL_FAILURE ||
                    ssh_buffer_unpack(session->in_buffer, "d", &recipient) != SSH_OK ||
                    recipient != channel->local_channel) {
                    ssh_set_error(SSH_FATAL, "unexpected SSH message %u or channel number", *type);
                    break;
                }
                return SSH_OK;
        }
        break;
    }

    channel->opened = 0;
    return SSH_ERROR;
}

ssh_channel ssh_channel_new(ssh_session session) {
    ssh_channel channel;

    if (session == NULL || session->channel != NULL) {
        ssh_set_error(SSH_FATAL, "a single SSH channel is supported per session");
        return NULL;
    }

    channel = calloc(1, sizeof(*channel));
    if (channel == NULL) {
        ssh_set_error(SSH_FATAL, "cannot allocate SSH channel");
        return NULL;
    }
    channel->in_buffer = ssh_buffer_new();
    if (channel->in_buffer == NULL) {
        ssh_set_error(SSH_FATAL, "cannot allocate SSH channel buffer");
        free(channel);
        return NULL;
    }

    channel->session = session;
    session->channel = channel;
    return channel;
}

int ssh_channel_open_session(ssh_channel channel) {
    ssh_session session;
    uint8_t type;
    uint32_t reason;
    char *description = NULL, *language = NULL;

    if (channel == NULL || channel->opened || channel->close_sent ||
        channel->close_received) {
        return SSH_ERROR;
    }
    session = channel->session;
    channel->local_channel = 1;
    channel->local_window = CHANNEL_INITIAL_WINDOW;
    channel->local_maxpacket = CHANNEL_MAX_PACKET;
    if (channel_send(channel, ssh_buffer_pack(session->out_buffer, "bsddd",
                                              SSH_MSG_CHANNEL_OPEN, "session",
                                              channel->local_channel, channel->local_window,
                                              channel->local_maxpacket)) != SSH_OK ||
        channel_next(channel, &type) != SSH_OK) {
        return SSH_ERROR;
    }

    if (type == SSH_MSG_CHANNEL_OPEN_FAILURE &&
        ssh_buffer_unpack(session->in_buffer, "dss", &reason, &description,
                          &language) == SSH_OK) {
        ssh_set_error(SSH_REQUEST_DENIED, "channel open rejected (%u): %.200s",
                      reason, description);
        free(description);
        free(language);
        return SSH_ERROR;
    }

    if (type != SSH_MSG_CHANNEL_OPEN_CONFIRMATION ||
        ssh_buffer_unpack(session->in_buffer, "ddd", &channel->remote_channel,
                          &channel->remote_window, &channel->remote_maxpacket) != SSH_OK ||
        channel->remote_maxpacket == 0 ||
        ssh_buffer_get_len(session->in_buffer) != 0) {
        ssh_set_error(SSH_FATAL, "invalid SSH channel open reply");
        return SSH_ERROR;
    }

    channel->opened = 1;
    LOG_NOTICE("channel opened local id=%u window=%u maxpacket=%u "
               "remote id=%u window=%u maxpacket=%u",
               channel->local_channel, channel->local_window, channel->local_maxpacket,
               channel->remote_channel, channel->remote_window, channel->remote_maxpacket);
    return SSH_OK;
}

/* The advertised window and queued data share a fixed receive budget. */
static int replenish_window(ssh_channel channel) {
    uint32_t available = CHANNEL_INITIAL_WINDOW - ssh_buffer_get_len(channel->in_buffer);
    uint32_t increment;

    if (channel->remote_eof || channel->close_sent ||
        available - channel->local_window < CHANNEL_INITIAL_WINDOW / 2) {
        return SSH_OK;
    }
    increment = available - channel->local_window;
    if (channel_send(channel, ssh_buffer_pack(channel->session->out_buffer, "bdd",
                                              SSH_MSG_CHANNEL_WINDOW_ADJUST,
                                              channel->remote_channel, increment)) != SSH_OK) {
        return SSH_ERROR;
    }
    channel->local_window += increment;
    return SSH_OK;
}

static int receive_data(ssh_channel channel, uint8_t type) {
    ssh_buffer payload = channel->session->in_buffer;
    ssh_string data;
    size_t length;
    uint32_t data_type;
    int rc = SSH_ERROR;

    if (type == SSH_MSG_CHANNEL_EXTENDED_DATA &&
        ssh_buffer_unpack(payload, "d", &data_type) != SSH_OK) {
        return SSH_ERROR;
    }

    data = ssh_buffer_get_ssh_string(payload);
    if (data == NULL) {
        return SSH_ERROR;
    }
    length = ssh_string_len(data);
    if (!channel->remote_eof && length <= channel->local_window &&
        length <= channel->local_maxpacket && ssh_buffer_get_len(payload) == 0) {
        if (type == SSH_MSG_CHANNEL_DATA && !channel->close_sent) {
            rc = ssh_buffer_add_data(channel->in_buffer, ssh_string_data(data), length);
        } else {
            rc = SSH_OK;
        }
        if (rc == SSH_OK) {
            channel->local_window -= length;
        }
    }
    ssh_string_free(data);
    return rc;
}

static int send_close(ssh_channel channel) {
    if (!channel->close_sent) {
        if (channel_send_control(channel, SSH_MSG_CHANNEL_CLOSE) != SSH_OK) {
            return SSH_ERROR;
        }
        channel->close_sent = 1;
    }
    return SSH_OK;
}

/* Dispatch messages that may interleave with a reply, window update or data. */
static int channel_dispatch(ssh_channel channel, uint8_t type) {
    ssh_buffer payload = channel->session->in_buffer;
    uint32_t increment;

    switch (type) {
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
            if (ssh_buffer_unpack(payload, "d", &increment) == SSH_OK &&
                ssh_buffer_get_len(payload) == 0 &&
                increment <= UINT32_MAX - channel->remote_window) {
                channel->remote_window += increment;
                return SSH_OK;
            }
            break;
        case SSH_MSG_CHANNEL_DATA:
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
            if (receive_data(channel, type) == SSH_OK) {
                return SSH_OK;
            }
            break;
        case SSH_MSG_CHANNEL_EOF:
            if (ssh_buffer_get_len(payload) == 0) {
                channel->remote_eof = 1;
                return SSH_OK;
            }
            break;
        case SSH_MSG_CHANNEL_CLOSE:
            if (ssh_buffer_get_len(payload) == 0) {
                channel->remote_eof = 1;
                channel->close_received = 1;
                return send_close(channel);
            }
            break;
        case SSH_MSG_CHANNEL_REQUEST:
            if (channel->close_sent) {
                return SSH_OK;
            }
            if (reject_request(channel, 0) == SSH_OK) {
                return SSH_OK;
            }
            break;
        default:
            break;
    }

    channel->opened = 0;
    ssh_set_error(SSH_FATAL, "invalid or unexpected SSH channel message %u", type);
    return SSH_ERROR;
}

int ssh_channel_request_sftp(ssh_channel channel) {
    ssh_session session;
    uint8_t type;

    if (channel == NULL || !channel->opened || channel->close_sent) {
        return SSH_ERROR;
    }
    session = channel->session;
    if (channel_send(channel, ssh_buffer_pack(session->out_buffer, "bdsbs",
                                              SSH_MSG_CHANNEL_REQUEST, channel->remote_channel,
                                              "subsystem", 1, "sftp")) != SSH_OK) {
        return SSH_ERROR;
    }

    while (channel_next(channel, &type) == SSH_OK) {
        if (type == SSH_MSG_CHANNEL_SUCCESS || type == SSH_MSG_CHANNEL_FAILURE) {
            if (ssh_buffer_get_len(session->in_buffer) != 0) {
                ssh_set_error(SSH_FATAL, "invalid SFTP subsystem reply");
                return SSH_ERROR;
            }
            if (type == SSH_MSG_CHANNEL_FAILURE) {
                ssh_set_error(SSH_REQUEST_DENIED, "SFTP subsystem request rejected");
                return SSH_ERROR;
            }
            LOG_NOTICE("SFTP subsystem request succeeded");
            return SSH_OK;
        }
        if (channel_dispatch(channel, type) != SSH_OK) {
            return SSH_ERROR;
        }
        if (channel->close_received) {
            ssh_set_error(SSH_REQUEST_DENIED, "channel closed during SFTP subsystem request");
            return SSH_ERROR;
        }
    }
    return SSH_ERROR;
}

int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len) {
    ssh_session session;
    const uint8_t *bytes = data;
    uint32_t remaining = len;
    uint8_t type;

    if (channel == NULL || !channel->opened || channel->local_eof ||
        channel->close_sent || (data == NULL && len != 0) || len > INT_MAX) {
        ssh_set_error(SSH_FATAL, "SSH channel is not writable or write size is invalid");
        return SSH_ERROR;
    }
    session = channel->session;

    while (remaining > 0) {
        uint32_t chunk;

        while (channel->remote_window == 0) {
            if (replenish_window(channel) != SSH_OK ||
                channel_next(channel, &type) != SSH_OK ||
                channel_dispatch(channel, type) != SSH_OK) {
                return SSH_ERROR;
            }
            if (channel->close_received) {
                ssh_set_error(SSH_REQUEST_DENIED, "channel closed while waiting for a send window");
                return SSH_ERROR;
            }
        }

        chunk = MIN(remaining, channel->remote_window);
        chunk = MIN(chunk, MIN(channel->remote_maxpacket, CHANNEL_MAX_PACKET));
        if (channel_send(channel, ssh_buffer_pack(session->out_buffer, "bddP",
                                                  SSH_MSG_CHANNEL_DATA, channel->remote_channel,
                                                  chunk, (size_t)chunk, bytes)) != SSH_OK) {
            return SSH_ERROR;
        }
        channel->remote_window -= chunk;
        remaining -= chunk;
        bytes += chunk;
    }
    return (int)len;
}

int ssh_channel_read(ssh_channel channel, void *dest, uint32_t count) {
    uint8_t *bytes = dest;
    uint32_t received = 0;
    uint8_t type;

    if (channel == NULL || !channel->opened ||
        (dest == NULL && count != 0) || count > INT_MAX) {
        ssh_set_error(SSH_FATAL, "SSH channel is not readable or read size is invalid");
        return SSH_ERROR;
    }

    while (received < count) {
        uint32_t pending = ssh_buffer_get_len(channel->in_buffer);

        if (pending != 0) {
            received += ssh_buffer_get_data(channel->in_buffer, bytes + received,
                                            MIN(count - received, pending));
            if (ssh_buffer_get_len(channel->in_buffer) == 0) {
                ssh_buffer_reinit(channel->in_buffer);
            }
        } else if (channel->remote_eof) {
            return received > 0 ? (int)received : SSH_EOF;
        } else {
            if (replenish_window(channel) != SSH_OK ||
                channel_next(channel, &type) != SSH_OK ||
                channel_dispatch(channel, type) != SSH_OK) {
                return SSH_ERROR;
            }
        }
    }
    return (int)received;
}

int ssh_channel_eof(ssh_channel channel) {
    if (channel == NULL || !channel->opened) {
        return SSH_ERROR;
    }
    if (!channel->local_eof && !channel->close_sent) {
        if (channel_send_control(channel, SSH_MSG_CHANNEL_EOF) != SSH_OK) {
            return SSH_ERROR;
        }
        channel->local_eof = 1;
    }
    return SSH_OK;
}

int ssh_channel_close(ssh_channel channel) {
    uint8_t type;

    if (channel == NULL || !channel->opened) {
        return SSH_ERROR;
    }
    if (channel->close_received) {
        return SSH_OK;
    }
    if (ssh_channel_eof(channel) != SSH_OK || send_close(channel) != SSH_OK) {
        return SSH_ERROR;
    }
    while (!channel->close_received) {
        if (channel_next(channel, &type) != SSH_OK ||
            channel_dispatch(channel, type) != SSH_OK) {
            return SSH_ERROR;
        }
    }
    return SSH_OK;
}

void ssh_channel_free(ssh_channel channel) {
    if (channel != NULL) {
        ssh_buffer_free(channel->in_buffer);
        channel->session->channel = NULL;
        free(channel);
    }
}
