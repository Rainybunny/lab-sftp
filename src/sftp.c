/**
 * @file stfp.c
 * @author Zhou Yuhan (zhouyuhan@pku.edu.cn)
 * @brief Implementaiton of SFTP functions, including APIs and helpers.
 * Only open, close, read, write of regular files are supported
 * @version 0.1
 * @date 2022-07-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <fcntl.h>
#include <stddef.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/libsftp.h"
#include "libsftp/logger.h"
#include "libsftp/session.h"

#define SFTP_PACKET_SIZE_MAX (256U * 1024U)
#define SFTP_HANDLE_SIZE_MAX 256U

struct sftp_session_struct {
    uint32_t id_counter;
    uint32_t version;
    int stream_failed;
    ssh_channel channel;
};

struct sftp_packet_struct {
    uint8_t type;
    ssh_buffer payload;
};

struct sftp_file_struct {
    sftp_session sftp;
    uint64_t offset;
    ssh_string handle;
    int eof;
};

static void sftp_packet_free(sftp_packet packet) {
    if (packet != NULL) {
        ssh_buffer_free(packet->payload);
        free(packet);
    }
}

static sftp_packet sftp_packet_read(sftp_session sftp) {
    uint8_t header[5];
    uint32_t length;
    uint8_t *payload;
    sftp_packet packet;

    if (ssh_channel_read(sftp->channel, header, sizeof(header)) != sizeof(header)) {
        ssh_set_error(SSH_FATAL, "incomplete SFTP packet header");
        return NULL;
    }

    memcpy(&length, header, sizeof(length));
    length = ntohl(length);
    if (length < 1 || length > SFTP_PACKET_SIZE_MAX) {
        ssh_set_error(SSH_FATAL, "invalid SFTP packet length %u", length);
        return NULL;
    }

    packet = calloc(1, sizeof(*packet));
    if (packet == NULL) {
        ssh_set_error(SSH_FATAL, "cannot allocate SFTP packet");
        return NULL;
    }
    packet->type = header[4];
    packet->payload = ssh_buffer_new();
    if (packet->payload == NULL) {
        ssh_set_error(SSH_FATAL, "cannot allocate SFTP packet buffer");
        sftp_packet_free(packet);
        return NULL;
    }

    length--;
    if (length != 0) {
        payload = ssh_buffer_allocate(packet->payload, length);
        if (payload == NULL ||
            ssh_channel_read(sftp->channel, payload, length) != (int)length) {
            ssh_set_error(SSH_FATAL, "cannot read complete SFTP packet payload");
            sftp_packet_free(packet);
            return NULL;
        }
    }
    return packet;
}

/* Sends one request and reads its response, taking ownership of the request buffer. */
static sftp_packet sftp_exchange(sftp_session sftp, uint8_t type,
                                 ssh_buffer request, int packed, uint32_t id) {
    uint32_t length, response_id;
    uint8_t header[5];
    sftp_packet response;

    if (packed != SSH_OK || sftp->stream_failed) {
        ssh_buffer_free(request);
        ssh_set_error(SSH_FATAL, packed != SSH_OK ? "cannot pack SFTP request"
                                                  : "SFTP stream is unavailable");
        return NULL;
    }

    length = htonl(ssh_buffer_get_len(request) + 1);
    memcpy(header, &length, sizeof(length));
    header[4] = type;
    if (ssh_buffer_prepend_data(request, header, sizeof(header)) != SSH_OK ||
        ssh_channel_write(sftp->channel, ssh_buffer_get(request),
                          ssh_buffer_get_len(request)) != (int)ssh_buffer_get_len(request)) {
        ssh_buffer_free(request);
        sftp->stream_failed = 1;
        ssh_set_error(SSH_FATAL, "cannot send SFTP request %u", type);
        return NULL;
    }
    ssh_buffer_free(request);

    response = sftp_packet_read(sftp);
    if (response == NULL) {
        sftp->stream_failed = 1;
        return NULL;
    }
    if (type != SSH_FXP_INIT &&
        (ssh_buffer_unpack(response->payload, "d", &response_id) != SSH_OK ||
         response_id != id)) {
        sftp_packet_free(response);
        sftp->stream_failed = 1;
        ssh_set_error(SSH_FATAL, "SFTP response does not match request %u", id);
        return NULL;
    }
    return response;
}

static int sftp_read_status(sftp_packet response, uint32_t *status) {
    char *message = NULL, *language = NULL;
    int rc = SSH_ERROR;

    if (response->type == SSH_FXP_STATUS &&
        ssh_buffer_unpack(response->payload, "dss", status, &message, &language) == SSH_OK &&
        ssh_buffer_get_len(response->payload) == 0) {
        if (*status != SSH_FX_OK && *status != SSH_FX_EOF) {
            ssh_set_error(SSH_REQUEST_DENIED, "SFTP status %u: %.240s", *status, message);
        }
        rc = SSH_OK;
    } else {
        ssh_set_error(SSH_FATAL, "expected a valid SFTP status, received type %u",
                      response->type);
    }
    free(message);
    free(language);
    return rc;
}

static int sftp_expect_ok(sftp_packet response) {
    uint32_t status;

    if (response == NULL || sftp_read_status(response, &status) != SSH_OK) {
        return SSH_ERROR;
    }
    if (status == SSH_FX_EOF) {
        ssh_set_error(SSH_FATAL, "unexpected SFTP EOF status");
    }
    return status == SSH_FX_OK ? SSH_OK : SSH_ERROR;
}

static ssh_buffer sftp_request_new(void) {
    ssh_buffer request = ssh_buffer_new();
    if (request == NULL) {
        ssh_set_error(SSH_FATAL, "cannot allocate SFTP request buffer");
    }
    return request;
}

sftp_session sftp_new(ssh_session session) {
    sftp_session sftp;

    if (session == NULL) {
        ssh_set_error(SSH_FATAL, "missing SSH session");
        return NULL;
    }
    sftp = calloc(1, sizeof(*sftp));
    if (sftp == NULL) {
        ssh_set_error(SSH_FATAL, "cannot allocate SFTP session");
        return NULL;
    }

    sftp->channel = ssh_channel_new(session);
    if (sftp->channel == NULL || ssh_channel_open_session(sftp->channel) != SSH_OK ||
        ssh_channel_request_sftp(sftp->channel) != SSH_OK) {
        sftp_free(sftp);
        return NULL;
    }
    return sftp;
}

void sftp_free(sftp_session sftp) {
    if (sftp != NULL) {
        if (sftp->channel != NULL) {
            ssh_channel_close(sftp->channel);
            ssh_channel_free(sftp->channel);
        }
        free(sftp);
    }
}

int sftp_init(sftp_session sftp) {
    ssh_buffer request;
    sftp_packet response;
    uint32_t version;
    int rc = SSH_ERROR;

    if (sftp == NULL) {
        ssh_set_error(SSH_FATAL, "missing SFTP session");
        return SSH_ERROR;
    }
    request = sftp_request_new();
    if (request == NULL) return SSH_ERROR;

    response = sftp_exchange(sftp, SSH_FXP_INIT, request,
                             ssh_buffer_pack(request, "d", (uint32_t)LIBSFTP_VERSION), 0);
    if (response == NULL) {
        return SSH_ERROR;
    }

    if (response->type != SSH_FXP_VERSION ||
        ssh_buffer_unpack(response->payload, "d", &version) != SSH_OK) {
        ssh_set_error(SSH_FATAL, "invalid SFTP version response");
    } else if (version != LIBSFTP_VERSION) {
        ssh_set_error(SSH_REQUEST_DENIED, "server SFTP version %u, expected %u",
                      version, LIBSFTP_VERSION);
    } else {
        sftp->version = version;
        LOG_NOTICE("SFTP version %u initialized", version);
        rc = SSH_OK;
    }
    sftp_packet_free(response);
    return rc;
}

sftp_file sftp_open(sftp_session sftp, const char *filename, int flags, mode_t mode) {
    ssh_buffer request;
    sftp_packet response;
    sftp_file file = NULL;
    uint32_t pflags, status, id;
    int packed;

    if (sftp == NULL || sftp->version != LIBSFTP_VERSION || filename == NULL) {
        ssh_set_error(SSH_FATAL, "SFTP session or file name is invalid");
        return NULL;
    }

    switch (flags & O_ACCMODE) {
        case O_RDONLY:
            pflags = SSH_FXF_READ;
            break;
        case O_WRONLY:
            pflags = SSH_FXF_WRITE;
            break;
        case O_RDWR:
            pflags = SSH_FXF_READ | SSH_FXF_WRITE;
            break;
        default:
            ssh_set_error(SSH_FATAL, "invalid SFTP file access mode");
            return NULL;
    }
    if (flags & O_CREAT) pflags |= SSH_FXF_CREAT;
    if (flags & O_TRUNC) pflags |= SSH_FXF_TRUNC;
    if (flags & O_EXCL) pflags |= SSH_FXF_EXCL;
    if (flags & O_APPEND) pflags |= SSH_FXF_APPEND;

    request = sftp_request_new();
    if (request == NULL) return NULL;
    id = ++sftp->id_counter;
    if (flags & O_CREAT) {
        packed = ssh_buffer_pack(request, "dsddd", id, filename, pflags,
                                 SSH_FILEXFER_ATTR_PERMISSIONS, (uint32_t)mode);
    } else {
        packed = ssh_buffer_pack(request, "dsdd", id, filename, pflags, 0U);
    }

    response = sftp_exchange(sftp, SSH_FXP_OPEN, request, packed, id);
    if (response == NULL) {
        return NULL;
    }
    if (response->type == SSH_FXP_HANDLE) {
        ssh_string handle = ssh_buffer_get_ssh_string(response->payload);
        if (handle == NULL || ssh_string_len(handle) > SFTP_HANDLE_SIZE_MAX ||
            ssh_buffer_get_len(response->payload) != 0) {
            ssh_string_free(handle);
            sftp->stream_failed = 1;
            ssh_set_error(SSH_FATAL, "invalid SFTP file handle");
        } else {
            file = calloc(1, sizeof(*file));
            if (file == NULL) {
                ssh_string_free(handle);
                sftp->stream_failed = 1;
                ssh_set_error(SSH_FATAL, "cannot allocate SFTP file");
            } else {
                file->sftp = sftp;
                file->handle = handle;
            }
        }
    } else if (sftp_read_status(response, &status) == SSH_OK &&
               (status == SSH_FX_OK || status == SSH_FX_EOF)) {
        ssh_set_error(SSH_FATAL, "SFTP open returned status %u without a file handle",
                      status);
    }

    sftp_packet_free(response);
    return file;
}

int sftp_close(sftp_file file) {
    ssh_buffer request;
    sftp_packet response;
    uint32_t id;
    int rc;

    if (file == NULL) {
        ssh_set_error(SSH_FATAL, "missing SFTP file");
        return SSH_ERROR;
    }

    request = sftp_request_new();
    rc = SSH_ERROR;
    if (request != NULL) {
        id = ++file->sftp->id_counter;
        response = sftp_exchange(file->sftp, SSH_FXP_CLOSE, request,
                                 ssh_buffer_pack(request, "dS", id, file->handle), id);
        rc = sftp_expect_ok(response);
        sftp_packet_free(response);
    }
    ssh_string_free(file->handle);
    free(file);
    return rc;
}

int32_t sftp_read(sftp_file file, void *buf, uint32_t count) {
    ssh_buffer request;
    sftp_packet response;
    ssh_string data;
    uint32_t id, status;
    size_t length;
    int32_t result = SSH_ERROR;

    if (file == NULL || (buf == NULL && count != 0)) {
        ssh_set_error(SSH_FATAL, "invalid SFTP read arguments");
        return SSH_ERROR;
    }
    if (file->eof || count == 0) {
        return 0;
    }

    count = MIN(count, SSH_FXP_MAXLEN);
    request = sftp_request_new();
    if (request == NULL) return SSH_ERROR;
    id = ++file->sftp->id_counter;
    response = sftp_exchange(file->sftp, SSH_FXP_READ, request,
                             ssh_buffer_pack(request, "dSqd", id, file->handle,
                                             file->offset, count), id);
    if (response == NULL) {
        return SSH_ERROR;
    }

    if (response->type == SSH_FXP_DATA) {
        data = ssh_buffer_get_ssh_string(response->payload);
        length = data != NULL ? ssh_string_len(data) : 0;
        if (length == 0 || length > count || length > UINT64_MAX - file->offset ||
            ssh_buffer_get_len(response->payload) != 0) {
            ssh_set_error(SSH_FATAL, "invalid SFTP read data length");
        } else {
            memcpy(buf, ssh_string_data(data), length);
            file->offset += length;
            result = (int32_t)length;
        }
        ssh_string_free(data);
    } else if (sftp_read_status(response, &status) == SSH_OK) {
        if (status == SSH_FX_EOF) {
            file->eof = 1;
            result = 0;
        } else if (status == SSH_FX_OK) {
            ssh_set_error(SSH_FATAL, "SFTP read returned success without file data");
        }
    }

    sftp_packet_free(response);
    return result;
}

int32_t sftp_write(sftp_file file, const void *buf, uint32_t count) {
    const uint8_t *bytes = buf;
    uint32_t written = 0;

    if (file == NULL || (buf == NULL && count != 0) || count > INT32_MAX ||
        count > UINT64_MAX - file->offset) {
        ssh_set_error(SSH_FATAL, "invalid SFTP write arguments");
        return SSH_ERROR;
    }

    while (written < count) {
        uint32_t chunk = MIN(count - written, SSH_FXP_MAXLEN);
        uint32_t id = ++file->sftp->id_counter;
        ssh_buffer request = sftp_request_new();
        if (request == NULL) return SSH_ERROR;
        sftp_packet response = sftp_exchange(file->sftp, SSH_FXP_WRITE, request,
                                             ssh_buffer_pack(request, "dSqdP", id,
                                                             file->handle, file->offset,
                                                             chunk, (size_t)chunk,
                                                             bytes + written), id);
        int rc = sftp_expect_ok(response);

        sftp_packet_free(response);
        if (rc != SSH_OK) {
            return SSH_ERROR;
        }
        written += chunk;
        file->offset += chunk;
    }
    return (int32_t)written;
}

sftp_attributes sftp_stat(sftp_session session, const char *path) {
    return NULL;
}
