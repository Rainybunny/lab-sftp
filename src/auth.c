/**
 * @file auth.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH authentication layer functionalities.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/auth.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

#define MAX_AUTH_ATTEMPTS 3

static int receive_auth_message(ssh_session session, uint8_t *type) {
    do {
        if (ssh_packet_receive(session) != SSH_OK) {
            return SSH_ERROR;
        }
        if (ssh_buffer_get_u8(session->in_buffer, type) != 1) {
            ssh_set_error(SSH_FATAL, "missing authentication message type");
            return SSH_ERROR;
        }
    } while (*type == SSH_MSG_IGNORE || *type == SSH_MSG_DEBUG);
    return SSH_OK;
}

int ssh_request_auth(ssh_session session) {
    uint8_t type;
    char *service = NULL;

    if (ssh_buffer_pack(session->out_buffer, "bs", SSH_MSG_SERVICE_REQUEST,
                        "ssh-userauth") != SSH_OK ||
        ssh_packet_send(session) != SSH_OK) {
        ssh_buffer_reinit(session->out_buffer);
        ssh_set_error(SSH_FATAL, "cannot send authentication service request");
        return SSH_ERROR;
    }

    if (receive_auth_message(session, &type) != SSH_OK ||
        type != SSH_MSG_SERVICE_ACCEPT ||
        ssh_buffer_unpack(session->in_buffer, "s", &service) != SSH_OK ||
        strcmp(service, "ssh-userauth") != 0 ||
        ssh_buffer_get_len(session->in_buffer) != 0) {
        free(service);
        ssh_set_error(SSH_REQUEST_DENIED, "ssh-userauth service request failed");
        return SSH_ERROR;
    }

    free(service);
    return SSH_OK;
}

static volatile sig_atomic_t password_interrupted;

static void interrupt_password_read(int signal_number) {
    password_interrupted = signal_number;
}

/* Keep echo disabled only while the input is being read. */
int ssh_read_password(char *password, size_t size) {
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP};
    struct sigaction original[sizeof(signals) / sizeof(signals[0])];
    struct sigaction action = {0};
    struct termios saved, hidden;
    size_t installed = 0, used = 0;
    int c = EOF, result = SSH_ERROR;
    int terminal = isatty(STDIN_FILENO);
    int overflow = 0;

    if (password == NULL || size == 0) {
        return SSH_ERROR;
    }
    password[0] = '\0';
    password_interrupted = 0;

    if (terminal) {
        if (tcgetattr(STDIN_FILENO, &saved) != 0) {
            goto done;
        }
        action.sa_handler = interrupt_password_read;
        sigemptyset(&action.sa_mask);
        while (installed < sizeof(signals) / sizeof(signals[0])) {
            if (sigaction(signals[installed], &action, &original[installed]) != 0) {
                goto done;
            }
            installed++;
        }
        hidden = saved;
        hidden.c_lflag &= ~(ECHO | ECHONL);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden) != 0) {
            goto done;
        }
    }

    fputs("password: ", stdout);
    fflush(stdout);
    while (!password_interrupted && (c = getchar()) != EOF && c != '\n') {
        if (used < size - 1 && c != '\0') {
            password[used++] = (char)c;
        } else {
            overflow = 1;
        }
    }
    password[used] = '\0';
    if (!password_interrupted && !overflow && c == '\n') {
        result = SSH_OK;
    }
    if (terminal) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &saved) != 0) {
            result = SSH_ERROR;
        }
        fputc('\n', stdout);
    }

done:
    while (installed > 0) {
        installed--;
        sigaction(signals[installed], &original[installed], NULL);
    }
    if (result != SSH_OK) {
        explicit_bzero(password, size);
        ssh_set_error(SSH_REQUEST_DENIED,
                      overflow ? "password exceeds the input limit or contains NUL"
                               : "password input ended or was interrupted");
    }
    return result;
}

void ssh_get_password(char *password) {
    ssh_read_password(password, 100);
}

static int display_banner(ssh_buffer buffer) {
    char *message = NULL, *language = NULL;
    int rc = ssh_buffer_unpack(buffer, "ss", &message, &language);

    if (rc == SSH_OK && ssh_buffer_get_len(buffer) != 0) {
        rc = SSH_ERROR;
    }
    if (rc == SSH_OK) {
        for (const unsigned char *p = (unsigned char *)message; *p != '\0'; p++) {
            if ((*p >= 32 && *p != 127) || *p == '\n' || *p == '\t') {
                fputc(*p, stderr);
            }
        }
        fputc('\n', stderr);
    }

    free(message);
    free(language);
    return rc;
}

static int allows_password(const char *methods) {
    while (*methods != '\0') {
        size_t length = strcspn(methods, ",");
        if (length == sizeof("password") - 1 &&
            memcmp(methods, "password", length) == 0) {
            return 1;
        }
        methods += length;
        if (*methods == ',') {
            methods++;
        }
    }
    return 0;
}

static int auth_failure(ssh_session session) {
    char *methods = NULL;
    uint8_t partial;
    int retry;

    if (ssh_buffer_unpack(session->in_buffer, "sb", &methods, &partial) != SSH_OK ||
        ssh_buffer_get_len(session->in_buffer) != 0) {
        free(methods);
        ssh_set_error(SSH_FATAL, "invalid password authentication failure");
        return SSH_ERROR;
    }

    retry = allows_password(methods);
    free(methods);
    if (partial || !retry) {
        ssh_set_error(SSH_REQUEST_DENIED, partial ? "additional authentication is required"
                                                : "server does not allow password authentication");
        return SSH_ERROR;
    }

    if (++session->auth_failures >= MAX_AUTH_ATTEMPTS) {
        ssh_set_error(SSH_REQUEST_DENIED, "password authentication failed after three attempts");
        return SSH_ERROR;
    }
    ssh_set_error(SSH_REQUEST_DENIED, "password authentication failed, try again");
    return SSH_AGAIN;
}

int ssh_userauth_password(ssh_session session, const char *password) {
    uint8_t type;

    if (session == NULL || password == NULL || session->opts.username == NULL) {
        ssh_set_error(SSH_FATAL, "missing username or password");
        return SSH_ERROR;
    }
    if (session->auth_failures >= MAX_AUTH_ATTEMPTS) {
        ssh_set_error(SSH_REQUEST_DENIED, "password authentication attempt limit reached");
        return SSH_ERROR;
    }

    if (ssh_buffer_pack(session->out_buffer, "bsssbs", SSH_MSG_USERAUTH_REQUEST,
                        session->opts.username, "ssh-connection", "password",
                        0, password) != SSH_OK ||
        ssh_packet_send(session) != SSH_OK) {
        ssh_buffer_reinit(session->out_buffer);
        ssh_set_error(SSH_FATAL, "cannot send password authentication request");
        return SSH_ERROR;
    }

    while (receive_auth_message(session, &type) == SSH_OK) {
        switch (type) {
            case SSH_MSG_USERAUTH_BANNER:
                if (display_banner(session->in_buffer) != SSH_OK) {
                    ssh_set_error(SSH_FATAL, "invalid authentication banner");
                    return SSH_ERROR;
                }
                break;
            case SSH_MSG_USERAUTH_SUCCESS:
                if (ssh_buffer_get_len(session->in_buffer) != 0) {
                    ssh_set_error(SSH_FATAL, "invalid authentication success message");
                    return SSH_ERROR;
                }
                session->auth_failures = 0;
                LOG_NOTICE("password authentication succeeded (SSH_MSG_USERAUTH_SUCCESS)");
                return SSH_OK;
            case SSH_MSG_USERAUTH_FAILURE:
                return auth_failure(session);
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
                ssh_set_error(SSH_REQUEST_DENIED, "server requires a password change");
                return SSH_ERROR;
            default:
                ssh_set_error(SSH_FATAL, "unexpected SSH message %u during authentication", type);
                return SSH_ERROR;
        }
    }
    return SSH_ERROR;
}
