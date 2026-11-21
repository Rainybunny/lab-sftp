/**
 * @file client.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SFTP client, only supports uploading and downloading files.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libsftp/auth.h"
#include "libsftp/libsftp.h"
#include "libsftp/util.h"

#define MAX_BUF_SIZE 16384
#define MAX_FILENAME 50

static const char *strip_filename(const char *filename) {
    const char *slash = strrchr(filename, '/');
    return slash != NULL ? slash + 1 : filename;
}

static int get_filename(char filename[MAX_FILENAME + 2]) {
    fputs("Enter filename: ", stdout);
    fflush(stdout);
    if (scanf("%51s", filename) != 1 || strlen(filename) > MAX_FILENAME ||
        *strip_filename(filename) == '\0') {
        fputs("A file name of up to 50 bytes is required\n", stderr);
        return -1;
    }
    return 0;
}

static int write_all(int fd, const char *buffer, size_t count) {
    while (count > 0) {
        ssize_t written = write(fd, buffer, count);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        buffer += written;
        count -= written;
    }
    return 0;
}

static int get_file(sftp_session sftp) {
    char filename[MAX_FILENAME + 2];
    char buffer[MAX_BUF_SIZE];
    const char *local_name;
    sftp_file file;
    int fd;
    int result = -1;

    if (get_filename(filename) != 0) return -1;
    local_name = strip_filename(filename);

    file = sftp_open(sftp, filename, O_RDONLY, 0);
    if (file == NULL) {
        fprintf(stderr, "Cannot open remote file %s: %s\n", filename, ssh_get_error());
        return -1;
    }

    fd = open(local_name, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd < 0) {
        fprintf(stderr, "Cannot open local file for writing: %s\n", strerror(errno));
        sftp_close(file);
        return -1;
    }

    for (;;) {
        int32_t received = sftp_read(file, buffer, sizeof(buffer));
        if (received == 0) {
            result = 0;
            break;
        }
        if (received < 0) {
            fprintf(stderr, "Cannot read remote file: %s\n", ssh_get_error());
            break;
        }
        if (write_all(fd, buffer, received) != 0) {
            fprintf(stderr, "Cannot write local file: %s\n", strerror(errno));
            break;
        }
    }

    if (close(fd) != 0) {
        fprintf(stderr, "Cannot close local file: %s\n", strerror(errno));
        result = -1;
    }
    if (sftp_close(file) != SSH_OK) {
        fprintf(stderr, "Cannot close remote file: %s\n", ssh_get_error());
        result = -1;
    }
    if (result == 0) {
        printf("%s downloaded to the current working directory\n", local_name);
    }
    return result;
}

static int put_file(sftp_session sftp) {
    char filename[MAX_FILENAME + 2];
    char buffer[MAX_BUF_SIZE];
    const char *remote_name;
    sftp_file file;
    int fd;
    int result = -1;

    if (get_filename(filename) != 0) return -1;
    remote_name = strip_filename(filename);

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open local file for reading: %s\n", strerror(errno));
        return -1;
    }

    file = sftp_open(sftp, remote_name, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if (file == NULL) {
        fprintf(stderr, "Cannot open remote file %s: %s\n", remote_name, ssh_get_error());
        close(fd);
        return -1;
    }

    for (;;) {
        ssize_t received = read(fd, buffer, sizeof(buffer));
        if (received == 0) {
            result = 0;
            break;
        }
        if (received < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Cannot read local file: %s\n", strerror(errno));
            break;
        }
        if (sftp_write(file, buffer, received) != received) {
            fprintf(stderr, "Cannot write remote file: %s\n", ssh_get_error());
            break;
        }
    }

    close(fd);
    if (sftp_close(file) != SSH_OK) {
        fprintf(stderr, "Cannot close remote file: %s\n", ssh_get_error());
        result = -1;
    }
    if (result == 0) {
        printf("%s uploaded to the remote home directory\n", remote_name);
    }
    return result;
}

int main(int argc, char **argv) {
    ssh_session session;
    sftp_session sftp = NULL;
    char password[100];
    char command[11];
    int rc;
    int result = EXIT_FAILURE;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s username@hostname\n", argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);
    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Cannot create SSH session: %s\n", ssh_get_error());
        return EXIT_FAILURE;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, argv[1]) != SSH_OK ||
        ssh_connect(session) != SSH_OK) {
        fprintf(stderr, "Cannot connect: %s\n", ssh_get_error());
        goto cleanup;
    }

    do {
        if (ssh_read_password(password, sizeof(password)) != SSH_OK) {
            fprintf(stderr, "%s\n", ssh_get_error());
            goto cleanup;
        }
        rc = ssh_userauth_password(session, password);
        explicit_bzero(password, sizeof(password));
        if (rc != SSH_OK) {
            fprintf(stderr, "%s\n", ssh_get_error());
        }
    } while (rc == SSH_AGAIN);

    if (rc != SSH_OK) goto cleanup;

    sftp = sftp_new(session);
    if (sftp == NULL || sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Cannot start SFTP: %s\n", ssh_get_error());
        goto cleanup;
    }

    for (;;) {
        fputs("sftp> ", stdout);
        fflush(stdout);
        if (scanf("%10s", command) != 1) {
            if (feof(stdin)) break;
            goto cleanup;
        }
        if (strcmp(command, "get") == 0) {
            if (get_file(sftp) != 0) goto cleanup;
        } else if (strcmp(command, "put") == 0) {
            if (put_file(sftp) != 0) goto cleanup;
        } else if (strcmp(command, "bye") == 0) {
            puts("Disconnect");
            break;
        } else {
            fprintf(stderr, "Unsupported command: %s. Use get, put, or bye.\n", command);
        }
    }
    result = EXIT_SUCCESS;

cleanup:
    sftp_free(sftp);
    ssh_free(session);
    return result;
}
