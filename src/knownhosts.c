/**
 * @file knownhosts.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief Get known SSH hosts on the client.
 * @version 0.1
 * @date 2022-10-05
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "libsftp/knownhosts.h"

#include <string.h>

#include "libsftp/util.h"

/**
 * @brief 
 * @note Not used since we do not verify public keys and certificates.
 * @return char* 
 */
char *ssh_get_known_hosts(void) {
    const char file[] = "/.ssh/known_hosts";
    char *dir = ssh_get_home_dir();
    char *path;

    if (dir == NULL) return NULL;
    path = malloc(strlen(dir) + sizeof(file));
    if (path != NULL) {
        strcpy(path, dir);
        strcat(path, file);
    }
    free(dir);
    return path;
}
