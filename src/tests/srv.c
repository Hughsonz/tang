/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "srv.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <systemd/sd-daemon.h>

static char tempdir[] = "/var/tmp/tangXXXXXX";
static pid_t pid;

static void
onexit(void)
{
    const char *cmd = "rm -rf ";
    char tmp[strlen(cmd) + strlen(tempdir) + 1];
    __attribute__((unused)) int r = 0;

    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);

    strcpy(tmp, cmd);
    strcat(tmp, tempdir);
    r = system(tmp);
}

static bool
makesock(int af, const msg_t *p, int fd)
{
    const struct addrinfo hnt = { .ai_family = af, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *addrs = NULL;
    bool success = false;
    int sock = -1;

    if (getaddrinfo(p->hostname, p->service, &hnt, &addrs) != 0)
        goto error;

    sock = socket(af, SOCK_DGRAM, 0);
    if (sock < 0)
        goto error;

    if (bind(sock, addrs->ai_addr, addrs->ai_addrlen) != 0)
        goto error;

    success = dup2(sock, fd) == fd;

error:
    freeaddrinfo(addrs);
    if (!success || sock != fd)
        close(sock);
    return success;
}

void
srv_setup(const msg_t *ipv4, const msg_t *ipv6)
{
    if (!mkdtemp(tempdir))
        error(EXIT_FAILURE, errno, "Error calling mkdtemp()");

    pid = fork();
    if (pid < 0)
        error(EXIT_FAILURE, errno, "Error calling fork()");

    if (pid == 0) {
        if (setenv("LISTEN_FDS", "2", true) != 0)
            error(EXIT_FAILURE, errno, "Error calling setenv()");

        if (!makesock(AF_INET, ipv4, SD_LISTEN_FDS_START))
            error(EXIT_FAILURE, errno, "Error calling makesock()");

        if (!makesock(AF_INET6, ipv6, SD_LISTEN_FDS_START + 1))
            error(EXIT_FAILURE, errno, "Error calling makesock()");

        execlp("../tang-keyd", "../tang-keyd", "-d", tempdir, NULL);
        error(EXIT_FAILURE, errno, "Error calling execlp()");
    }

    atexit(onexit);
    usleep(100000); /* Let the daemon have time to start. */
}

EC_KEY *
srv_keygen(const char *name, const char *grpname, const char *use, bool adv)
{
    char fname[PATH_MAX];
    char cmd[PATH_MAX*2];
    EC_GROUP *grp = NULL;
    EC_KEY *key = NULL;
    FILE *f = NULL;

    if (snprintf(fname, sizeof(fname), "%s/%s", tempdir, name) <= 0)
        return NULL;

    if (snprintf(cmd, sizeof(cmd),
                 "../tang-key-gen -%c %s %s -f %s >/dev/null",
                 adv ? 'A' : 'a', grpname, use, fname) <= 0)
        return NULL;

    if (system(cmd) != 0)
        return NULL;

    f = fopen(fname, "r");
    if (!f)
        return NULL;

    grp = PEM_read_ECPKParameters(f, NULL, NULL, NULL);
    if (grp) {
        if (EC_GROUP_get_curve_name(grp) != NID_undef) {
            key = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
            if (key) {
                if (EC_KEY_set_group(key, grp) <= 0) {
                    EC_KEY_free(key);
                    key = NULL;
                }
            }
        }
    }

    usleep(100000); /* Let the daemon have time to pick up the new files. */

    EC_GROUP_free(grp);
    fclose(f);
    return key;
}

