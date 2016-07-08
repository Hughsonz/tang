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

#include "eng.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>

#define LISTEN_FD_START 3
#define NEVTS 5

#define JSONRPC_CODE_PARSE_ERROR -32700
#define JSONRPC_CODE_INVALID_REQUEST -32600
#define JSONRPC_CODE_METHOD_NOT_FOUND -32601
#define JSONRPC_CODE_INVALID_PARAMS -32702
#define JSONRPC_CODE_INTERNAL_ERROR -32703
#define TANG_CODE_PERMISSION_DENIED 5700

extern eng_t openssl;

typedef struct {
    char data[65535];
    int size;
} pkt_t;

union anyaddr {
    struct sockaddr_storage store;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
};

struct addr {
    union anyaddr any;
    socklen_t size;
};

static const struct {
    json_int_t code;
    const char *msg;
} errors[] = {
    { JSONRPC_CODE_PARSE_ERROR, "Parse error" },
    { JSONRPC_CODE_INVALID_REQUEST, "Invalid Request" },
    { JSONRPC_CODE_METHOD_NOT_FOUND, "Method not found" },
    { JSONRPC_CODE_INVALID_PARAMS, "Invalid params" },
    { JSONRPC_CODE_INTERNAL_ERROR, "Internal error" },
    { TANG_CODE_PERMISSION_DENIED, "Permission denied" },
    {}
};

static int epoll = -1;

static void
onsig(int sig)
{
    close(epoll);
}

static int
epoll_add(int fd)
{
    return epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &(struct epoll_event) {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLPRI,
        .data.fd = fd
    });
}

static int
callback(const char *buffer, size_t size, void *data)
{
    pkt_t *pkt = data;

    if (pkt->size + size + 1 > sizeof(pkt->data))
        return -1;

    memcpy(&pkt->data[pkt->size], buffer, size);
    pkt->size += size;
    return 0;
}

static void
make_error(json_int_t code, const json_t *id, pkt_t *pkt)
{
    const char *msg = NULL;
    json_t *err = NULL;

    for (size_t i = 0; errors[i].msg && !msg; i++) {
        if (errors[i].code == code)
            msg = errors[i].msg;
    }

    if (!msg)
        return make_error(JSONRPC_CODE_INTERNAL_ERROR, id, pkt);

    err = json_pack("{s:s,s:O,s:{s:i,s:s}}",
                    "jsonrpc", "2.0", "id", id ? id : json_null(),
                    "error", "code", code, "message", msg);
    if (err) {
        pkt->size = 0;
        if (json_dump_callback(err, callback, pkt, JSON_SORT_KEYS) == 0)
            return;
    }

    /* If we get here, we have hardcore-failed. So we need to set an error
     * response without anything that can fail (like allocation). */
    strcpy(pkt->data,
           "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{"
           "\"code\":-32603,\"message\":\"Internal error\"}}");
    pkt->size = strlen(pkt->data);
}

static void
handle(json_t *ctx, int fd)
{
    eng_err_t err = ENG_ERR_NONE;
    const char *paramid = NULL;
    const char *method = NULL;
    const char *jrpcv = NULL;
    const json_t *id = NULL;
    struct addr addr = {};
    json_t *req = NULL;
    json_t *rep = NULL;
    pkt_t pkt = {};

    addr.size = sizeof(addr.any.store);
    pkt.size = recvfrom(fd, pkt.data, sizeof(pkt.data),
                        0, &addr.any.addr, &addr.size);
    if (pkt.size < 0)
        return;

    req = json_loadb(pkt.data, pkt.size, 0, NULL);
    if (!req) {
        make_error(JSONRPC_CODE_PARSE_ERROR, id, &pkt);
        goto egress;
    }

    fprintf(stderr, "Received: ");
    json_dumpf(req, stderr, JSON_SORT_KEYS);
    fprintf(stderr, "\n");

    if (json_unpack(req, "{s:s,s:s,s:o,s?{s?s}}",
                    "jsonrpc", &jrpcv, "method", &method, "id", &id,
                    "params", "id", &paramid) == -1 || strcmp(jrpcv, "2.0")) {
        make_error(JSONRPC_CODE_INVALID_REQUEST, id, &pkt);
        goto egress;
    }

    if (strcmp(method, "tang.adv") == 0)
        err = openssl.adv(ctx, paramid, &rep);
    else if (strcmp(method, "tang.rec") == 0)
        err = openssl.rec(ctx, paramid, json_object_get(req, "params"), &rep);
    else {
        make_error(JSONRPC_CODE_METHOD_NOT_FOUND, id, &pkt);
        goto egress;
    }

    switch (err) {
    case ENG_ERR_BAD_REQ:
        make_error(JSONRPC_CODE_INVALID_PARAMS, id, &pkt);
        break;

    case ENG_ERR_DENIED:
        make_error(TANG_CODE_PERMISSION_DENIED, id, &pkt);
        break;

    case ENG_ERR_NONE:
        rep = json_pack("{s:s,s:O,s:o}", "jsonrpc", "2.0",
                        "id", id, "result", rep);
        memset(&pkt, 0, sizeof(pkt));
        if (rep && json_dump_callback(rep, callback, &pkt,
                                      JSON_SORT_KEYS | JSON_COMPACT) == 0)
            break;
        /* Fallthrough */

    default:
        make_error(JSONRPC_CODE_INTERNAL_ERROR, id, &pkt);
        break;
    }

egress:
    fprintf(stderr, "Sending (%d): %s\n", pkt.size, pkt.data);

    if (pkt.size > 0)
        sendto(fd, pkt.data, pkt.size, 0, &addr.any.addr, addr.size);
    json_decref(req);
    json_decref(rep);
}

static size_t
get_listen_fds(void)
{
    const char *lfds = NULL;

    lfds = getenv("LISTEN_FDS");
    if (!lfds)
        return 0;

    return strtoul(lfds, NULL, 10);
}

int
main(int argc, char *argv[])
{
    struct epoll_event evts[NEVTS] = {};
    json_t *cfg = NULL;
    json_t *ctx = NULL;
    size_t lfds = 0;

    OpenSSL_add_all_algorithms();

    if (RAND_poll() <= 0)
        return EXIT_FAILURE;

    if (argc != 3 ||
        strcmp(argv[1], "openssl") != 0 ||
        !(cfg = json_loads(argv[2], 0, NULL))) {
        fprintf(stderr, "Usage: %s <ENGINE> <CONFIG>\n", argv[0]);
        return EXIT_FAILURE;
    }

    lfds = get_listen_fds();
    int fds[lfds ? lfds + 1 : 3];

    for (size_t i = 0; i < sizeof(fds) / sizeof(*fds); i++)
        fds[i] = -1;

    if (lfds > 0) {
        for (size_t i = 0; i < lfds; i++)
            fds[i + 1] = LISTEN_FD_START + i;
    } else {
        union anyaddr addr4 = { .addr4 = {
            .sin_family = AF_INET,
            .sin_port = htons(TANG_PORT),
            .sin_addr = { .s_addr = htonl(INADDR_ANY) }
        } };

        union anyaddr addr6 = { .addr6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(TANG_PORT),
            .sin6_addr = IN6ADDR_ANY_INIT
        } };

        fds[1] = socket(AF_INET6, SOCK_DGRAM, 0);
        fds[2] = socket(AF_INET, SOCK_DGRAM, 0);
        if (bind(fds[1], &addr6.addr, sizeof(addr6.addr6)) != 0 &&
            bind(fds[2], &addr4.addr, sizeof(addr4.addr4)) != 0)
            goto egress;
    }

    ctx = openssl.init(cfg, &fds[0]);
    if (!ctx)
        goto egress;

    epoll = epoll_create(1024);
    if (epoll < 0)
        goto egress;

    for (size_t i = 0; i < sizeof(fds) / sizeof(*fds); i++) {
        if (epoll_add(fds[i]) != 0)
            goto egress;
    }

    signal(SIGTERM, onsig);
    signal(SIGINT, onsig);

    for (int nevts; (nevts = epoll_wait(epoll, evts, NEVTS, -1)) > 0; ) {
        for (int i = 0; i < nevts; i++) {
            if (evts[i].data.fd == fds[0])
                openssl.event(ctx, evts[i].data.fd);
            else
                handle(ctx, evts[i].data.fd);
        }
    }

egress:
    for (size_t i = 0; i < sizeof(fds) / sizeof(*fds); i++)
        close(fds[i]);
    close(epoll);

    json_decref(cfg);
    json_decref(ctx);
    EVP_cleanup();
    return EXIT_FAILURE;
}
