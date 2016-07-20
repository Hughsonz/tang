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
#include "http_parser.h"

#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define LISTEN_FD_START 3
#define NEVTS 5

extern eng_t jose;

typedef struct {
    char data[32 * 1024];
    size_t used;
} buf_t;

typedef struct {
    json_t *ctx;
    int fd;
    int err;
    char url[4096];
    char *body;
    size_t blen;
} req_t;

static int epoll = -1;

static void
onsig(int sig)
{
    close(epoll);
    epoll = -1;
}

static const char *
http_status_string(int code)
{
    static const struct {
        int code;
        const char *msg;
    } codes[] = {
        { 200, "OK" },
        { 400, "Bad Request" },
        { 403, "Forbidden" },
        { 404, "Not Found" },
        { 405, "Method Not Allowed" },
        { 413, "Request Entity Too Large" },
        { 414, "Request-URI Too Long" },
        { 500, "Internal Server Error" },
        {}
    };

    for (size_t i = 0; codes[i].msg; i++)
        if (codes[i].code == code)
            return codes[i].msg;

    return NULL;
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

static int
on_url(http_parser *parser, const char *at, size_t length)
{
    req_t *req = parser->data;

    if (req->err != 0)
        return 0;

    if (strlen(req->url) + length >= sizeof(req->url)) {
        req->err = 414;
        return 0;
    }

    strncat(req->url, at, length);
    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    req_t *req = parser->data;
    char *tmp = NULL;

    if (req->err != 0)
        return 0;

    if (req->blen + length > 2 * 1024 * 1024) {
        req->err = 413;
        return 0;
    }

    tmp = realloc(req->body, req->blen + length + 1);
    if (!tmp)
        return ENOMEM;

    memcpy(&tmp[req->blen], at, length);
    tmp[req->blen + length] = 0;
    req->blen += length;
    req->body = tmp;
    return 0;
}

static eng_err_t
rec(req_t *r, enum http_method h, regmatch_t *m, const char **ct, json_t **rep)
{
    char id[sizeof(r->url)] = {};
    eng_err_t err = ENG_ERR_NONE;
    json_t *req = NULL;

    if (m[1].rm_so < m[1].rm_eo)
        strncpy(id, &r->url[m[1].rm_so], m[1].rm_eo - m[1].rm_so);

    switch (h) {
    case HTTP_DELETE: return jose.del(r->ctx, id);
    case HTTP_PUT: return jose.add(r->ctx, id);
    case HTTP_POST: break;
    default: return ENG_ERR_BAD_REQ;
    }

    req = json_loadb(r->body, r->blen, 0, NULL);
    if (!req)
        return ENG_ERR_BAD_REQ;

    *ct = "application/jwk+json";
    err = jose.rec(r->ctx, req, rep);
    json_decref(req);
    return err;
}

static eng_err_t
adv(req_t *r, enum http_method h, regmatch_t *m, const char **ct, json_t **rep)
{
    *ct = "application/jose+json";

    if (m[1].rm_so < m[1].rm_eo) {
        char id[sizeof(r->url)] = {};
        strncpy(id, &r->url[m[1].rm_so], m[1].rm_eo - m[1].rm_so);
        return jose.adv(r->ctx, id, rep);
    }

    return jose.adv(r->ctx, NULL, rep);
}

static const struct {
    const char *re;
    eng_err_t
    (*func)(req_t *, enum http_method, regmatch_t *,
            const char **ct, json_t **);
    uint64_t methods;
} funcs[] = {
    { "^/+rec/+([0-9A-Za-z_-]+)?$", rec,
      (1 << HTTP_DELETE) | (1 << HTTP_PUT) | (1 << HTTP_POST) },
    { "^/+rec$", rec,
      (1 << HTTP_DELETE) | (1 << HTTP_PUT) | (1 << HTTP_POST) },
    { "^/+adv/+([0-9A-Za-z_-]+)?$", adv, (1 << HTTP_GET) },
    { "^/+adv$", adv, (1 << HTTP_GET) },
    {}
};

static int
on_message_complete(http_parser *parser)
{
    req_t *req = parser->data;
    const char *msg = NULL;
    const char *ct = NULL;
    char *enc = NULL;

    if (req->err != 0)
        goto egress;

    req->err = 404;

    for (size_t i = 0; funcs[i].func; i++) {
        eng_err_t err = ENG_ERR_NONE;
        regmatch_t m[3] = {};
        json_t *rep = NULL;
        regex_t re = {};

        if (regcomp(&re, funcs[i].re, REG_EXTENDED) != 0) {
            req->err = 500;
            goto egress;
        }

        if (regexec(&re, req->url, sizeof(m) / sizeof(*m), m, 0) != 0) {
            regfree(&re);
            continue;
        }

        if (((1 << parser->method) & funcs[i].methods) == 0) {
            req->err = 405;
            regfree(&re);
            break;
        }

        err = funcs[i].func(req, parser->method, m, &ct, &rep);
        regfree(&re);

        switch (err) {
        case ENG_ERR_INTERNAL: req->err = 500; break;
        case ENG_ERR_BAD_REQ: req->err = 400; break;
        case ENG_ERR_BAD_ID: req->err = 404; break;
        case ENG_ERR_DENIED: req->err = 403; break;
        case ENG_ERR_NONE: req->err = 200; break;
        }

        if (req->err == 200 && rep) {
            enc = json_dumps(rep, JSON_SORT_KEYS | JSON_COMPACT);
            req->err = enc ? req->err : 500;
        }

        json_decref(rep);
        break;
    }

egress:
    msg = http_status_string(req->err);
    if (!msg) {
        req->err = 500;
        msg = "Internal Server Error";
    }

    dprintf(req->fd, "HTTP/1.1 %d %s\r\n", req->err, msg);
    dprintf(req->fd, "Content-Length: %zu\r\n", enc ? strlen(enc) : 0);

    if (req->err == 200 && ct)
        dprintf(req->fd, "Content-Type: %s\r\n", ct);

    dprintf(req->fd, "\r\n");

    if (enc)
        dprintf(req->fd, "%s", enc);

    memset(req->url, 0, sizeof(req->url));

    free(req->body);
    free(enc);

    req->err = 0;
    req->blen = 0;
    req->body = NULL;
    return 0;
}

static const http_parser_settings settings = {
    .on_url = on_url,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

int
main(int argc, char *argv[])
{
    struct epoll_event evts[NEVTS] = {};
    json_t *cfg = NULL;
    json_t *ctx = NULL;
    size_t lfds = 0;
    int engfd = -1;

    if (argc != 3 ||
        strcmp(argv[1], "jose") != 0 ||
        !(cfg = json_loads(argv[2], 0, NULL))) {
        fprintf(stderr, "Usage: %s <ENGINE> <CONFIG>\n", argv[0]);
        return EXIT_FAILURE;
    }

    lfds = get_listen_fds();
    if (!lfds)
        return EXIT_FAILURE;

    buf_t bufs[lfds];
    req_t reqs[lfds];
    http_parser parsers[lfds];

    epoll = epoll_create(1024);
    if (epoll < 0)
        goto egress;

    ctx = jose.init(cfg, &engfd);
    if (!ctx)
        goto egress;

    if (epoll_ctl(epoll, EPOLL_CTL_ADD, engfd, &(struct epoll_event) {
                      .events = EPOLLIN | EPOLLRDHUP | EPOLLPRI,
                      .data.fd = engfd
                  }) != 0)
        goto egress;

    memset(bufs, 0, sizeof(bufs));
    memset(reqs, 0, sizeof(reqs));

    for (size_t i = 0; i < lfds; i++) {
        reqs[i].fd = LISTEN_FD_START + i;
        reqs[i].ctx = ctx;

        http_parser_init(&parsers[i], HTTP_REQUEST);
        parsers[i].data = &reqs[i];

        if (fcntl(reqs[i].fd, F_SETFL, O_NONBLOCK) != 0)
            goto egress;

        if (epoll_ctl(epoll, EPOLL_CTL_ADD, reqs[i].fd, &(struct epoll_event) {
                          .events = EPOLLIN | EPOLLRDHUP | EPOLLPRI,
                          .data.fd = reqs[i].fd
                      }) != 0)
            goto egress;
    }

    signal(SIGPIPE, onsig);
    signal(SIGTERM, onsig);
    signal(SIGINT, onsig);

    for (int nevts; (nevts = epoll_wait(epoll, evts, NEVTS, -1)) > 0; ) {
        for (int i = 0; i < nevts; i++) {
            if (evts[i].data.fd == engfd) {
                jose.event(ctx, engfd);
                continue;
            }

            for (size_t j = 0; j < sizeof(reqs) / sizeof(*reqs); j++) {
                ssize_t r = 0;

                if (evts[i].data.fd != reqs[j].fd)
                    continue;

                r = read(reqs[j].fd, &bufs[j].data[bufs[j].used],
                         sizeof(bufs[j].data) - bufs[j].used);
                if (r == 0)
                    goto egress;
                else if (r < 0) {
                    switch (errno) {
                    case EAGAIN: continue;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
                    case EWOULDBLOCK: continue;
#endif
                    default: goto egress;
                    }
                }

                bufs[j].used += r;
                r = http_parser_execute(&parsers[j], &settings,
                                        bufs[j].data, bufs[j].used);
                if (parsers[j].http_errno != 0) {
                    fprintf(stderr, "Fatal Error: %s\n",
                            http_errno_description(parsers[j].http_errno));
                    goto egress;
                }

                bufs[j].used -= r;
                memmove(bufs[j].data, &bufs[j].data[r], bufs[j].used);
                break;
            }
        }
    }

egress:
    for (size_t i = 0; i < sizeof(reqs) / sizeof(*reqs); i++)
        close(reqs[i].fd);
    close(engfd);
    close(epoll);

    json_decref(cfg);
    json_decref(ctx);
    return EXIT_FAILURE;
}
