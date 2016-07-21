/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
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

#include "clt.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

struct ctx {
    size_t size;
    char *body;
    bool done;
};

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    char *tmp = NULL;

    if (ctx->size + length > 2 * 1024 * 1024)
        return -E2BIG;

    tmp = realloc(ctx->body, ctx->size + length);
    if (!tmp)
        return -ENOMEM;

    memcpy(&tmp[ctx->size], at, length);
    ctx->size += length;
    ctx->body = tmp;
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct ctx *ctx = parser->data;
    ctx->done = true;
    return 0;
}

static const http_parser_settings settings = {
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};


static int
callback(const char *buffer, size_t size, void *data)
{
    int *sock = data;

    if (dprintf(*sock, "%zX\r\n", size) < 0)
        return -EIO;

    if (send(*sock, buffer, size, 0) < 0)
        return -errno;

    if (send(*sock, "\r\n", 2, 0) < 0)
        return -errno;

    return 0;
}

int
http(const char *url, enum http_method m, const json_t *ib, json_t **ob)
{
    const uint16_t mask = (1 << UF_SCHEMA) | (1 << UF_HOST) | (1 << UF_PATH);
    struct http_parser_url purl = {};
    struct addrinfo *ais = NULL;
    const char *method = NULL;
    int sock = -1;
    int r = 0;

    *ob = NULL;

    switch (m) {
    case HTTP_DELETE: method = "DELETE"; break;
    case HTTP_GET: method = "GET"; break;
    case HTTP_POST: method = "POST"; break;
    case HTTP_PUT: method = "PUT"; break;
    default: return -ENOTSUP;
    }

    if (http_parser_parse_url(url, strlen(url), false, &purl) != 0)
        return -EINVAL;

    if ((purl.field_set & mask) != mask)
        return -EINVAL;

    if (purl.field_data[UF_PATH].len > PATH_MAX)
        return -EINVAL;

    char host[purl.field_data[UF_HOST].len + 1];
    char path[purl.field_data[UF_PATH].len + 1];
    char srvc[6] = "http";
    memset(host, 0, sizeof(host));

    if (strncmp(&url[purl.field_data[UF_SCHEMA].off], "http",
                purl.field_data[UF_SCHEMA].len) != 0)
        return -EINVAL;

    if (purl.field_set & (1 << UF_PORT)) {
        if (purl.field_data[UF_PORT].len >= sizeof(srvc))
            return -EINVAL;

        strncpy(srvc, &url[purl.field_data[UF_PORT].off],
                purl.field_data[UF_PORT].len);
        srvc[purl.field_data[UF_PORT].len] = 0;
    }

    strncpy(host, &url[purl.field_data[UF_HOST].off],
            purl.field_data[UF_HOST].len);
    host[purl.field_data[UF_HOST].len] = 0;

    strncpy(path, &url[purl.field_data[UF_PATH].off],
            purl.field_data[UF_PATH].len);
    path[purl.field_data[UF_PATH].len] = 0;

    r = getaddrinfo(host, srvc,
                    &(struct addrinfo) { .ai_socktype = SOCK_STREAM }, &ais);
    switch (r) {
    case 0: break;
    case EAI_AGAIN: return -EAGAIN;
    case EAI_BADFLAGS: return -EINVAL;
    case EAI_FAMILY: return -ENOTSUP;
    case EAI_MEMORY: return -ENOMEM;
    case EAI_SERVICE: return -EINVAL;
    default: return -EIO;
    }

    for (const struct addrinfo *ai = ais; ai; ai = ai->ai_next) {
        http_parser parser = {};
        struct ctx ctx = {};
        char buf[512] = {};
        size_t len = 0;

        close(sock);

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0)
            continue;

        if (dprintf(sock, "%s %s HTTP/1.1\r\n", method, path) < 0)
            break;

        if (dprintf(sock, "Host: %s\r\n", host) < 0)
            break;

        if ((m == HTTP_PUT || m == HTTP_POST) && ib) {
            if (dprintf(sock, "Transfer-Encoding: chunked\r\n") < 0)
                break;

            if (dprintf(sock, "Content-Type: application/json\r\n") < 0)
                break;
        } else {
            if (dprintf(sock, "Content-Length: 0\r\n") < 0)
                break;
        }

        if (dprintf(sock, "\r\n") < 0)
            break;

        if ((m == HTTP_PUT || m == HTTP_POST) && ib) {
            if (json_dump_callback(ib, callback, &sock,
                                   JSON_SORT_KEYS | JSON_COMPACT) == -1)
                break;

            if (dprintf(sock, "0\r\n\r\n") < 0)
                break;
        }

        http_parser_init(&parser, HTTP_RESPONSE);
        parser.data = &ctx;

        for (ssize_t x = 1; x > 0 && !ctx.done; ) {
            size_t sz = 0;

            x = recv(sock, &buf[len], sizeof(buf) - len, 0);
            if (x < 0)
                break;

            len += x;

            sz = http_parser_execute(&parser, &settings, buf, x);
            if (parser.http_errno != 0) {
                fprintf(stderr, "Fatal error: %s: %s\n",
                        http_errno_name(parser.http_errno),
                        http_errno_description(parser.http_errno));
                break;
            }

            len -= sz;
            memmove(buf, &buf[sz], len);
        }

        if (ctx.done) {
            if (ctx.size > 0)
                *ob = json_loadb(ctx.body, ctx.size, 0, NULL);
            errno = -parser.status_code;
        }

        free(ctx.body);
        break;
    }

    freeaddrinfo(ais);
    close(sock);
    return -errno;
}
