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

#pragma once
#include <jansson.h>
#include <stdbool.h>

typedef enum {
    ENG_ERR_NONE = 0,
    ENG_ERR_INTERNAL,
    ENG_ERR_BAD_REQ,
    ENG_ERR_BAD_ID,
    ENG_ERR_DENIED,
} eng_err_t;

typedef struct eng {
    const char *name;

    json_t *(*init)(const json_t *cfg, int *fd);
    void (*event)(json_t *ctx, int fd);

    eng_err_t (*add)(json_t *ctx, const char *ktp);
    eng_err_t (*del)(json_t *ctx, const char *ktp);
    eng_err_t (*adv)(json_t *ctx, const char *ktp, const char **o);
    eng_err_t (*rec)(json_t *ctx, const char *ktp, json_t *i, const char **o);
} eng_t;
