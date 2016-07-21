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

#include "http.h"
#include "adv.h"
#include "rec.h"

#include <jose/jwk.h>

#include <string.h>

static int
cmd_provision(int argc, char *argv[])
{
    return EXIT_FAILURE;
}

static int
cmd_recover(int argc, char *argv[])
{
    return EXIT_FAILURE;
}

static int
cmd_check(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    char url[8192] = {};
    json_t *keys = NULL;
    json_t *adv = NULL;
    size_t rec = 0;
    int r = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s URL\n", argv[0]);
        return EXIT_FAILURE;
    }

    snprintf(url, sizeof(url), "%s/adv", argv[1]);
    r = http(url, HTTP_GET, NULL, &adv);
    if (r != 200) {
        if (r < 0)
            printf("Error fetching advertisement! %s\n", strerror(-r));
        else
            printf("Error fetching advertisement! HTTP Status %d\n", r);

        goto egress;
    }

    keys = adv_vld(adv, NULL);
    if (!keys) {
        printf("Error validating advertisement!\n");
        goto egress;
    }

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = json_array_get(keys, i);
        json_t *state = NULL;
        json_t *bef = NULL;
        json_t *aft = NULL;
        json_t *req = NULL;
        json_t *rep = NULL;

        if (!jose_jwk_allowed(jwk, true, NULL, "tang.derive") &&
            !jose_jwk_allowed(jwk, true, NULL, "wrapKey"))
            continue;

        if (!adv_rep(jwk, 16, &state, &bef)) {
            printf("Error creating binding!\n");
            goto egress;
        }

        req = rec_req(state);
        if (!req) {
            printf("Error preparing recovery request!\n");
            goto egress;
        }

        snprintf(url, sizeof(url), "%s/rec", argv[1]);
        r = http(url, HTTP_POST, req, &rep);
        if (r != 200) {
            if (r < 0)
                printf("Error performing recovery! %s\n", strerror(-r));
            else
                printf("Error performing recovery! HTTP Status %d\n", r);

            goto egress;
        }

        aft = rec_rep(state, rep);
        if (!aft) {
            printf("Error handing recovery result!\n");
            goto egress;
        }

        if (!json_equal(bef, aft)) {
            printf("Recovered key doesn't match!\n");
            goto egress;
        }

        json_decref(state);
        json_decref(bef);
        json_decref(aft);
        json_decref(req);
        json_decref(rep);

        rec++;
    }

    printf("OK: %zu\n", rec);
    ret = EXIT_SUCCESS;

egress:
    json_decref(keys);
    json_decref(adv);
    return ret;
}

int
main(int argc, char *argv[])
{
    static const struct {
        const char *cmd;
        int (*func)(int argc, char *argv[]);
    } table[] = {
        { "provision", cmd_provision },
        { "recover", cmd_recover },
        { "check", cmd_check },
        {}
    };

    const char *cmd = NULL;

    if (argc >= 2) {
        char argv0[strlen(argv[0]) + strlen(argv[1]) + 2];
        strcpy(argv0, argv[0]);
        strcat(argv0, " ");
        strcat(argv0, argv[1]);
        cmd = argv[1];
        argv[1] = argv0;

        for (size_t i = 0; table[i].cmd; i++) {
            if (strcmp(cmd, table[i].cmd) == 0)
                return table[i].func(argc - 1, argv + 1);
        }
    }

    fprintf(stderr,
"Usage: tang COMMAND [OPTIONS] [ARGUMENTS]\n"
"\n"
"tang provision [-o FILE] [-a ADV ...] URL ...\n"
"tang recover   [-i FILE]\n"
"tang check     URL\n"
"\n");
    return EXIT_FAILURE;
}
