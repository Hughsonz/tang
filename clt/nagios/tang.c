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

#include "../clt.h"

#include <jose/jwk.h>

#include <string.h>
#include <time.h>

enum {
    NAGIOS_OK = 0,
    NAGIOS_WARN = 1,
    NAGIOS_CRIT = 2,
    NAGIOS_UNKN = 3
};

static double
curtime(void)
{
    struct timespec ts = {};
    double out = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
        out = ((double) ts.tv_sec) + ((double) ts.tv_nsec) / 1000000000L;

    return out;
}

static void
dump_perf(json_t *time)
{
    const char *key = NULL;
    bool first = true;
    json_t *val = 0;

    json_object_foreach(time, key, val) {
        int v = 0;

        if (!first)
            printf(" ");
        else
            first = false;

        if (json_is_integer(val))
            v = json_integer_value(val);
        else if (json_is_real(val))
            v = json_real_value(val) * 1000000;

        printf("%s=%d", key, v);
    }
}

int
main(int argc, char *argv[])
{
    int ret = NAGIOS_CRIT;
    char url[8192] = {};
    json_t *time = NULL;
    json_t *keys = NULL;
    json_t *adv = NULL;
    size_t sig = 0;
    size_t rec = 0;
    double s = 0;
    double e = 0;
    int r = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s URL\n", argv[0]);
        return ret;
    }

    time = json_object();
    if (!time)
        goto egress;

    snprintf(url, sizeof(url), "%s/adv", argv[1]);
    s = curtime();
    r = http(url, HTTP_GET, NULL, &adv);
    e = curtime();
    if (r != 200) {
        if (r < 0)
            printf("Error fetching advertisement! %s\n", strerror(-r));
        else
            printf("Error fetching advertisement! HTTP Status %d\n", r);

        goto egress;
    }

    if (s == 0.0 || e == 0.0 ||
        json_object_set_new(time, "adv", json_real(e - s)) != 0) {
        printf("Error calculating performance metrics!\n");
        goto egress;
    }

    keys = adv_vld(adv);
    if (!keys) {
        printf("Error validating advertisement!\n");
        goto egress;
    }

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = json_array_get(keys, i);
        const char *kid = NULL;
        json_t *state = NULL;
        json_t *bef = NULL;
        json_t *aft = NULL;
        json_t *req = NULL;
        json_t *rep = NULL;

        if (jose_jwk_allowed(jwk, true, NULL, "verify")) {
            sig++;
            continue;
        }

        if (!jose_jwk_allowed(jwk, true, NULL, "tang.derive") &&
            !jose_jwk_allowed(jwk, true, NULL, "wrapKey"))
            continue;

        bef = json_pack("{s:s,s:i}", "kty", "oct", "bytes", 16);
        if (!bef) {
            printf("Error creating JWK template!\n");
            goto egress;
        }

        state = adv_rep(jwk, bef);
        if (!state) {
            printf("Error creating binding!\n");
            goto egress;
        }

        req = rec_req(state);
        if (!req) {
            printf("Error preparing recovery request!\n");
            goto egress;
        }

        snprintf(url, sizeof(url), "%s/rec", argv[1]);
        s = curtime();
        r = http(url, HTTP_POST, req, &rep);
        e = curtime();
        if (r != 200) {
            if (r < 0)
                printf("Error performing recovery! %s\n", strerror(-r));
            else
                printf("Error performing recovery! HTTP Status %d\n", r);

            goto egress;
        }

        if (json_unpack(jwk, "{s:s}", "kid", &kid) != 0)
            goto egress;

        if (s == 0.0 || e == 0.0 ||
            json_object_set_new(time, kid, json_real(e - s)) < 0) {
            printf("Error calculating performance metrics!\n");
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

    if (rec == 0) {
        printf("Advertisement contains no recovery keys!\n");
        goto egress;
    }

    json_object_set_new(time, "nkeys", json_integer(json_array_size(keys)));
    json_object_set_new(time, "nsigk", json_integer(sig));
    json_object_set_new(time, "nreck", json_integer(rec));

    printf("OK|");
    dump_perf(time);
    printf("\n");
    ret = NAGIOS_OK;

egress:
    json_decref(time);
    json_decref(keys);
    json_decref(adv);
    return ret;
}
