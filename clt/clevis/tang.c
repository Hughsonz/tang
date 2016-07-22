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

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <string.h>

static uint8_t *
readkey(FILE *file, size_t *len)
{
    uint8_t *out = NULL;

    *len = 0;

    while (true) {
        uint8_t *tmp = NULL;
        size_t r = 0;

        tmp = realloc(out, *len + 16);
        if (!tmp)
            break;
        out = tmp;

        r = fread(&out[*len], 1, 16, file);
        *len += r;
        if (r < 16) {
            if (ferror(file) || *len == 0)
                break;
            if (feof(file))
                return out;
        }
    }

    if (out)
        memset(out, 0, *len);

    free(out);
    return NULL;
}

static json_t *
load_adv(const char *filename)
{
    json_t *keys = NULL;
    json_t *adv = NULL;
    FILE *file = NULL;

    file = fopen(filename, "r");
    if (!file)
        return NULL;

    adv = json_loadf(file, 0, NULL);
    fclose(file);

    keys = adv_vld(adv);
    json_decref(keys);
    if (!keys) {
        json_decref(adv);
        return NULL;
    }

    return adv;
}

static json_t *
dnld_adv(const char *url)
{
    char full[8192] = {};
    json_t *keys = NULL;
    json_t *adv = NULL;
    json_t *jwk = NULL;
    FILE *tty = NULL;
    char yn = 'x';
    size_t i = 0;
    int r = 0;

    snprintf(full, sizeof(full), "%s/adv", url);

    r = http(full, HTTP_GET, NULL, &adv);
    if (r != 200)
        return NULL;

    keys = adv_vld(adv);
    if (!keys)
        goto egress;

    tty = fopen("/dev/tty", "a+");
    if (!tty)
        goto egress;

    fprintf(tty, "The advertisement is signed with the following keys:\n");

    json_array_foreach(keys, i, jwk) {
        if (!jose_jwk_allowed(jwk, true, NULL, "tang.derive") &&
            !jose_jwk_allowed(jwk, true, NULL, "wrapKey"))
            continue;

        fprintf(tty, "\t%s\n", json_string_value(json_object_get(jwk, "kid")));
    }

    while (!strchr("YyNn", yn)) {
        fprintf(tty, "\nDo you wish to trust the advertisement? [yN] ");
        if (fread(&yn, 1, 1, tty) != 1)
            break;
    }

egress:
    json_decref(keys);

    if(tty)
        fclose(tty);

    if (strchr("Yy", yn))
        return adv;

    json_decref(adv);
    return NULL;
}

static json_t *
select_jwk(json_t *jws)
{
    json_t *jwkset = NULL;
    json_t *jwk = NULL;
    size_t i = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    json_array_foreach(json_object_get(jwkset, "keys"), i, jwk) {
        if (jose_jwk_allowed(jwk, true, NULL, "tang.derive") ||
            jose_jwk_allowed(jwk, true, NULL, "wrapKey")) {
            jwk = json_incref(jwk);
            json_decref(jwkset);
            return jwk;
        }
    }

    json_decref(jwkset);
    return NULL;
}

static int
encrypt(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *url = NULL;
    json_t *jws = NULL;
    json_t *cfg = NULL;
    json_t *jwk = NULL;
    json_t *jwe = NULL;
    json_t *cek = NULL;
    json_t *ste = NULL;
    uint8_t *ky = NULL;
    size_t kyl = 0;

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing configuration!\n");
        return EXIT_FAILURE;
    }

    ky = readkey(stdin, &kyl);
    if (!ky) {
        fprintf(stderr, "Error reading key!\n");
        json_decref(cfg);
        return EXIT_FAILURE;
    }

    if (json_unpack(cfg, "{s:s,s?o}", "url", &url, "adv", &jws) != 0) {
        fprintf(stderr, "Invalid configuration!\n");
        goto egress;
    }

    if (json_is_string(jws))
        jws = load_adv(json_string_value(jws));
    else if (!json_is_object(jws))
        jws = dnld_adv(url);
    else {
        json_t *keys = adv_vld(jws);
        if (!keys) {
            fprintf(stderr, "Specified advertisement is invalid!\n");
            goto egress;
        }

        json_decref(keys);
    }

    jwk = select_jwk(jws);
    if (!jwk) {
        fprintf(stderr, "Error selecting remote public key!\n");
        goto egress;
    }

    cek = json_pack("{s:s,s:i}", "kty", "oct", "bytes", 32);
    if (!cek)
        goto egress;

    ste = adv_rep(jwk, cek);
    if (!ste) {
        fprintf(stderr, "Error creating binding!\n");
        goto egress;
    }

    jwe = json_pack("{s:{s:s},s:{s:{s:s,s:O,s:O}}}",
                    "protected",
                        "alg", "dir",
                    "unprotected",
                        "tang",
                            "url", url,
                            "ste", ste,
                            "adv", jws);
    if (!jwe) {
        fprintf(stderr, "Error creating JWE template!\n");
        goto egress;
    }

    if (!jose_jwe_encrypt(jwe, cek, ky, kyl)) {
        fprintf(stderr, "Error encrypting key!\n");
        goto egress;
    }

    if (json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT) != 0)
        goto egress;

    ret = EXIT_SUCCESS;

egress:
    memset(ky, 0, kyl);
    json_decref(jws);
    json_decref(cfg);
    json_decref(jwk);
    json_decref(jwe);
    json_decref(cek);
    json_decref(ste);
    free(ky);
    return ret;
}

static int
decrypt(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *url = NULL;
    char full[8192] = {};
    json_t *ste = NULL;
    json_t *jwe = NULL;
    json_t *req = NULL;
    json_t *rep = NULL;
    json_t *cek = NULL;
    uint8_t *ky = NULL;
    size_t kyl = 0;
    int r = 0;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        goto egress;

    if (json_unpack(jwe, "{s:{s:{s:s,s:o}}}",
                    "unprotected", "tang", "url", &url, "ste", &ste) != 0)
        goto egress;

    req = rec_req(ste);
    if (!req)
        goto egress;

    snprintf(full, sizeof(full), "%s/rec", url);
    r = http(full, HTTP_POST, req, &rep);
    if (r != 200)
        goto egress;

    cek = rec_rep(ste, rep);
    if (!cek)
        goto egress;

    ky = jose_jwe_decrypt(jwe, cek, &kyl);
    if (!ky)
        goto egress;

    if (fwrite(ky, kyl, 1, stdout) != 1)
        goto egress;

    ret = EXIT_SUCCESS;

egress:
    if (ky)
        memset(ky, 0, kyl);
    json_decref(req);
    json_decref(rep);
    json_decref(cek);
    json_decref(jwe);
    free(ky);
    return ret;
}

int
main(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[1], "encrypt") == 0)
        return encrypt(argc, argv);

    if (argc == 2 && strcmp(argv[1], "decrypt") == 0)
        return decrypt(argc, argv);

    fprintf(stderr, "Usage: %s encrypt CONFIG\n", argv[0]);
    fprintf(stderr, "   or: %s decrypt\n", argv[0]);
    return EXIT_FAILURE;
}
