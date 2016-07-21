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

#include "adv.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

static bool
anon(const json_t *key, size_t bytes, json_t **state, json_t **jwk)
{
    const int iter = 1000;
    EC_POINT *k = NULL;
    BN_CTX *ctx = NULL;
    EC_KEY *lcl = NULL;
    EC_KEY *rem = NULL;
    char *pass = NULL;
    uint8_t ky[bytes];
    uint8_t st[bytes];

    *jwk = NULL;
    *state = NULL;

    rem = jose_openssl_jwk_to_EC_KEY(key);
    if (!rem)
        goto egress;

    lcl = EC_KEY_new();
    if (!lcl)
        goto egress;

    if (EC_KEY_set_group(lcl, EC_KEY_get0_group(rem)) <= 0)
        goto egress;

    if (EC_KEY_generate_key(lcl) <= 0)
        goto egress;

    k = EC_POINT_new(EC_KEY_get0_group(rem));
    if (!k)
        goto egress;

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    if (EC_POINT_mul(EC_KEY_get0_group(rem), k, NULL,
                     EC_KEY_get0_public_key(rem),
                     EC_KEY_get0_private_key(lcl), ctx) <= 0)
        goto egress;

    if (RAND_bytes(st, sizeof(st)) <= 0)
        goto egress;

    pass = EC_POINT_point2hex(EC_KEY_get0_group(lcl), k,
                              POINT_CONVERSION_COMPRESSED, ctx);
    if (!pass)
        goto egress;

    if (PKCS5_PBKDF2_HMAC(pass, strlen(pass), st, bytes, iter,
                          EVP_sha256(), bytes, ky) <= 0)
        goto egress;

    *jwk = json_pack("{s:s,s:o}", "kty", "oct",
                     "k", jose_b64_encode_json(ky, bytes));
    if (!*jwk)
        return false;

    *state = json_pack("{s:i,s:s,s:O,s:o,s:{s:O,s:o}}",
                       "iter", iter, "hash", "sha256", "jwk", key,
                       "salt", jose_b64_encode_json(st, bytes),
                       "req",
                           "kid", json_object_get(key, "kid"),
                           "jwk", jose_openssl_jwk_from_EC_POINT(
                                                   EC_KEY_get0_group(lcl),
                                                   EC_KEY_get0_public_key(lcl),
                                                   NULL));

egress:
    memset(ky, 0, sizeof(ky));
    memset(st, 0, sizeof(st));

    if (!*state) {
        json_decref(*jwk);
        *jwk = NULL;
    }

    OPENSSL_free(pass);
    EC_POINT_free(k);
    BN_CTX_free(ctx);
    EC_KEY_free(lcl);
    EC_KEY_free(rem);
    return *state != NULL;
}

static bool
wrap(const json_t *key, size_t bytes, json_t **state, json_t **jwk)
{
    uint8_t ky[bytes * 3];
    json_t *jwe = NULL;
    json_t *cek = NULL;
    json_t *pt = NULL;

    *state = NULL;

    if (RAND_bytes(ky, sizeof(ky)) <= 0)
        return false;

    *jwk = json_pack("{s:s,s:o}", "kty", "oct",
                     "k", jose_b64_encode_json(ky, bytes));
    if (!*jwk)
        return false;

    for (size_t i = 0; i < bytes; i++)
        ky[i] ^= ky[bytes + i];

    pt = json_pack("{s:o,s:o}", "key", jose_b64_encode_json(ky, bytes),
                   "bid", jose_b64_encode_json(&ky[bytes * 2], bytes));
    if (!pt)
        goto egress;

    jwe = json_pack("{s:{s:O}}", "protected",
                    "kid", json_object_get(key, "kid"));
    cek = json_object();
    if (!jwe || !cek)
        goto egress;

    if (!jose_jwe_wrap(jwe, cek, key, NULL))
        goto egress;

    if (!jose_jwe_encrypt_json(jwe, cek, pt))
        goto egress;

    *state = json_pack("{s:O,s:O,s:O,s:o}", "jwe", jwe, "jwk", key,
                       "bid", json_object_get(pt, "bid"),
                       "otp", jose_b64_encode_json(&ky[bytes], bytes));

egress:
    memset(ky, 0, sizeof(ky));

    if (!*state) {
        json_decref(*jwk);
        *jwk = NULL;
    }

    json_decref(jwe);
    json_decref(cek);
    json_decref(pt);
    return *state != NULL;
}

json_t *
adv_vld(const json_t *jws, const json_t *sig)
{
    json_t *jwkset = NULL;
    json_t *keys = NULL;
    size_t sigs = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    keys = json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        goto error;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *key = json_array_get(keys, i);

        if (!jose_jwk_allowed(key, true, NULL, "verify"))
            continue;

        if (!jose_jws_verify(jws, key))
            goto error;

        sigs++;
    }

    if (sigs == 0)
        goto error;

    if (sig && !jose_jws_verify(jws, sig))
        goto error;

    keys = json_incref(keys);
    json_decref(jwkset);
    return keys;

error:
    json_decref(jwkset);
    return NULL;
}

bool
adv_rep(const json_t *jwk, size_t bytes, json_t **state, json_t **key)
{
    if (jose_jwk_allowed(jwk, true, NULL, "tang.derive"))
        return anon(jwk, bytes, state, key);

    if (jose_jwk_allowed(jwk, true, NULL, "wrapKey"))
        return wrap(jwk, bytes, state, key);

    return false;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_op_t tang = {
        .pub = "tang.derive",
        .prv = "tang.recover",
        .use = "tang"
    };

    jose_jwk_register_op(&tang);
}
