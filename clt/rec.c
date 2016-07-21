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

#include "rec.h"
#include <jose/b64.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

static json_t *
req_anon(json_t *state)
{
    EC_POINT *p = NULL;
    BN_CTX *ctx = NULL;
    EC_KEY *eph = NULL;
    EC_KEY *key = NULL;
    json_t *jwk = NULL;
    json_t *req = NULL;

    /* Unpack state values. */
    if (json_unpack(state, "{s:{s:o}}", "req", "jwk", &jwk) != 0)
        return NULL;

    key = jose_openssl_jwk_to_EC_KEY(jwk);
    if (!key)
        goto egress;

    /* Generate the ephemeral key. */
    eph = EC_KEY_new();
    if (!eph)
        goto egress;

    if (EC_KEY_set_group(eph, EC_KEY_get0_group(key)) <= 0)
        goto egress;

    if (EC_KEY_generate_key(eph) <= 0)
        goto egress;

    if (json_object_set_new(state, "eph",
                            jose_openssl_jwk_from_EC_KEY(eph)) != 0)
        goto egress;


    /* Perform point addition. */
    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    p = EC_POINT_new(EC_KEY_get0_group(key));
    if (!p)
        goto egress;

    if (EC_POINT_add(EC_KEY_get0_group(key), p,
                     EC_KEY_get0_public_key(eph),
                     EC_KEY_get0_public_key(key), ctx) <= 0)
        goto egress;

    /* Create output request. */
    req = json_deep_copy(json_object_get(state, "req"));
    if (!req)
        goto egress;

    if (json_object_set_new(req, "jwk",
                            jose_openssl_jwk_from_EC_POINT(
                                EC_KEY_get0_group(key),
                                p, NULL)) != 0) {
        json_decref(req);
        req = NULL;
    }

egress:
    EC_POINT_free(p);
    EC_KEY_free(eph);
    EC_KEY_free(key);
    BN_CTX_free(ctx);
    return req;
}

static json_t *
req_wrap(json_t *state)
{
    const json_t *jwk = NULL;
    const json_t *jwe = NULL;
    uint8_t *otp = NULL;
    uint8_t *xor = NULL;
    json_t *cek = NULL;
    json_t *pt = NULL;
    json_t *ct = NULL;
    size_t len = 0;

    otp = jose_b64_decode_json(json_object_get(state, "otp"), &len);
    if (!otp)
        return NULL;

    xor = malloc(len);
    if (!xor) {
        memset(otp, 0, len);
        free(otp);
        return NULL;
    }

    jwk = json_object_get(state, "jwk");
    jwe = json_object_get(state, "jwe");
    if (!jwk || !jwe)
        goto error;

    if (RAND_bytes(xor, len) <= 0)
        goto error;

    for (size_t i = 0; i < len; i++)
        otp[i] ^= xor[i];

    pt = json_pack("{s:O,s:o}", "jwe", jwe,
                   "otp", jose_b64_encode_json(xor, len));
    if (!pt)
        goto error;

    ct = json_pack("{s:{s:O}}", "protected",
                   "kid", json_object_get(jwk, "kid"));
    if (!ct)
        goto error;

    cek = json_object();
    if (!cek)
        goto error;

    if (!jose_jwe_wrap(ct, cek, jwk, NULL))
        goto error;

    if (!jose_jwe_encrypt_json(ct, cek, pt))
        goto error;

    if (json_object_set_new(state, "otp", jose_b64_encode_json(otp, len)) != 0)
        goto error;

    memset(otp, 0, len);
    memset(xor, 0, len);
    json_decref(cek);
    json_decref(pt);
    free(otp);
    free(xor);
    return ct;

error:
    memset(otp, 0, len);
    memset(xor, 0, len);
    json_decref(cek);
    json_decref(pt);
    json_decref(ct);
    free(otp);
    free(xor);
    return NULL;
}

static json_t *
kdf(json_t *state, const EC_GROUP *grp, const EC_POINT *p, BN_CTX *ctx)
{
    static const struct {
        const char *name;
        const EVP_MD *(*md)(void);
    } table[] = {
        { "sha256", EVP_sha256 },
        {}
    };

    const EVP_MD *md = NULL;
    const char *salt = NULL;
    const char *hash = NULL;
    json_t *out = NULL;
    uint8_t *ky = NULL;
    uint8_t *st = NULL;
    char *pass = NULL;
    size_t len = 0;
    int iter = 1;

    if (json_unpack(state, "{s:s,s:s,s:i}",
                    "hash", &hash, "salt", &salt, "iter", &iter) != 0)
        return NULL;

    for (size_t i = 0; table[i].name && !md; i++) {
        if (strcmp(table[i].name, hash) == 0)
            md = table[i].md();
    }

    if (!md)
        return NULL;

    st = jose_b64_decode(salt, &len);
    if (!st)
        return NULL;

    ky = malloc(len);
    if (!ky)
        goto egress;

    pass = EC_POINT_point2hex(grp, p, POINT_CONVERSION_COMPRESSED, ctx);
    if (!pass)
        goto egress;

    if (PKCS5_PBKDF2_HMAC(pass, strlen(pass), st, len, iter, md, len, ky) <= 0)
        goto egress;

    out = json_pack("{s:s,s:o}", "kty", "oct",
                    "k", jose_b64_encode_json(ky, len));

egress:
    memset(st, 0, len);

    if (ky)
        memset(ky, 0, len);

    if (pass)
        memset(pass, 0, strlen(pass));

    OPENSSL_free(pass);
    free(st);
    free(ky);
    return out;
}

static json_t *
rep_anon(json_t *state, const json_t *rep)
{
    const json_t *tmp = NULL;
    const json_t *jwk = NULL;
    EC_POINT *p = NULL;
    EC_KEY *eph = NULL;
    EC_KEY *key = NULL;
    EC_KEY *rpl = NULL;
    BN_CTX *ctx = NULL;
    json_t *out = NULL;

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    /* Load all the keys required for recovery. */
    if (json_unpack(state, "{s:o,s:o}", "eph", &tmp, "jwk", &jwk) != 0)
        goto egress;

    eph = jose_openssl_jwk_to_EC_KEY(tmp);
    key = jose_openssl_jwk_to_EC_KEY(jwk);
    rpl = jose_openssl_jwk_to_EC_KEY(rep);
    if (!eph || !key || !rpl)
        goto egress;

    if (EC_GROUP_cmp(EC_KEY_get0_group(rpl), EC_KEY_get0_group(eph), ctx) != 0)
        goto egress;

    /* Perform recovery. */
    p = EC_POINT_new(EC_KEY_get0_group(eph));
    if (!p)
        goto egress;

    if (EC_POINT_mul(EC_KEY_get0_group(key), p, NULL,
                     EC_KEY_get0_public_key(key),
                     EC_KEY_get0_private_key(eph), ctx) <= 0)
        goto egress;

    if (EC_POINT_invert(EC_KEY_get0_group(key), p, ctx) <= 0)
        goto egress;

    if (EC_POINT_add(EC_KEY_get0_group(key), p, p,
                     EC_KEY_get0_public_key(rpl), ctx) <= 0)
        goto egress;

    /* Create output key. */
    out = kdf(state, EC_KEY_get0_group(key), p, ctx);

egress:
    EC_POINT_free(p);
    EC_KEY_free(eph);
    EC_KEY_free(key);
    EC_KEY_free(rpl);
    BN_CTX_free(ctx);
    return out;
}

static json_t *
rep_wrap(json_t *state, const json_t *rep)
{
    uint8_t *otp = NULL;
    uint8_t *key = NULL;
    json_t *out = NULL;
    size_t otpl = 0;
    size_t keyl = 0;

    otp = jose_b64_decode_json(json_object_get(state, "otp"), &otpl);
    if (!otp)
        return NULL;

    key = jose_b64_decode_json(json_object_get(rep, "k"), &keyl);
    if (!key) {
        memset(otp, 0, otpl);
        free(otp);
        return NULL;
    }

    if (otpl != keyl)
        goto egress;

    for (size_t i = 0; i < otpl; i++)
        key[i] ^= otp[i];

    out = json_pack("{s:s,s:o}", "kty", "oct",
                    "k", jose_b64_encode_json(key, keyl));

egress:
    memset(otp, 0, otpl);
    memset(key, 0, keyl);
    free(otp);
    free(key);
    return out;
}

json_t *
rec_req(json_t *state)
{
    json_t *out = NULL;

    out = req_wrap(state);
    return out ? out : req_anon(state);
}

json_t *
rec_rep(json_t *state, const json_t *rep)
{
    json_t *jwk = NULL;

    jwk = rep_wrap(state, rep);
    return jwk ? jwk : rep_anon(state, rep);
}
