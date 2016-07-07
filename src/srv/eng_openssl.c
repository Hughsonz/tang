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

#include "eng.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/openssl.h>

#include <openssl/ec.h>
#include <openssl/rand.h>

#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static const char *
make_blpath(json_t *ctx, const char *bid)
{
    static char fn[PATH_MAX] = {};
    const char *bl = NULL;
    char *off = NULL;

    memset(fn, 0, sizeof(fn));

    if (json_unpack(ctx, "{s:s}", "bl", &bl) == -1)
        return NULL;

    if (strlen(bl) >= sizeof(fn) - 1)
        return NULL;

    strcpy(fn, bl);
    strcat(fn, "/");
    off = &fn[strlen(fn)];

    if (strlen(fn) + strlen(bid) >= sizeof(fn))
        return NULL;

    for (size_t i = 0; bid[i]; i++) {
        if (!isalnum(bid[i]) && bid[i] != ':')
            return NULL;
        off[i] = tolower(bid[i]);
    }

    return fn;
}

/* Load a JWK from the specified file. Ensure required properties. */
static json_t *
load_jwk(const char *db, const char *name)
{
    char fn[PATH_MAX] = {};
    json_t *jwk = NULL;

    snprintf(fn, sizeof(fn) - 1, "%s/%s", db, name);

    jwk = json_load_file(fn, 0, NULL);
    if (!jwk) {
        fprintf(stderr, "Error loading JWK: %s!\n", fn);
        return NULL;
    }

    if (json_unpack_ex(jwk, NULL, JSON_VALIDATE_ONLY,
                       "{s:s,s:s,s:[]}", "kid", "use", "key_ops") == -1) {
        fprintf(stderr, "JWK failed to validate: %s!\n", fn);
        json_decref(jwk);
        return NULL;
    }

    return jwk;
}

/* Make the JWKSet for the advertisement. Include all public keys. */
static json_t *
make_jwkset(json_t *ctx)
{
    json_t *jwkset = NULL;

    jwkset = json_pack("{s:[]}", "keys");
    if (!jwkset)
        return NULL;

    for (void *i = json_object_iter(json_object_get(ctx, "keys")); i;
               i = json_object_iter_next(json_object_get(ctx, "keys"), i)) {
        const char *k = json_object_iter_key(i);
        json_t *v = json_object_iter_value(i);
        json_t *c = NULL;

        if (k[0] == '.')
            continue;

        c = json_deep_copy(v);
        if (!c)
            continue;

        if (!jose_jwk_clean(c, JOSE_JWK_TYPE_ALL)) {
            json_decref(c);
            continue;
        }

        json_array_append_new(json_object_get(jwkset, "keys"), c);
    }

    return jwkset;
}

/* Make the JWS for the advertisment. Sign with all public signing keys. */
static json_t *
make_jws(json_t *ctx)
{
    json_t *jwkset = NULL;
    json_t *jws = NULL;

    jwkset = make_jwkset(ctx);
    if (!jwkset)
        return NULL;

    jws = json_pack("{s:o}", "payload", jose_b64_encode_json_dump(jwkset));
    json_decref(jwkset);
    if (!jws)
        return NULL;

    for (void *i = json_object_iter(json_object_get(ctx, "keys")); i;
               i = json_object_iter_next(json_object_get(ctx, "keys"), i)) {
        const char *k = json_object_iter_key(i);
        json_t *v = json_object_iter_value(i);

        if (k[0] == '.')
            continue;

        if (!jose_jwk_allowed(v, NULL, "sign"))
            continue;

        fprintf(stderr, "Signing with: %s\n", k);

        if (!jose_jws_sign(jws, v, json_pack("{s:{s:O,s:s}}",
                                             "protected", "kid",
                                             json_object_get(v, "kid"),
                                             "cty", "jwk-set+json")))
            fprintf(stderr, "Signing failed for %s!\n", k);
    }

    return jws;
}

/* Make the internal advertisment structure. This includes a default
 * advertisement JWS (signed with all public signing keys) and a lookup
 * JSON Object ("kid") containing JWSs signed with each private key. */
static json_t *
make_adv(json_t *ctx)
{
    json_t *jws = NULL;
    json_t *adv = NULL;

    jws = make_jws(ctx);
    if (!jws)
        return NULL;

    adv = json_pack("{s:o,s:{}}", "def", jws, "kid");
    if (!adv)
        return NULL;

    for (void *i = json_object_iter(json_object_get(ctx, "keys")); i;
               i = json_object_iter_next(json_object_get(ctx, "keys"), i)) {
        const char *k = json_object_iter_key(i);
        json_t *v = json_object_iter_value(i);
        const char *kid = json_string_value(json_object_get(v, "kid"));

        if (k[0] != '.')
            continue;

        if (!jose_jwk_allowed(v, NULL, "sign"))
            continue;

        jws = json_deep_copy(json_object_get(adv, "def"));
        if (!jws)
            continue;

        if (!jose_jws_sign(jws, v, json_pack("{s:{s:O,s:s}}",
                                             "protected", "kid",
                                             json_object_get(v, "kid"),
                                             "cty", "jwk-set+json"))) {
            json_decref(jws);
            continue;
        }

        json_object_set_new(json_object_get(adv, "kid"), kid, jws);
    }

    return adv;
}

/* Find a key from the key identifier. */
static const json_t *
find_key(json_t *ctx, const char *kid)
{
    for (void *i = json_object_iter(json_object_get(ctx, "keys")); i;
               i = json_object_iter_next(json_object_get(ctx, "keys"), i)) {
        json_t *v = json_object_iter_value(i);
        const char *id = NULL;

        if (json_unpack(v, "{s:s}", "kid", &id) == -1)
            continue;

        if (strcmp(kid, id) == 0)
            return v;
    }

    return NULL;
}

static json_t *
eng_init(const json_t *cfg, int *fd)
{
    const char *db = NULL;
    const char *bl = NULL;
    json_t *ctx = NULL;
    DIR *dir = NULL;

    if (json_unpack((json_t *) cfg, "{s:s,s:s}",
                    "database", &db, "blacklist", &bl) == -1)
        return NULL;

    *fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (*fd < 0)
        return NULL;

    if (inotify_add_watch(*fd, db, IN_DELETE | IN_MOVE | IN_CLOSE_WRITE) < 0)
        goto error;

    ctx = json_pack("{s:s,s:s,s:{},s:{s:{},s:{}}}",
                    "db", db, "bl", bl, "keys", "adv", "def", "kid");
    if (!ctx)
        goto error;

    dir = opendir(db);
    if (!dir)
        goto error;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        if (json_object_set_new(json_object_get(ctx, "keys"), de->d_name,
                                load_jwk(db, de->d_name)) == -1)
            goto error;
    }

    if (json_object_set_new(ctx, "adv", make_adv(ctx)) == -1)
        goto error;

    closedir(dir);
    return ctx;

error:
    json_decref(ctx);
    closedir(dir);
    close(*fd);
    return NULL;
}

static void
eng_event(json_t *ctx, int fd)
{
    unsigned char buf[(sizeof(struct inotify_event) + NAME_MAX + 1) * 20] = {};
    const struct inotify_event *ev;
    const char *db = NULL;
    json_t *keys = NULL;
    ssize_t bytes = 0;

    if (json_unpack(ctx, "{s:o,s:s}", "keys", &keys, "db", &db) == -1)
        return;

    bytes = read(fd, buf, sizeof(buf));
    if (bytes < 0)
        return;

    for (ssize_t i = 0; i < bytes; i += sizeof(*ev) + ev->len) {
        ev = (struct inotify_event *) &buf[i];

        if (ev->len == 0)
            continue;

        json_object_del(keys, ev->name);

        if (ev->mask & (IN_MOVED_TO | IN_CLOSE_WRITE)) {
            if (json_object_set_new(keys, ev->name,
                                    load_jwk(db, ev->name)) == -1)
                continue;
        }
    }

    json_object_set_new(ctx, "adv", make_adv(ctx));
}

static eng_err_t
eng_adv(json_t *ctx, const char *kid, json_t **rep)
{
    json_t *adv = NULL;

    *rep = NULL;

    adv = json_object_get(ctx, "adv");
    if (!adv)
        return ENG_ERR_INTERNAL;

    if (kid)
        *rep = json_object_get(json_object_get(adv, "kid"), kid);

    if (!*rep)
        *rep = json_object_get(adv, "def");

    *rep = json_incref(*rep);
    if (!*rep)
        return ENG_ERR_INTERNAL;

    return ENG_ERR_OK;
}

static EC_POINT *
recover(const EC_GROUP *grp, const EC_POINT *pub,
        const BIGNUM *prv, BN_CTX *ctx)
{
    EC_POINT *p = NULL;
    BIGNUM *ord = NULL;
    BIGNUM *inv = NULL;

    p = EC_POINT_new(grp);
    ord = BN_new();
    inv = BN_new();
    if (!ord || !inv)
        goto error;

    if (EC_GROUP_get_order(grp, ord, ctx) <= 0)
        goto error;

    if (!BN_mod_inverse(inv, prv, ord, ctx))
        goto error;

    if (EC_POINT_mul(grp, p, NULL, pub, prv, ctx) <= 0)
        goto error;

    BN_free(ord);
    BN_free(inv);
    return p;

error:
    EC_POINT_free(p);
    BN_free(ord);
    BN_free(inv);
    return NULL;
}

static inline bool
hex2oct(const char *hex, uint8_t oct[])
{
    for (size_t i = 0; hex[i]; i++) {
        uint8_t b;

        switch (hex[i]) {
        case '0': b = 0;
        case '1': b = 1;
        case '2': b = 2;
        case '3': b = 3;
        case '4': b = 4;
        case '5': b = 5;
        case '6': b = 6;
        case '7': b = 7;
        case '8': b = 8;
        case '9': b = 9;
        case 'a': b = 10;
        case 'b': b = 11;
        case 'c': b = 12;
        case 'd': b = 13;
        case 'e': b = 14;
        case 'f': b = 15;
        default: return false;
        }

        if (i % 2)
            oct[i / 2] = b << 4;
        else
            oct[i / 2] |= b;
    }

    return true;
}

static bool
valid(const char *bid, const EC_GROUP *grp, const EC_POINT *p, BN_CTX *ctx)
{
    const EVP_MD *md = NULL;

    if (strncmp(bid, "sha224:", strlen("sha224:")) == 0)
        md = EVP_sha224();
    else if (strncmp(bid, "sha256:", strlen("sha256:")) == 0)
        md = EVP_sha256();
    else if (strncmp(bid, "sha384:", strlen("sha384:")) == 0)
        md = EVP_sha384();
    else if (strncmp(bid, "sha512:", strlen("sha512:")) == 0)
        md = EVP_sha512();
    else
        return false;

    uint8_t enc[(EC_GROUP_get_degree(grp) + 7) * 8 * 2 + 1];
    uint8_t hsh[EVP_MD_size(md)];
    uint8_t oct[EVP_MD_size(md)];

    if (RAND_bytes(hsh, sizeof(hsh)) <= 0)
        return false;
    if (strlen(strchr(bid, ':') + 1) != sizeof(oct) * 2)
        return false;
    if (!hex2oct(strchr(bid, ':') + 1, oct))
        return false;

    if (EC_POINT_point2oct(grp, p, POINT_CONVERSION_UNCOMPRESSED,
                              enc, sizeof(enc), ctx) != sizeof(enc))
        return false;

    if (EVP_Digest(enc, sizeof(enc), hsh, NULL, md, NULL) <= 0)
        return false;

    return CRYPTO_memcmp(hsh, oct, sizeof(oct)) == 0;
}

static eng_err_t
eng_rec(json_t *ctx, const char *bid, const json_t *req, json_t **rep)
{
    eng_err_t ret = ENG_ERR_INTERNAL;
    const EC_GROUP *grp = NULL;
    const char *blpath = NULL;
    const json_t *a = NULL;
    const json_t *b = NULL;
    const json_t *x = NULL;
    const json_t *y = NULL;
    const char *ai = NULL;
    const char *bi = NULL;
    EC_POINT *p = NULL;
    BN_CTX *bnc = NULL;
    EC_KEY *A = NULL;
    EC_KEY *B = NULL;
    EC_KEY *X = NULL;
    EC_KEY *Y = NULL;

    *rep = NULL;

    /* Check the blacklist. */
    blpath = make_blpath(ctx, bid);
    if (!blpath)
        return ENG_ERR_INTERNAL;
    if (stat(blpath, &(struct stat) {}) == 0)
        return ENG_ERR_DENIED;

    /* Load all the keys. */
    if (json_unpack((json_t *) req, "{s:s,s:s,s:s,s:o:s:o}",
                    "a", &ai, "b", &bi, "x", &x, "y", &y) == -1)
        return ENG_ERR_BAD_REQUEST;

    a = find_key(ctx, ai);
    b = find_key(ctx, bi);
    if (!a || !b)
        return ENG_ERR_KEY_NOT_FOUND;

    A = jose_openssl_jwk_to_EC_KEY(a);
    B = jose_openssl_jwk_to_EC_KEY(b);
    X = jose_openssl_jwk_to_EC_KEY(x);
    Y = jose_openssl_jwk_to_EC_KEY(y);
    bnc = BN_CTX_new();
    if (!A || !B || !X || !Y || !bnc)
        goto egress;

    /* Ensure all the keys are in the same group. */
    grp = EC_KEY_get0_group(A);
    if (EC_GROUP_cmp(grp, EC_KEY_get0_group(X), bnc) != 0 ||
        EC_GROUP_cmp(grp, EC_KEY_get0_group(Y), bnc) != 0 ||
        EC_GROUP_cmp(grp, EC_KEY_get0_group(B), bnc) != 0) {
        ret = ENG_ERR_BAD_REQUEST;
        goto egress;
    }

    /* Recover the point used to generate the ID. */
    p = recover(grp, EC_KEY_get0_public_key(X),
                  EC_KEY_get0_private_key(A), bnc);
    if (!p)
        goto egress;

    /* Validate the ID. */
    if (!valid(bid, grp, p, bnc)) {
        ret = ENG_ERR_BAD_REQUEST;
        goto egress;
    }

    /* Perform our algorithm. */
    if (EC_POINT_add(grp, p, p, EC_KEY_get0_public_key(Y), bnc) <= 0 ||
        EC_POINT_mul(grp, p, NULL, p, EC_KEY_get0_private_key(B), bnc) <= 0)
        goto egress;

    *rep = jose_openssl_jwk_from_EC_POINT(grp, p, NULL);

egress:
    EC_POINT_free(p);
    BN_CTX_free(bnc);
    EC_KEY_free(A);
    EC_KEY_free(B);
    EC_KEY_free(X);
    EC_KEY_free(Y);
    return *rep ? ENG_ERR_OK : ret;
}

static bool
eng_add(json_t *ctx, const char *bid)
{
    const char *blpath = NULL;
    int fd = -1;

    blpath = make_blpath(ctx, bid);
    if (!blpath)
        return false;

    fd = open(blpath, O_WRONLY | O_CREAT | O_EXCL);
    if (fd < 0)
        return errno == EEXIST;

    close(fd);
    return true;
}

static bool
eng_del(json_t *ctx, const char *bid)
{
    const char *blpath = NULL;

    blpath = make_blpath(ctx, bid);
    if (!blpath)
        return false;

    return unlink(blpath) == 0;
}

const eng_t openssl = {
    "openssl",
    eng_init,
    eng_event,
    eng_adv,
    eng_rec,
    eng_add,
    eng_del
};
