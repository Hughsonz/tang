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

/**
 * The ctx structure looks like this: {
 *   "inotify": { <attr>: [ <path(string)>, <wd(integer)> ], ... },
 *
 *   "database": { <path>: [ <jwk(object)>, ... ] },
 *   "blacklist": { <hash:thumbprint>: true, ... },
 *
 *   "adv": {
 *     "default": <adv(string)>,
 *     <hash:thumbprint>: <adv(string)>,
 *     ...
 *   },
 *   "rec": {
 *     <hash:thumbprint>: <jwk(object)>,
 *     ...
 *   }
 * }
 *
 * We setup two inotify watches (key database directory and blacklist
 * directory) into the "inotify" section of the tree. The on-disk state is
 * synchronized into the "database" and "blacklist" structures of the tree.
 * This allows us to avoid disk IO at request time.
 *
 * After any changes to the "database" section, the "adv" and "rec" sections
 * are destroyed and recreated.
 *
 * The "adv" section contains all of the possible signing options. The
 * signatures are pre-computed and pre-marshalled. This means that when an
 * advtertisement request is received, the only thing we need to do is hand
 * off the appropriate pre-marshalled buffer.
 *
 * Similarly, the "rec" section contains a pre-computed table for looking up
 * JWKs using their thumbprints. These are then used for the cryptographic
 * operation.
 */

#define IN_FLAGS (IN_DELETE | IN_MOVE | IN_CLOSE_WRITE | IN_CREATE)

static const char *hashes[] = {
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    NULL
};

static bool
ktp_valid_syntax(const char *ktp)
{
    for (size_t i = 0; hashes[i]; i++) {
        size_t tlen = jose_jwk_thumbprint_len(hashes[i]);
        size_t hlen = strlen(hashes[i]);

        if (strncmp(hashes[i], ktp, hlen) != 0)
            continue;

        if (ktp[hlen++] != ':')
            continue;

        if (strlen(ktp) != hlen + tlen)
            continue;

        uint8_t thp[tlen];

        if (jose_b64_decode_buf(&ktp[hlen], thp))
            return true;
    }

    return false;
}

static const char *
make_blpath(json_t *ctx, const char *ktp)
{
    static char fn[PATH_MAX] = {};
    const char *dir = NULL;
    int wd = -1;

    memset(fn, 0, sizeof(fn));

    if (json_unpack(ctx, "{s:{s:[si!]}}",
                    "inotify", "blacklist", &dir, &wd) == -1)
        return NULL;

    if (strlen(dir) + strlen(ktp) + 2 > sizeof(fn))
        return NULL;

    strcpy(fn, dir);
    strcat(fn, "/");
    strcat(fn, ktp);
    return fn;
}

/* Load a JWK from the specified file. Ensure required properties. */
static json_t *
load_jwks(const char *db, const char *name)
{
    char fn[PATH_MAX] = {};
    json_t *jwkset = NULL;
    json_t *jwk = NULL;
    json_t *arr = NULL;
    size_t i = 0;

#warning TODO
    snprintf(fn, sizeof(fn) - 1, "%s/%s", db, name);

    jwkset = json_load_file(fn, 0, NULL);
    if (!jwkset) {
        fprintf(stderr, "Error loading JWK(Set): %s!\n", fn);
        return NULL;
    }

    arr = json_incref(json_object_get(jwkset, "keys"));
    if (!json_is_array(arr))
        arr = json_pack("[o]", "keys", jwkset);

    json_array_foreach(arr, i, jwk) {
        if (json_unpack(jwk, "{s?s,s?s}", "kty", &kty, "use", &use) == -1)
            goto error;

        if (!kty || strcmp(kty, "EC") != 0)
            goto error;

        if (!use || 

    }

    if (json_unpack_ex(jwk, NULL, JSON_VALIDATE_ONLY,
                       "{s:s,s:s,s:[]}", "kid", "use", "key_ops") == -1) {
        fprintf(stderr, "JWK failed to validate: %s!\n", fn);
        json_decref(jwk);
        return NULL;
    }

    return jwk;
}

static json_t *
make_jwkset(json_t *ctx)
{
    const char *key = NULL;
    json_t *jwkset = NULL;
    json_t *val = NULL;

    jwkset = json_pack("{s:[],s:[]}", "keys", "hashes");
    if (!jwkset)
        return NULL;

    json_object_foreach(json_object_get(ctx, "database"), key, val) {
        json_t *jwk = NULL;
        size_t i = 0;

        if (key[0] == '.')
            continue;

        json_array_foreach(val, i, jwk) {
            json_t *cpy = NULL;

            cpy = json_deep_copy(jwk);
            if (!cpy)
                continue;

            if (!jose_jwk_clean(cpy)) {
                json_decref(cpy);
                continue;
            }

            json_array_append_new(json_object_get(jwkset, "keys"), cpy);
        }
    }

    for (size_t i = 0; hashes[i]; i++) {
        json_array_append_new(json_object_get(jwkset, "hashes"),
                              json_string(hashes[i]));
    }

    return jwkset;
}

static json_t *
make_jws(json_t *ctx)
{
    const char *key = NULL;
    json_t *jwkset = NULL;
    json_t *jws = NULL;
    json_t *val = NULL;

    jwkset = make_jwkset(ctx);
    if (!jwkset)
        return NULL;

    jws = json_pack("{s:o}", "payload", jose_b64_encode_json_dump(jwkset));
    json_decref(jwkset);
    if (!jws)
        return NULL;

    json_object_foreach(json_object_get(ctx, "database"), key, val) {
        json_t *jwk = NULL;
        size_t i = 0;

        if (key[0] == '.')
            continue;

        json_array_foreach(val, i, jwk) {
            if (!jose_jwk_allowed(jwk, NULL, "sign"))
                continue;

            if (!jose_jws_sign(jws, jwk, json_pack("{s:{s:s}}", "protected",
                                                   "cty", "jwk-set+json")))
                fprintf(stderr, "Signing failed for %s!\n", key);
        }
    }

    return jws;
}

static json_t *
make_adv(json_t *ctx)
{
    const char *key = NULL;
    json_t *val = NULL;
    json_t *jws = NULL;
    json_t *adv = NULL;
    char *pub = NULL;

    jws = make_jws(ctx);
    if (!jws)
        return NULL;

    pub = json_dumps(jws, JSON_SORT_KEYS | JSON_COMPACT);
    json_decref(jws);
    if (!pub)
        return NULL;

    jws = json_string(pub);
    free(pub);
    if (!jws)
        return NULL;

    adv = json_pack("{s:o}", "default", jws);
    if (!adv)
        return NULL;

    json_object_foreach(json_object_get(ctx, "database"), key, val) {
        json_t *jwk = NULL;
        size_t i = 0;

        json_array_foreach(val, i, jwk) {
            json_t *sig = NULL;
            char *prv = NULL;

            sig = json_deep_copy(jws);
            if (!sig)
                continue;

            if (!jose_jws_sign(sig, jwk, json_pack("{s:{s:s}}", "protected",
                                                   "cty", "jwk-set+json"))) {
                json_decref(sig);
                continue;
            }

            prv = json_dumps(sig, JSON_SORT_KEYS | JSON_COMPACT);
            json_decref(sig);
            if (!prv)
                continue;

            sig = json_string(prv);
            free(prv);
            if (!sig)
                continue;

            for (size_t j = 0; hashes[j]; j++) {
                size_t len = 0;

                len = jose_jwk_thumbprint_len(hashes[i]);
                if (len == 0)
                    continue;

                char tp[strlen(hashes[i]) + len + 2];

                strcpy(tp, hashes[i]);
                strcat(tp, ":");
                if (jose_jwk_thumbprint_buf(jwk, hashes[i], &tp[strlen(tp)]))
                    json_object_set(adv, tp, key[0] == '.' ? sig : jws);
            }

            json_decref(sig);
        }
    }

    return adv;
}

static json_t *
make_rec(const json_t *ctx)
{
    const char *key = NULL;
    json_t *rec = NULL;
    json_t *val = NULL;
    json_t *jwk = NULL;
    size_t i = 0;

    rec = json_object();
    if (!rec)
        return NULL;

    json_object_foreach(json_object_get(ctx, "database"), key, val) {
        json_array_foreach(val, i, jwk) {
            for (size_t j = 0; hashes[j]; j++) {
                size_t len = 0;

                len = jose_jwk_thumbprint_len(hashes[i]);
                if (len == 0)
                    continue;

                char thp[strlen(hashes[i]) + len + 2];

                strcpy(thp, hashes[i]);
                strcat(thp, ":");
                if (jose_jwk_thumbprint_buf(jwk, hashes[i], &thp[strlen(thp)]))
                    json_object_set(rec, thp, jwk);
            }
        }
    }

    return rec;
}

static json_t *
eng_init(const json_t *cfg, int *fd)
{
    const char *db = NULL;
    const char *bl = NULL;
    json_t *ctx = NULL;
    DIR *dir = NULL;
    int dbwd = 0;
    int blwd = 0;

    if (json_unpack((json_t *) cfg, "{s:s,s:s}",
                    "database", &db, "blacklist", &bl) == -1)
        return NULL;

    *fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (*fd < 0)
        return NULL;


    dbwd = inotify_add_watch(*fd, db, IN_FLAGS);
    if (dbwd < 0)
        goto error;

    blwd = inotify_add_watch(*fd, bl, IN_FLAGS);
    if (blwd < 0)
        goto error;

    ctx = json_pack("{s:{s:[s,i],s:[s,i]},s:{},s:{}}", "inotify",
                    "database", db, dbwd,
                    "blacklist", bl, blwd,
                    "database", "blacklist");
    if (!ctx)
        goto error;

    dir = opendir(db);
    if (!dir)
        goto error;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        if (json_object_set_new(json_object_get(ctx, "database"), de->d_name,
                                load_jwks(db, de->d_name)) == -1)
            goto error;
    }

    closedir(dir);
    dir = opendir(bl);
    if (!dir)
        goto error;

    for (struct dirent *de = readdir(dir); de; de = readdir(dir)) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        if (json_object_set_new(json_object_get(ctx, "blacklist"),
                                de->d_name, json_true()) == -1)
            goto error;
    }

    if (json_object_set_new(ctx, "adv", make_adv(ctx)) == -1)
        goto error;

    if (json_object_set_new(ctx, "rec", make_rec(ctx)) == -1)
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
    ssize_t bytes = 0;

    bytes = read(fd, buf, sizeof(buf));
    if (bytes < 0)
        return;

    for (ssize_t i = 0; i < bytes; i += sizeof(*ev) + ev->len) {
        const char *key = NULL;
        json_t *val = NULL;

        ev = (struct inotify_event *) &buf[i];

        if (ev->len == 0)
            continue;

        json_object_foreach(json_object_get(ctx, "inotify"), key, val) {
            const char *dir = NULL;
            json_t *obj = NULL;
            int wd = -1;

            if (json_unpack(val, "[s,i!]", &dir, &wd) == -1)
                continue;

            if (ev->wd != wd)
                continue;

            obj = json_object_get(ctx, key);
            json_object_del(obj, ev->name);

            if ((ev->mask & (IN_MOVED_TO | IN_CLOSE_WRITE | IN_CREATE)) == 0)
                continue;

            if (strcmp(key, "database") == 0)
                json_object_set_new(obj, ev->name, load_jwks(dir, ev->name));
            else if (strcmp(key, "blacklist") == 0)
                json_object_set_new(obj, ev->name, json_true());
        }
    }

    json_object_set_new(ctx, "adv", make_adv(ctx));
    json_object_set_new(ctx, "rec", make_rec(ctx));
}

static eng_err_t
eng_add(json_t *ctx, const char *ktp)
{
    const char *blp = NULL;
    int fd = -1;

    if (!ktp_valid_syntax(ktp))
        return ENG_ERR_BAD_ID;

    blp = make_blpath(ctx, ktp);
    if (!blp)
        return ENG_ERR_INTERNAL;

    fd = open(blp, O_WRONLY | O_CREAT | O_EXCL);
    if (fd < 0 && errno != EEXIST)
        return ENG_ERR_INTERNAL;

    close(fd);
    return ENG_ERR_NONE;
}

static eng_err_t
eng_del(json_t *ctx, const char *ktp)
{
    const char *blp = NULL;

    if (!ktp_valid_syntax(ktp))
        return ENG_ERR_BAD_ID;

    blp = make_blpath(ctx, ktp);
    if (!blp)
        return ENG_ERR_INTERNAL;

    return unlink(blp) == 0 ? ENG_ERR_NONE : ENG_ERR_INTERNAL;
}

static eng_err_t
eng_adv(json_t *ctx, const char *ktp, const char **o)
{
    int r = 0;

    if (!ktp_valid_syntax(ktp))
        return ENG_ERR_BAD_ID;

    r = json_unpack(ctx, "{s:{s:s}}", "adv", ktp ? ktp : "default", o);
    return r == 0 ? ENG_ERR_NONE : ktp ? ENG_ERR_BAD_ID : ENG_ERR_INTERNAL;
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
bid_valid(const char *bid, const EC_GROUP *grp, const EC_POINT *p, BN_CTX *ctx)
{
    const EVP_MD *md = NULL;

    md = get_md(bid);
    if (!md)
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
eng_rec(json_t *ctx, const char *ktp, const json_t *req, json_t **rep)
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
    if (!ktp_valid_syntax(ktp))
        return ENG_ERR_BAD_ID;
    blpath = make_blpath(ctx, bid);
    if (!blpath)
        return ENG_ERR_INTERNAL;
    if (stat(blpath, &(struct stat) {}) == 0)
        return ENG_ERR_DENIED;

    /* Load all the keys. */
    if (json_unpack((json_t *) req, "{s:s,s:s,s:s,s:o:s:o}",
                    "a", &ai, "b", &bi, "x", &x, "y", &y) == -1)
        return ENG_ERR_BAD_REQ;

    a = find_key(ctx, ai);
    b = find_key(ctx, bi);
    if (!a || !b)
        return ENG_ERR_BAD_REQ;

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
        ret = ENG_ERR_BAD_REQ;
        goto egress;
    }

    /* Recover the point used to generate the ID. */
    p = recover(grp, EC_KEY_get0_public_key(X),
                  EC_KEY_get0_private_key(A), bnc);
    if (!p)
        goto egress;

    /* Validate the ID. */
    if (!bid_valid(bid, grp, p, bnc)) {
        ret = ENG_ERR_BAD_REQ;
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
    return *rep ? ENG_ERR_NONE : ret;
}

const eng_t jose = {
    "jose",
    eng_init,
    eng_event,
    eng_add,
    eng_del,
    eng_adv,
    eng_rec,
};
