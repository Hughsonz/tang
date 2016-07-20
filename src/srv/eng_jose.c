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
#include <jose/jwe.h>
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
 *   "inotify": {
 *     "database": [ <path(string)>, <wd(integer)> ],
 *     "blacklist": [ <path(string)>, <wd(integer)> ],
 *   },
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
    "sha256",
    NULL
};

static bool
bid_valid(const char *bid)
{
    uint8_t id[4096];

    if (!bid)
        return false;

    if (jose_b64_dlen(strlen(bid)) > sizeof(id))
        return false;

    return jose_b64_decode_buf(bid, id);
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

    snprintf(fn, sizeof(fn) - 1, "%s/%s", db, name);

    jwkset = json_load_file(fn, 0, NULL);
    if (!jwkset) {
        fprintf(stderr, "Error loading JWK(Set): %s!\n", fn);
        return NULL;
    }

    arr = json_incref(json_object_get(jwkset, "keys"));
    if (!json_is_array(arr)) {
        json_decref(arr);
        arr = json_pack("[O]", jwkset);
    }

    json_decref(jwkset);

    json_array_foreach(arr, i, jwk) {
        const char *use = NULL;
        const char *msg = NULL;
        json_t *kid = NULL;

        kid = jose_jwk_thumbprint_json(jwk, hashes[0]);
        if (json_object_set_new(jwk, "kid", kid) < 0)
            msg = "Error making JWK thumbprint!";

        else if (json_unpack(jwk, "{s?s}", "use", &use) == -1)
            msg = "Error unpacking JWK!";

        else if (!use)
            msg = "Not loading JWK without use!";

        if (msg) {
            fprintf(stderr, "%s %s", msg, fn);
            json_decref(arr);
            return NULL;
        }
    }

    return arr;
}

static json_t *
make_jwkset(json_t *ctx)
{
    const char *key = NULL;
    json_t *jwkset = NULL;
    json_t *val = NULL;

    jwkset = json_pack("{s:[]}", "keys");
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

    jws = make_jws(ctx);
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

            sig = json_deep_copy(jws);
            if (!sig)
                continue;

            if (!jose_jws_sign(sig, jwk, json_pack("{s:{s:s}}", "protected",
                                                   "cty", "jwk-set+json"))) {
                json_decref(sig);
                continue;
            }

            for (size_t j = 0; hashes[j]; j++) {
                char thp[jose_jwk_thumbprint_len(hashes[j]) + 1];
                if (jose_jwk_thumbprint_buf(jwk, hashes[j], thp))
                    json_object_set(adv, thp, key[0] == '.' ? sig : jws);
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
                char thp[jose_jwk_thumbprint_len(hashes[j]) + 1];
                if (jose_jwk_thumbprint_buf(jwk, hashes[j], thp))
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
eng_add(json_t *ctx, const char *bid)
{
    const char *blp = NULL;
    int fd = -1;

    if (!bid_valid(bid))
        return ENG_ERR_BAD_ID;

    blp = make_blpath(ctx, bid);
    if (!blp)
        return ENG_ERR_INTERNAL;

    fd = open(blp, O_WRONLY | O_CREAT | O_EXCL);
    if (fd < 0 && errno != EEXIST)
        return ENG_ERR_INTERNAL;

    close(fd);
    return ENG_ERR_NONE;
}

static eng_err_t
eng_del(json_t *ctx, const char *bid)
{
    const char *blp = NULL;

    if (!bid_valid(bid))
        return ENG_ERR_BAD_ID;

    blp = make_blpath(ctx, bid);
    if (!blp)
        return ENG_ERR_INTERNAL;

    return unlink(blp) == 0 ? ENG_ERR_NONE : ENG_ERR_INTERNAL;
}

static eng_err_t
eng_adv(json_t *ctx, const char *kid, json_t **rep)
{
    int r = 0;

    r = json_unpack(ctx, "{s:{s:O}}", "adv", kid ? kid : "default", rep);
    return r == 0 ? ENG_ERR_NONE : kid ? ENG_ERR_BAD_ID : ENG_ERR_INTERNAL;
}

static eng_err_t
anonymous(json_t *ctx, const char *key, const json_t *jwk, json_t **rep)
{
    eng_err_t err = ENG_ERR_INTERNAL;
    const EC_GROUP *grp = NULL;
    json_t *prv = NULL;
    EC_KEY *lcl = NULL;
    EC_KEY *rem = NULL;
    BN_CTX *bnc = NULL;
    EC_POINT *r = NULL;

    if (json_unpack(ctx, "{s:{s:o}}", "rec", key, &prv) == -1)
        return ENG_ERR_BAD_REQ;

    if (!jose_jwk_allowed(prv, "tang", NULL))
        return ENG_ERR_BAD_REQ;

    bnc = BN_CTX_new();
    if (!bnc)
        return ENG_ERR_INTERNAL;

    lcl = jose_openssl_jwk_to_EC_KEY(prv);
    rem = jose_openssl_jwk_to_EC_KEY(jwk);
    grp = EC_KEY_get0_group(lcl);
    if (!lcl || !rem || EC_GROUP_cmp(grp, EC_KEY_get0_group(rem), bnc) != 0) {
        err = ENG_ERR_BAD_REQ;
        goto egress;
    }

    r = EC_POINT_new(grp);
    if (!r)
        goto egress;

    if (EC_POINT_mul(grp, r, NULL, EC_KEY_get0_public_key(rem),
                     EC_KEY_get0_private_key(lcl), bnc) <= 0)
        goto egress;

    *rep = jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(rem), r, NULL);
    if (!*rep)
        goto egress;

    err = ENG_ERR_NONE;

egress:
    EC_POINT_free(r);
    EC_KEY_free(lcl);
    EC_KEY_free(rem);
    BN_CTX_free(bnc);
    return err;
}

static json_t *
decrypt(json_t *ctx, const json_t *jwe, const json_t *rcp)
{
    const json_t *jwk = NULL;
    const char *kid = NULL;
    json_t *hdr = NULL;
    json_t *cek = NULL;
    json_t *pt = NULL;

    if (!rcp) {
        json_t *rcps = NULL;

        rcps = json_incref(json_object_get(jwe, "recipients"));
        if (json_is_array(rcps)) {
            size_t i = 0;

            json_array_foreach(rcps, i, rcp) {
                pt = decrypt(ctx, jwe, rcp);
                if (pt)
                    break;
            }
        } else if (!rcps) {
            pt = decrypt(ctx, jwe, rcp);
        }

        return pt;
    }

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (json_unpack(hdr, "{s:s}", "kid", &kid) == -1)
        goto egress;

    if (json_unpack(ctx, "{s:{s:o}}", "rec", kid, &jwk) == -1)
        goto egress;

    cek = jose_jwe_unwrap(jwe, rcp, jwk);
    if (!cek)
        goto egress;

    pt = jose_jwe_decrypt_json(jwe, cek);
    json_decref(cek);

egress:
    json_decref(hdr);
    return pt;
}

static eng_err_t
eng_rec(json_t *ctx, const json_t *req, json_t **rep)
{
    eng_err_t err = ENG_ERR_BAD_REQ;
    const json_t *jwe = NULL;
    const json_t *jwk = NULL;
    const char *key = NULL;
    const char *otp = NULL;
    const char *bid = NULL;
    json_t *rec = NULL;
    json_t *prv = NULL;
    uint8_t *ky = NULL;
    uint8_t *pd = NULL;
    size_t kyl = 0;
    size_t pdl = 0;
    *rep = NULL;

    /* If we receive an anonymous request, handle it. */
    if (json_unpack((json_t *) req, "{s:s,s:o!}",
                    "key", &key, "jwk", &jwk) == 0)
        return anonymous(ctx, key, jwk, rep);

    rec = decrypt(ctx, req, NULL);
    if (!rec)
        goto egress;

    if (json_unpack(rec, "{s:o,s:s}", "jwe", &jwe, "key", &key) == -1)
        goto egress;

    prv = decrypt(ctx, jwe, NULL);
    if (!prv)
        goto egress;

    if (json_unpack(prv, "{s:s,s:s}", "otp", &otp, "bid", &bid) == -1)
        goto egress;

    if (!bid_valid(bid))
        goto egress;

    if (json_unpack(ctx, "{s:{s:b}}", "blacklist", bid, &(int){0}) == 0) {
        err = ENG_ERR_DENIED;
        goto egress;
    }

    ky = jose_b64_decode(key, &kyl);
    pd = jose_b64_decode(otp, &pdl);
    if (!ky || !pd || kyl != pdl)
        goto egress;

    for (size_t i = 0; i < kyl; i++)
        ky[i] ^= pd[i];

    *rep = json_pack("{s:s,s:s}", "kty", "oct",
                     "k", jose_b64_encode_json(ky, kyl));
    err = *rep ? ENG_ERR_NONE : ENG_ERR_INTERNAL;

egress:
    json_decref(rec);
    json_decref(prv);
    if (ky)
        memset(ky, 0, kyl);
    free(ky);
    if (pd)
        memset(pd, 0, pdl);
    free(pd);
    return err;
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

/*
static void __attribute__((constructor))
constructor(void)
{
    jose_jwk_op_t tang = {
        .pub = "deriveKey",
        .prv = "recoverKey",
    };

    jose_jwk_register_op(&tang);
}
*/
