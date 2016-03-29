/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
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

#include "srv.h"

#include "../core/conv.h"
#include "../clt/adv.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define test(cond, cmd) \
    if (!(cond)) { \
        fprintf(stderr, "Error: %s:%d: %s\n", \
                __FILE__, __LINE__, strerror(errno)); \
        cmd; \
    }
#define testg(cond, label) test(cond, goto label)
#define teste(cond) test(cond, exit(EXIT_FAILURE))
#define testb(cond) test(cond, return false)

static void
test_adv_req(BN_CTX *ctx)
{
    TANG_MSG_ADV_REQ *madvreq = NULL;
    STACK_OF(TANG_KEY) *keys = NULL;
    TANG_KEY *tkey = NULL;
    EC_KEY *key = NULL;

    /* Test an empty ADV_REQ. */
    madvreq = adv_req(NULL);
    teste(madvreq);
    teste(SKM_sk_num(TANG_KEY, madvreq->keys) == 0);
    TANG_MSG_ADV_REQ_free(madvreq);

    /* Test an ADV_REQ with specified key. */
    key = EC_KEY_new_by_curve_name(NID_secp521r1);
    teste(key);
    teste(EC_KEY_generate_key(key) > 0);

    tkey = TANG_KEY_new();
    teste(tkey);
    teste(conv_eckey2tkey(key, TANG_KEY_USE_SIG, tkey, ctx) == 0);

    keys = SKM_sk_new_null(TANG_KEY);
    teste(keys);
    teste(SKM_sk_push(TANG_KEY, keys, tkey) > 0);

    madvreq = adv_req(keys);
    teste(madvreq);
    teste(SKM_sk_num(TANG_KEY, madvreq->keys) == 1);
    teste(TANG_KEY_equals(SKM_sk_value(TANG_KEY, madvreq->keys, 0), tkey));
    TANG_MSG_ADV_REQ_free(madvreq);

    SKM_sk_pop_free(TANG_KEY, keys, TANG_KEY_free);
    EC_KEY_free(key);
}

#define items(n) (sizeof(n) / sizeof(n[0]))

static const int grps[] = {
    NID_secp384r1,
    NID_secp521r1,
};

static const TANG_KEY_USE uses[] = {
    TANG_KEY_USE_SIG,
    TANG_KEY_USE_REC,
};

static bool
sign(TANG_MSG_ADV_REP *rep, EC_KEY *key)
{
    uint8_t hash[EVP_MAX_MD_SIZE] = {};
    unsigned int hlen = sizeof(hash);
    const EVP_MD *md = NULL;
    ECDSA_SIG *sig = NULL;
    TANG_SIG *tsig = NULL;
    uint8_t *buf = NULL;
    int len = 0;
    int r = 0;

    md = EVP_get_digestbynid(NID_sha224);
    if (!md)
        return false;

    len = i2d_TANG_MSG_ADV_REP_BDY(rep->body, &buf);
    if (len <= 0)
        return false;

    r = EVP_Digest(buf, len, hash, &hlen, md, NULL);
    OPENSSL_free(buf);
    buf = NULL;
    if (r <= 0)
        return false;

    tsig = TANG_SIG_new();
    if (!tsig)
        goto error;

    ASN1_OBJECT_free(tsig->type);
    tsig->type = OBJ_nid2obj(NID_ecdsa_with_SHA224);
    if (!tsig->type)
        goto error;

    sig = ECDSA_do_sign(hash, hlen, key);
    if (!sig)
        return false;

    len = i2d_ECDSA_SIG(sig, &buf);
    ECDSA_SIG_free(sig);
    if (len <= 0)
        goto error;

    r = ASN1_OCTET_STRING_set(tsig->sig, buf, len);
    OPENSSL_free(buf);
    buf = NULL;
    if (r <= 0)
        goto error;

    r = SKM_sk_push(TANG_SIG, rep->sigs, tsig);
    if (r <= 0)
        goto error;

    return true;

error:
    TANG_SIG_free(tsig);
    return false;
}

static void
test_adv_rep(BN_CTX *ctx)
{
    EC_KEY *keys[items(uses) * items(grps)] = {};
    TANG_MSG_ADV_REP *rep = NULL;

    teste(rep);

    for (size_t i = 0; i < items(grps); i++) {
        for (size_t j = 0; j < items(uses); j++) {
            keys[i * items(grps) + j] = EC_KEY_new_by_curve_name(grps[i]);
            if (!keys[i * items(grps) + j])
                goto error;

            if (EC_KEY_generate_key(keys[i * items(grps) + j]) <= 0)
                goto error;
        }
    }

    rep = TANG_MSG_ADV_REP_new();
    if (!rep)
        goto error;

    for (size_t i = 0; i < items(keys); i++) {
        TANG_KEY *tkey = NULL;

        tkey = TANG_KEY_new();
        if (!tkey)
            goto error;

        if (conv_eckey2tkey(keys[i], uses[i % items(grps)], tkey, ctx) != 0) {
            TANG_KEY_free(tkey);
            goto error;
        }

        if (SKM_sk_push(TANG_KEY, rep->body->keys, tkey) <= 0) {
            TANG_KEY_free(tkey);
            goto error;
        }
    }

    for (size_t i = 0; i < items(keys); i++) {
        if (uses[i % items(grps)] != TANG_KEY_USE_SIG)
            continue;

        if (!sign(rep, keys[i]))
            goto error;
    }

}

int
main(int argc, char *argv[])
{
    msg_t ipv4 = { .hostname = "127.0.0.1", .service = "5700", .timeout = 1 };
    msg_t ipv6 = { .hostname = "::1", .service = "5700", .timeout = 1 };
    EC_KEY *reca = NULL;
    EC_KEY *recA = NULL;
    EC_KEY *siga = NULL;
    EC_KEY *sigA = NULL;
    BN_CTX *ctx = NULL;

    srv_setup(&ipv4, &ipv6);

    ctx = BN_CTX_new();
    teste(ctx);

    test_adv_req();

    /* Make some unadvertised keys. */
    reca = srv_keygen("reca", "secp384r1", "rec", false);
    teste(reca);
    siga = srv_keygen("siga", "secp384r1", "sig", false);
    teste(siga);


    /* Make some advertised keys. */
    recA = srv_keygen("recA", "secp384r1", "rec", true);
    teste(recA);
    sigA = srv_keygen("sigA", "secp384r1", "sig", true);
    teste(sigA);


    EC_KEY_free(reca);
    EC_KEY_free(recA);
    EC_KEY_free(siga);
    EC_KEY_free(sigA);
    BN_CTX_free(ctx);
    return 0;
}
