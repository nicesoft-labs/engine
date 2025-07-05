#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "gost_prov.h"
#include "gost_lcl.h"

/* Key management context */

static void *gost_keymgmt_new(void *provctx)
{
    GOST_KEYMGMT_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void gost_keymgmt_free(void *vctx)
{
    GOST_KEYMGMT_CTX *ctx = vctx;

    if (ctx != NULL) {
        EC_KEY_free(ctx->ec);
        OPENSSL_free(ctx);
    }
}

static const char *gost_query_operation_name(int op_id)
{
    return "EC";
}

static int gost_has(const void *keydata, int selection)
{
    const GOST_KEYMGMT_CTX *ctx = keydata;
    const EC_KEY *ec = ctx->ec;
    int ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && EC_KEY_get0_private_key(ec) != NULL;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && EC_KEY_get0_public_key(ec) != NULL;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && EC_KEY_get0_group(ec) != NULL;
    return ok;
}

static const OSSL_PARAM keymgmt_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *gost_gettable_params(void *provctx)
{
    return keymgmt_params;
}

static const OSSL_PARAM *gost_imexport_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };
    return types;
}

static void gost_gen_cleanup(void *genctx)
{
    /* no cleanup needed since genctx is returned as keydata */
}

static void *gost_gen_init(void *provctx, int selection,
                           const OSSL_PARAM params[], int def_nid)
{
    GOST_KEYMGMT_CTX *gctx = gost_keymgmt_new(provctx);
    const OSSL_PARAM *p;
    const char *name = NULL;

    if (gctx == NULL)
        return NULL;
    gctx->param_nid = def_nid;

    if (params != NULL
        && (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL
        && OSSL_PARAM_get_utf8_string_ptr(p, &name)) {
        int nid = OBJ_sn2nid(name);
        if (nid == NID_undef)
            nid = OBJ_txt2nid(name);
        if (nid != NID_undef)
            gctx->param_nid = nid;
    }
    return gctx;
}

static void *gost_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    GOST_KEYMGMT_CTX *gctx = genctx;
    EC_KEY *ec = EC_KEY_new();

    if (ec == NULL)
        return NULL;
    if (!fill_GOST_EC_params(ec, gctx->param_nid)
        || !gost_ec_keygen(ec)) {
        EC_KEY_free(ec);
        return NULL;
    }
    /* genctx will be cleaned up by the framework */
    return gctx;
}

static void *gost_load(const void *reference, size_t reference_sz)
{
    GOST_KEYMGMT_CTX *ctx = gost_keymgmt_new(NULL);
    EC_KEY *ec = NULL;

    if (ctx == NULL)
        return NULL;
    if (reference_sz == sizeof(ec))
        memcpy(&ec, reference, sizeof(ec));
    ctx->ec = ec;
    if (ec != NULL) {
        const EC_GROUP *grp = EC_KEY_get0_group(ec);
        if (grp != NULL)
            ctx->param_nid = EC_GROUP_get_curve_name(grp);
    }
    return ctx;
}

static int gost_get_params(void *key, OSSL_PARAM params[])
{
    GOST_KEYMGMT_CTX *ctx = key;
    EC_KEY *ec = ctx->ec;
    const EC_GROUP *group = ec != NULL ? EC_KEY_get0_group(ec) : NULL;
    OSSL_PARAM *p;

    if (group == NULL)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {
        const char *sn = OBJ_nid2sn(EC_GROUP_get_curve_name(group));
        if (sn == NULL || !OSSL_PARAM_set_utf8_string(p, sn))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
        BIGNUM *order = BN_new();
        int bits = 0;
        if (order == NULL || !EC_GROUP_get_order(group, order, NULL)) {
            BN_free(order);
            return 0;
        }
        bits = BN_num_bits(order);
        BN_free(order);
        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }
    return 1;
}

static int gost_export(void *keydata, int selection,
                       OSSL_CALLBACK *param_cb, void *cbarg)
{
    GOST_KEYMGMT_CTX *ctx = keydata;
    EC_KEY *ec = ctx->ec;
    const EC_GROUP *group = ec != NULL ? EC_KEY_get0_group(ec) : NULL;
    const EC_POINT *pub = ec != NULL ? EC_KEY_get0_public_key(ec) : NULL;
    const BIGNUM *priv = ec != NULL ? EC_KEY_get0_private_key(ec) : NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    unsigned char *pubbuf = NULL;
    size_t publen = 0;
    unsigned char *privbuf = NULL;
    size_t privlen = 0;
    int ok = 0;

    if (group == NULL)
        return 0;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && priv != NULL) {
        privlen = (EC_GROUP_get_degree(group) + 7) / 8;
        privbuf = OPENSSL_malloc(privlen);
        if (privbuf == NULL
            || BN_bn2binpad(priv, privbuf, privlen) < 0
            || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                                 privbuf, privlen))
            goto err;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && pub != NULL) {
        publen = EC_POINT_point2buf(group, pub,
                                    POINT_CONVERSION_UNCOMPRESSED,
                                    &pubbuf, NULL);
        if (publen == 0
            || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                                 pubbuf, publen))
            goto err;
    }
    {
        const char *sn = OBJ_nid2sn(EC_GROUP_get_curve_name(group));
        if (sn != NULL
            && !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                               sn, 0))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;
    ok = param_cb(params, cbarg);
 err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_free(pubbuf);
    OPENSSL_free(privbuf);
    return ok;
}

static int gost_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    GOST_KEYMGMT_CTX *ctx = keydata;
    EC_KEY *ec = ctx->ec;
    const OSSL_PARAM *p;

    if (ec == NULL) {
        ec = EC_KEY_new();
        if (ec == NULL)
            return 0;
        ctx->ec = ec;
    }


    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {
        const char *name = NULL;
        int nid;
        
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &name))
            return 0;
        nid = OBJ_sn2nid(name);
        if (nid == NID_undef)
            nid = OBJ_txt2nid(name);
        if (nid == NID_undef || !fill_GOST_EC_params(ec, nid))
            return 0;
        ctx->param_nid = nid;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        BIGNUM *bn = BN_bin2bn(p->data, p->data_size, NULL);
        if (bn == NULL || !EC_KEY_set_private_key(ec, bn)) {
            BN_free(bn);
            return 0;
        }
        BN_free(bn);
        gost_ec_compute_public(ec);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        EC_POINT *point;
        if (group == NULL)
            return 0;
        point = EC_POINT_new(group);
        if (point == NULL
            || !EC_POINT_oct2point(group, point, p->data, p->data_size, NULL)
            || !EC_KEY_set_public_key(ec, point)) {
            EC_POINT_free(point);
            return 0;
        }
        EC_POINT_free(point);
    }
    if (EC_KEY_get0_group(ec) != NULL)
        ctx->param_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
    return 1;
}

/* Generation helpers for each algorithm */
static void *gost2001_gen_init(void *provctx, int selection,
                               const OSSL_PARAM params[])
{
    return gost_gen_init(provctx, selection, params,
                         NID_id_GostR3410_2001_CryptoPro_A_ParamSet);
}

static void *gost2012_256_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[])
{
    return gost_gen_init(provctx, selection, params,
                         NID_id_tc26_gost_3410_2012_256_paramSetA);
}

static void *gost2012_512_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[])
{
    return gost_gen_init(provctx, selection, params,
                         NID_id_tc26_gost_3410_2012_512_paramSetA);
}

typedef void (*fptr_t)(void);

static const OSSL_DISPATCH gost2001_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (fptr_t)gost_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (fptr_t)gost_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (fptr_t)gost2001_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (fptr_t)gost_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (fptr_t)gost_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (fptr_t)gost_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (fptr_t)gost_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (fptr_t)gost_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (fptr_t)gost_has },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (fptr_t)gost_query_operation_name },
    { OSSL_FUNC_KEYMGMT_EXPORT, (fptr_t)gost_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (fptr_t)gost_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (fptr_t)gost_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (fptr_t)gost_imexport_types },
    { 0, NULL }
};

static const OSSL_DISPATCH gost2012_256_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (fptr_t)gost_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (fptr_t)gost_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (fptr_t)gost2012_256_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (fptr_t)gost_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (fptr_t)gost_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (fptr_t)gost_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (fptr_t)gost_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (fptr_t)gost_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (fptr_t)gost_has },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (fptr_t)gost_query_operation_name },
    { OSSL_FUNC_KEYMGMT_EXPORT, (fptr_t)gost_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (fptr_t)gost_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (fptr_t)gost_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (fptr_t)gost_imexport_types },
    { 0, NULL }
};

static const OSSL_DISPATCH gost2012_512_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (fptr_t)gost_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (fptr_t)gost_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (fptr_t)gost2012_512_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (fptr_t)gost_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (fptr_t)gost_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (fptr_t)gost_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (fptr_t)gost_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (fptr_t)gost_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (fptr_t)gost_has },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (fptr_t)gost_query_operation_name },
    { OSSL_FUNC_KEYMGMT_EXPORT, (fptr_t)gost_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (fptr_t)gost_imexport_types },
    { OSSL_FUNC_KEYMGMT_IMPORT, (fptr_t)gost_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (fptr_t)gost_imexport_types },
    { 0, NULL }
};

const OSSL_ALGORITHM GOST_prov_keymgmts[] = {
    { "gost2001", NULL, gost2001_keymgmt_functions },
    { "gost2012_256", NULL, gost2012_256_keymgmt_functions },
    { "gost2012_512", NULL, gost2012_512_keymgmt_functions },
    { NULL, NULL, NULL }
};
