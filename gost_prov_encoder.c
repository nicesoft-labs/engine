#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include "gost_asn1.h"


#ifndef OSSL_ENCODER_PARAM_OUTPUT_TYPE
# define OSSL_ENCODER_PARAM_OUTPUT_TYPE "output-type"
#endif
#ifndef OSSL_ENCODER_PARAM_STRUCTURE
# define OSSL_ENCODER_PARAM_STRUCTURE "structure"
#endif


/*
 * Very small and simplified ENCODER implementation.  This is
 * currently just enough to export a GOST_KEYMGMT_CTX EC_KEY as
 * PKCS#8 or SubjectPublicKeyInfo in either DER or PEM form.
 */

typedef struct {
    PROV_CTX *provctx;
    int ispem;      /* 0 = DER, 1 = PEM */
    int selection;  /* expected selection */
} GOST_ENCODER_CTX;

static void *encoder_newctx(void *provctx)
{
    GOST_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void encoder_freectx(void *vctx)
{
    GOST_ENCODER_CTX *ctx = vctx;

    OPENSSL_free(ctx);
}

static int encoder_encode(void *vctx, OSSL_CORE_BIO *cout, const void *obj,
                          const OSSL_PARAM obj_abstract[], int selection,
                          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    GOST_ENCODER_CTX *ctx = vctx;
    const GOST_KEYMGMT_CTX *gctx = obj;
    GOST_PRIVATE_KEY_INFO *privinfo = NULL;
    GOST_PUBLIC_KEY_INFO *pubinfo = NULL;
    BIO *out = NULL;
    int ret = 0;

    if (gctx == NULL || gctx->ec == NULL || obj_abstract != NULL)
        return 0;

    ctx->selection = selection;
    DEBUG_LOG("encoder_encode: param_nid=%d selection=%d", gctx->param_nid, selection);

    if (ctx->provctx->libctx != NULL)
        out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out == NULL) {
        DEBUG_LOG("BIO_new_from_core_bio returned NULL");
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        EC_KEY_get0_private_key(gctx->ec) != NULL) {
            DEBUG_LOG("encode PRIVATE key path param_nid=%d", gctx->param_nid);
            DEBUG_LOG("call gost_priv_key_info_from_ec param_nid=%d", gctx->param_nid);
        privinfo = gost_priv_key_info_from_ec(gctx->ec, gctx->param_nid);
        if (privinfo != NULL) {
            if (ctx->ispem) {
                DEBUG_LOG("serialize path: PEM private key");
                ret = PEM_write_bio_GOST_PRIVATE_KEY_INFO(out, privinfo);
            } else {
                DEBUG_LOG("serialize path: DER private key");
                ret = i2d_GOST_PRIVATE_KEY_INFO_bio(out, privinfo);
            }
        }
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
               EC_KEY_get0_public_key(gctx->ec) != NULL) {
        DEBUG_LOG("encode PUBLIC key path param_nid=%d", gctx->param_nid);
        DEBUG_LOG("call gost_pub_key_info_from_ec param_nid=%d", gctx->param_nid);
        pubinfo = gost_pub_key_info_from_ec(gctx->ec, gctx->param_nid);
        if (pubinfo != NULL) {
            if (ctx->ispem) {
                DEBUG_LOG("serialize path: PEM public key");
                ret = PEM_write_bio_GOST_PUBLIC_KEY_INFO(out, pubinfo);
            } else {
                DEBUG_LOG("serialize path: DER public key");
                ret = i2d_GOST_PUBLIC_KEY_INFO_bio(out, pubinfo);
            }
        }
    }

end:
    BIO_free(out);
    GOST_PRIVATE_KEY_INFO_free(privinfo);
    GOST_PUBLIC_KEY_INFO_free(pubinfo);
    return ret > 0;
}

static int encoder_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    GOST_ENCODER_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL) {
        const char *t = NULL;

        if (!OSSL_PARAM_get_utf8_string_ptr(p, &t))
            return 0;
        if (strcmp(t, "PEM") == 0)
            ctx->ispem = 1;
        else if (strcmp(t, "DER") == 0)
            ctx->ispem = 0;
        else
            return 0;
    }

    return 1;
}

static int encoder_does_selection(void *provctx, int selection)
{
    int allowed = OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    if (selection == 0)
        return 1;
    if ((selection & ~allowed) != 0)
        return 0;
    return (selection & allowed) != 0;
}

static int encoder_get_params_generic(OSSL_PARAM params[],
                                      const char *output_type,
                                      const char *structure)
{
    OSSL_PARAM *p;

    DEBUG_LOG("encoder_get_params: output=%s structure=%s", output_type,
              structure);

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, output_type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, structure))
        return 0;
    return 1;
}

static int encoder_get_params(void *vctx, OSSL_PARAM params[])
{
    GOST_ENCODER_CTX *ctx = vctx;
    const char *type = ctx->ispem ? "PEM" : "DER";
    const char *structure =
        (ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
        "PrivateKeyInfo" : "SubjectPublicKeyInfo";

    return encoder_get_params_generic(params, type, structure);
}

static const OSSL_PARAM *encoder_gettable_params(void *provctx)
{
    static const OSSL_PARAM known_gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_OUTPUT_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_STRUCTURE, NULL, 0),
        OSSL_PARAM_END
    };

    return known_gettable;
}


typedef void (*fptr_t)(void);
/*
 * This macro declares DER and PEM variants for each GOST encoder.
 * The format and expected key selection are preset via the arguments.
 */

#define MAKE_ENCODER_FUNCTIONS(alg, fmt, ispemflag, selflag, suffix)       \
    static void *alg##_##fmt##_##suffix##_encoder_newctx(void *provctx)    \
    {                                                                      \
        GOST_ENCODER_CTX *ctx = encoder_newctx(provctx);                   \
        if (ctx != NULL) {                                                 \
            ctx->ispem = ispemflag;                                        \
            ctx->selection = selflag;                                      \
        }                                                                  \
        return ctx;                                                        \
    }                                                                      \
    static const OSSL_DISPATCH alg##_##fmt##_##suffix##_encoder_functions[] = { \
        { OSSL_FUNC_ENCODER_NEWCTX,                                        \
          (fptr_t)alg##_##fmt##_##suffix##_encoder_newctx },               \
        { OSSL_FUNC_ENCODER_FREECTX, (fptr_t)encoder_freectx },             \
        { OSSL_FUNC_ENCODER_ENCODE, (fptr_t)encoder_encode },              \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (fptr_t)encoder_set_ctx_params },\
        { OSSL_FUNC_ENCODER_DOES_SELECTION, (fptr_t)encoder_does_selection },\
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,                                \
          (fptr_t)encoder_gettable_params },                                \
        { OSSL_FUNC_ENCODER_GET_PARAMS, (fptr_t)encoder_get_params },       \
        { 0, NULL }                                                        \
    }

MAKE_ENCODER_FUNCTIONS(gost2001, der, 0, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_ENCODER_FUNCTIONS(gost2001, pem, 1, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_ENCODER_FUNCTIONS(gost2001, der, 0, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);
MAKE_ENCODER_FUNCTIONS(gost2001, pem, 1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);

MAKE_ENCODER_FUNCTIONS(gost2012_256, der, 0, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_ENCODER_FUNCTIONS(gost2012_256, pem, 1, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_ENCODER_FUNCTIONS(gost2012_256, der, 0, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);
MAKE_ENCODER_FUNCTIONS(gost2012_256, pem, 1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);

MAKE_ENCODER_FUNCTIONS(gost2012_512, der, 0, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_ENCODER_FUNCTIONS(gost2012_512, pem, 1, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_ENCODER_FUNCTIONS(gost2012_512, der, 0, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);
MAKE_ENCODER_FUNCTIONS(gost2012_512, pem, 1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);

const OSSL_ALGORITHM GOST_prov_encoders[] = {
    { "gost2001", "provider=gostprov,output=der,structure=PrivateKeyInfo", gost2001_der_priv_encoder_functions },
    { "gost2001", "provider=gostprov,output=pem,structure=PrivateKeyInfo", gost2001_pem_priv_encoder_functions },
    { "gost2001", "provider=gostprov,output=der,structure=SubjectPublicKeyInfo", gost2001_der_pub_encoder_functions },
    { "gost2001", "provider=gostprov,output=pem,structure=SubjectPublicKeyInfo", gost2001_pem_pub_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=der,structure=PrivateKeyInfo", gost2012_256_der_priv_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=pem,structure=PrivateKeyInfo", gost2012_256_pem_priv_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=der,structure=SubjectPublicKeyInfo", gost2012_256_der_pub_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=pem,structure=SubjectPublicKeyInfo", gost2012_256_pem_pub_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=der,structure=PrivateKeyInfo", gost2012_512_der_priv_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=pem,structure=PrivateKeyInfo", gost2012_512_pem_priv_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=der,structure=SubjectPublicKeyInfo", gost2012_512_der_pub_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=pem,structure=SubjectPublicKeyInfo", gost2012_512_pem_pub_encoder_functions },
    { NULL, NULL, NULL }
};

