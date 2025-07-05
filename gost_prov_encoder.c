#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "gost_prov.h"
#include "gost_lcl.h"

#ifndef OSSL_ENCODER_PARAM_OUTPUT_TYPE
# define OSSL_ENCODER_PARAM_OUTPUT_TYPE "output-type"
#endif


/*
 * Very small and simplified ENCODER implementation.  This is
 * currently just enough to export a GOST_KEYMGMT_CTX EC_KEY as
 * PKCS#8 or SubjectPublicKeyInfo in either DER or PEM form.
 */

typedef struct {
    PROV_CTX *provctx;
    int ispem; /* 0 = DER, 1 = PEM */
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

/* Map parameter set NID to algorithm NID */
static int param_to_alg_nid(int param_nid)
{
    switch (param_nid) {
    case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
    case NID_id_GostR3410_2001_TestParamSet:
    case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
        return NID_id_GostR3410_2001;

    case NID_id_tc26_gost_3410_2012_256_paramSetA:
    case NID_id_tc26_gost_3410_2012_256_paramSetB:
    case NID_id_tc26_gost_3410_2012_256_paramSetC:
    case NID_id_tc26_gost_3410_2012_256_paramSetD:
        return NID_id_GostR3410_2012_256;

    case NID_id_tc26_gost_3410_2012_512_paramSetA:
    case NID_id_tc26_gost_3410_2012_512_paramSetB:
    case NID_id_tc26_gost_3410_2012_512_paramSetC:
        return NID_id_GostR3410_2012_512;
    }
    return NID_undef;
}

static int encoder_encode(void *vctx, OSSL_CORE_BIO *cout, const void *obj,
                          const OSSL_PARAM obj_abstract[], int selection,
                          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    GOST_ENCODER_CTX *ctx = vctx;
    const GOST_KEYMGMT_CTX *gctx = obj;
    EVP_PKEY *pkey = NULL;
    BIO *out = NULL;
    int alg_nid = NID_undef;
    int ret = 0;

    if (gctx == NULL || gctx->ec == NULL || obj_abstract != NULL)
        return 0;

    alg_nid = param_to_alg_nid(gctx->param_nid);
    if (alg_nid == NID_undef)
        return 0;

    if ((pkey = EVP_PKEY_new()) == NULL)
        goto end;
    if (!EVP_PKEY_set_type(pkey, alg_nid)
        || !EVP_PKEY_set1_EC_KEY(pkey, gctx->ec))
        goto end;

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        EC_KEY_get0_private_key(gctx->ec) != NULL) {
        if (ctx->ispem)
            ret = PEM_write_bio_PrivateKey_traditional(out, pkey,
                                                      NULL, NULL, 0, NULL, NULL);
        else
            ret = i2d_PrivateKey_bio(out, pkey);
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
               EC_KEY_get0_public_key(gctx->ec) != NULL) {
        if (ctx->ispem)
            ret = PEM_write_bio_PUBKEY(out, pkey);
        else
            ret = i2d_PUBKEY_bio(out, pkey);
    }

end:
    BIO_free(out);
    EVP_PKEY_free(pkey);
    return ret > 0;
}

static int encoder_set_ctx_params(void *vctx, const OSSL_PARAM params[])

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
    if ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                      OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) != 0)
        return 1;
    return 0;
}

static int encoder_get_params(OSSL_PARAM params[])
{
    /* No parameters to return */
    (void)params;
    return 1;
}

typedef void (*fptr_t)(void);
/*
 * This macro declares DER and PEM variants for each GOST encoder.
 * The format is selected via ispemflag or set_ctx_params.
 */

#define MAKE_ENCODER_FUNCTIONS(alg, fmt, ispemflag)                        \
    static void *alg##_##fmt##_encoder_newctx(void *provctx)               \
    {                                                                      \
        GOST_ENCODER_CTX *ctx = encoder_newctx(provctx);                   \
        if (ctx != NULL)                                                   \
            ctx->ispem = ispemflag;                                        \
        return ctx;                                                        \
    }                                                                      \
    static const OSSL_DISPATCH alg##_##fmt##_encoder_functions[] = {       \
        { OSSL_FUNC_ENCODER_NEWCTX, (fptr_t)alg##_##fmt##_encoder_newctx },\
        { OSSL_FUNC_ENCODER_FREECTX, (fptr_t)encoder_freectx },             \
        { OSSL_FUNC_ENCODER_ENCODE, (fptr_t)encoder_encode },              \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (fptr_t)encoder_set_ctx_params },\
        { OSSL_FUNC_ENCODER_DOES_SELECTION, (fptr_t)encoder_does_selection },\
        { OSSL_FUNC_ENCODER_GET_PARAMS, (fptr_t)encoder_get_params },       \
        { 0, NULL }                                                        \
    }

MAKE_ENCODER_FUNCTIONS(gost2001, der, 0);
MAKE_ENCODER_FUNCTIONS(gost2001, pem, 1);
MAKE_ENCODER_FUNCTIONS(gost2012_256, der, 0);
MAKE_ENCODER_FUNCTIONS(gost2012_256, pem, 1);
MAKE_ENCODER_FUNCTIONS(gost2012_512, der, 0);
MAKE_ENCODER_FUNCTIONS(gost2012_512, pem, 1);

const OSSL_ALGORITHM GOST_prov_encoders[] = {
    { "gost2001:DER", "provider=gostprov", gost2001_der_encoder_functions },
    { "gost2001:PEM", "provider=gostprov", gost2001_pem_encoder_functions },
    { "gost2012_256:DER", "provider=gostprov", gost2012_256_der_encoder_functions },
    { "gost2012_256:PEM", "provider=gostprov", gost2012_256_pem_encoder_functions },
    { "gost2012_512:DER", "provider=gostprov", gost2012_512_der_encoder_functions },
    { "gost2012_512:PEM", "provider=gostprov", gost2012_512_pem_encoder_functions },
    { NULL, NULL, NULL }
};

