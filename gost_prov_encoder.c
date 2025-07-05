#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include "gost_asn1.h"

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
        || !EVP_PKEY_set1_engine(pkey, ctx->provctx->e)
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

/* Currently not implemented */
static int encoder_export_object(void *vctx, const void *objref, size_t objref_sz,
                                 OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    /* TODO: implement export if needed */
    return 0;
}

static void *encoder_import_object(void *vctx, int selection,
                                   const OSSL_PARAM params[])
{
    /* TODO: implement import if needed */
    return NULL;
}

static int encoder_does_selection(void *provctx, int selection)
{
    if ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                      OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) != 0)
        return 1;
    return 0;
}

static const OSSL_PARAM *encoder_parameters(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END
    };
    return params;
}

/* A placeholder to silence unused function warnings. */

void gost_prov_encoder_stub(void)
{
}
