#include <openssl/pem.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/core_object.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include "gost_asn1.h"

/*
 * Very small and simplified DECODER implementation.  This is
 * currently just enough to import a PKCS#8 or SubjectPublicKeyInfo
 * structure and create a GOST_KEYMGMT_CTX from it.
 */

typedef struct {
    PROV_CTX *provctx;
    int ispem;        /* 0 = DER input, 1 = PEM input */
    int selection;    /* Remember selection for export */
} GOST_DECODER_CTX;

static void *decoder_newctx(void *provctx)
{
    GOST_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void decoder_freectx(void *vctx)
{
    OPENSSL_free(vctx);
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

static const char *alg_nid2name(int nid)
{
    switch (nid) {
    case NID_id_GostR3410_2001:
        return "gost2001";
    case NID_id_GostR3410_2012_256:
        return "gost2012_256";
    case NID_id_GostR3410_2012_512:
        return "gost2012_512";
    }
    return NULL;
}

static int parse_algor(const X509_ALGOR *algor, int *alg_nid, int *param_nid)
{
    const ASN1_OBJECT *algobj = NULL;
    int ptype = V_ASN1_UNDEF;
    const ASN1_STRING *pval = NULL;
    const unsigned char *p;
    GOST_KEY_PARAMS *gkp = NULL;

    if (algor == NULL)
        return 0;
    X509_ALGOR_get0(&algobj, &ptype, (const void **)&pval, algor);
    if (algobj != NULL)
        *alg_nid = OBJ_obj2nid(algobj);
    if (ptype != V_ASN1_SEQUENCE || pval == NULL)
        return 0;

    p = pval->data;
    gkp = d2i_GOST_KEY_PARAMS(NULL, &p, pval->length);
    if (gkp == NULL)
        return 0;
    *param_nid = OBJ_obj2nid(gkp->key_params);
    GOST_KEY_PARAMS_free(gkp);
    return *param_nid != NID_undef;
}

static int read_der_from_bio(GOST_DECODER_CTX *ctx, OSSL_CORE_BIO *cin,
                             unsigned char **der, long *der_len, char **pem_name)
{
    BIO *in = BIO_new_from_core_bio(ctx->provctx->libctx, cin);
    int ok = 0;

    if (in == NULL)
        return 0;

    if (ctx->ispem) {
        char *header = NULL;

        ok = PEM_read_bio(in, pem_name, &header, der, der_len) > 0;
        OPENSSL_free(header);
    } else {
        unsigned char *buf = NULL;
        size_t buflen = 0;
        char tbuf[4096];
        size_t n;

        while (BIO_read_ex(in, tbuf, sizeof(tbuf), &n)) {
            unsigned char *tmp = OPENSSL_realloc(buf, buflen + n);
            if (tmp == NULL) {
                OPENSSL_free(buf);
                buf = NULL;
                goto end;
            }
            buf = tmp;
            memcpy(buf + buflen, tbuf, n);
            buflen += n;
        }
        if (buf == NULL)
            goto end;
        *der = buf;
        *der_len = (long)buflen;
        ok = 1;
    }
 end:
    BIO_free(in);
    return ok;
}

static int decoder_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    GOST_DECODER_CTX *ctx = vctx;
    unsigned char *der = NULL;
    long der_len = 0;
    char *pem_name = NULL;
    const unsigned char *p = NULL;
    GOST_PRIVATE_KEY_INFO *priv = NULL;
    GOST_PUBLIC_KEY_INFO *pub = NULL;
    int alg_nid = NID_undef, param_nid = NID_undef;
    GOST_KEYMGMT_CTX *gctx = NULL;
    const char *keytype = NULL;
    OSSL_PARAM params[4];
    size_t pidx = 0;
    int ok = 0;
    int sel = 0;

    (void)cb;
    (void)cbarg;

    ctx->selection = selection;

    if (!read_der_from_bio(ctx, cin, &der, &der_len, &pem_name))
        goto end;

    gctx = gost_keymgmt_new(ctx->provctx);
    if (gctx == NULL)
        goto end;

    p = der;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 || selection == 0) {
        priv = d2i_GOST_PRIVATE_KEY_INFO(NULL, &p, der_len);
        if (priv != NULL
            && parse_algor(priv->algor, &alg_nid, &param_nid)) {
            unsigned char *privbuf = NULL;
            int i;
            int klen = priv->priv_key->length;

            privbuf = OPENSSL_malloc(klen);
            if (privbuf == NULL)
                goto end;
            for (i = 0; i < klen; i++)
                privbuf[i] = priv->priv_key->data[klen - 1 - i];

            params[pidx++] =
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                  privbuf, klen);
            sel |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        }
    }

    if (priv == NULL
        && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 || selection == 0)) {
        p = der;
        pub = d2i_GOST_PUBLIC_KEY_INFO(NULL, &p, der_len);
        if (pub != NULL
            && parse_algor(pub->algor, &alg_nid, &param_nid)) {
            params[pidx++] =
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  pub->pub_key->data,
                                                  pub->pub_key->length);
            sel |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        }
    }

    if (alg_nid == NID_undef || param_nid == NID_undef)
        goto end;

    keytype = alg_nid2name(param_to_alg_nid(param_nid));
    if (keytype == NULL)
        goto end;

    params[pidx++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                      (char *)OBJ_nid2sn(param_nid),
                                                      0);
    params[pidx] = OSSL_PARAM_construct_end();

    if (!gost_import(gctx, sel, params))
        goto end;

    {
        int objtype = OSSL_OBJECT_PKEY;
        void *ref = gctx;
        OSSL_PARAM out[4];

        out[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
        out[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)keytype, 0);
        out[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &ref, sizeof(ref));
        out[3] = OSSL_PARAM_construct_end();

        ok = data_cb(out, data_cbarg);
    }

 end:
    OPENSSL_free(pem_name);
    OPENSSL_free(der);
    GOST_PRIVATE_KEY_INFO_free(priv);
    GOST_PUBLIC_KEY_INFO_free(pub);
    if (!ok)
        gost_keymgmt_free(gctx);
    return ok;
}

static int decoder_export_object(void *vctx,
                                 const void *reference, size_t reference_sz,
                                 OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    GOST_DECODER_CTX *ctx = vctx;
    GOST_KEYMGMT_CTX *keydata;

    if (reference_sz != sizeof(keydata))
        return 0;

    keydata = *(GOST_KEYMGMT_CTX **)reference;
    if (keydata == NULL)
        return 0;

    if (ctx->selection == 0)
        ctx->selection = OSSL_KEYMGMT_SELECT_ALL;

    return gost_export(keydata, ctx->selection, export_cb, export_cbarg);
}


static int decoder_does_selection(void *provctx, int selection)
{
    if ((selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY |
                      OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) != 0)
        return 1;
    return 0;
}

static int decoder_parameters(OSSL_PARAM params[])
{
    (void)params;
    return 1;
}

typedef void (*fptr_t)(void);

#define MAKE_DECODER_FUNCTIONS(alg, fmt, ispemflag)                        \
    static void *alg##_##fmt##_decoder_newctx(void *provctx)               \
    {                                                                      \
        GOST_DECODER_CTX *ctx = decoder_newctx(provctx);                   \
        if (ctx != NULL)                                                   \
            ctx->ispem = ispemflag;                                        \
        return ctx;                                                        \
    }                                                                      \
    static const OSSL_DISPATCH alg##_##fmt##_decoder_functions[] = {       \
        { OSSL_FUNC_DECODER_NEWCTX, (fptr_t)alg##_##fmt##_decoder_newctx },\
        { OSSL_FUNC_DECODER_FREECTX, (fptr_t)decoder_freectx },             \
        { OSSL_FUNC_DECODER_DECODE, (fptr_t)decoder_decode },              \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT, (fptr_t)decoder_export_object },\
        { OSSL_FUNC_DECODER_DOES_SELECTION, (fptr_t)decoder_does_selection },\
        { OSSL_FUNC_DECODER_GET_PARAMS, (fptr_t)decoder_parameters },       \
        { 0, NULL }                                                        \
    }

MAKE_DECODER_FUNCTIONS(gost2001, der, 0);
MAKE_DECODER_FUNCTIONS(gost2001, pem, 1);
MAKE_DECODER_FUNCTIONS(gost2012_256, der, 0);
MAKE_DECODER_FUNCTIONS(gost2012_256, pem, 1);
MAKE_DECODER_FUNCTIONS(gost2012_512, der, 0);
MAKE_DECODER_FUNCTIONS(gost2012_512, pem, 1);

const OSSL_ALGORITHM GOST_prov_decoders[] = {
    { "gost2001", "provider=gostprov,input=der", gost2001_der_decoder_functions },
    { "gost2001", "provider=gostprov,input=pem", gost2001_pem_decoder_functions },
    { "gost2012_256", "provider=gostprov,input=der", gost2012_256_der_decoder_functions },
    { "gost2012_256", "provider=gostprov,input=pem", gost2012_256_pem_decoder_functions },
    { "gost2012_512", "provider=gostprov,input=der", gost2012_512_der_decoder_functions },
    { "gost2012_512", "provider=gostprov,input=pem", gost2012_512_pem_decoder_functions },
    { NULL, NULL, NULL }
};
