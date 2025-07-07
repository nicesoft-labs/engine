#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include "gost_asn1.h"

#ifndef OSSL_ENCODER_PARAM_OUTPUT_TYPE
# define OSSL_ENCODER_PARAM_OUTPUT_TYPE "output-type"
#endif
#ifndef OSSL_ENCODER_PARAM_STRUCTURE
# define OSSL_ENCODER_PARAM_STRUCTURE "structure"
#endif

#ifdef ENABLE_GOST_DEBUG
static void debug_dump_params(const OSSL_PARAM *p)
{
    DEBUG_LOG(">>>> debug_dump_params: Dumping OSSL_PARAM");
    if (p == NULL) {
        DEBUG_LOG(">>>> debug_dump_params: params is NULL");
        return;
    }
    for (; p != NULL && p->key != NULL; p++) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING:
        case OSSL_PARAM_UTF8_PTR:
            DEBUG_LOG("param %s = %s", p->key, p->data ? (char *)p->data : "NULL");
            break;
        case OSSL_PARAM_INTEGER:
            if (p->data_size == sizeof(int))
                DEBUG_LOG("param %s = %d", p->key, p->data ? *(int *)p->data : 0);
            else
                DEBUG_LOG("param %s integer size=%zu", p->key, p->data_size);
            break;
        case OSSL_PARAM_UNSIGNED_INTEGER:
            if (p->data_size == sizeof(unsigned int))
                DEBUG_LOG("param %s = %u", p->key, p->data ? *(unsigned int *)p->data : 0);
            else
                DEBUG_LOG("param %s uinteger size=%zu", p->key, p->data_size);
            break;
        default:
            DEBUG_LOG("param %s type=%u size=%zu data=%p", p->key, p->data_type, p->data_size, p->data);
            break;
        }
    }
    DEBUG_LOG(">>>> debug_dump_params: End");
}
#else
static void debug_dump_params(const OSSL_PARAM *p)
{
    (void)p;
}
#endif

typedef struct {
    PROV_CTX *provctx;
    int ispem;      /* 0 = DER, 1 = PEM */
    int selection;  /* expected selection */
    int init_selection; /* initial selection from newctx */
} GOST_ENCODER_CTX;

static void *encoder_newctx(void *provctx)
{
    DEBUG_LOG(">>>> encoder_newctx: Creating new GOST_ENCODER_CTX for provctx=%p", provctx);
    GOST_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        DEBUG_LOG(">>>> encoder_newctx: Failed to allocate ctx");
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->provctx = provctx;
    DEBUG_LOG(">>>> encoder_newctx: ctx=%p provctx=%p", ctx, provctx);
    return ctx;
}

static void encoder_freectx(void *vctx)
{
    GOST_ENCODER_CTX *ctx = vctx;
    DEBUG_LOG(">>>> encoder_freectx: Freeing ctx=%p", ctx);
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
    unsigned char *der = NULL;
    int der_len = 0;
    int ret = 0;

    DEBUG_LOG(">>>> encoder_encode: Starting with ctx=%p cout=%p obj=%p selection=%d",
              vctx, cout, obj, selection);
    DEBUG_LOG(">>>> encoder_encode: ctx->provctx=%p ctx->ispem=%d ctx->selection=%d ctx->init_selection=%d",
              ctx->provctx, ctx->ispem, ctx->selection, ctx->init_selection);
    DEBUG_LOG(">>>> encoder_encode: obj_abstract=%p cb=%p cbarg=%p",
              obj_abstract, cb, cbarg);

    if (gctx == NULL || gctx->ec == NULL || obj_abstract != NULL) {
        DEBUG_LOG(">>>> encoder_encode: Invalid input: gctx=%p gctx->ec=%p obj_abstract=%p",
                  gctx, gctx ? gctx->ec : NULL, obj_abstract);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        goto end;
    }

    DEBUG_LOG(">>>> encoder_encode: param_nid=%d (%s)", gctx->param_nid, OBJ_nid2sn(gctx->param_nid));

    if (selection == 0) {
        selection = ctx->selection;
        DEBUG_LOG(">>>> encoder_encode: Using ctx->selection=%d", selection);
    } else {
        ctx->selection = selection;
        DEBUG_LOG(">>>> encoder_encode: Updated ctx->selection to %d", selection);
    }

    if (ctx->provctx->libctx != NULL) {
        out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
        if (out == NULL) {
            DEBUG_LOG(">>>> encoder_encode: BIO_new_from_core_bio returned NULL");
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        DEBUG_LOG(">>>> encoder_encode: Created BIO out=%p", out);
    } else {
        DEBUG_LOG(">>>> encoder_encode: ctx->provctx->libctx is NULL");
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        goto end;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 &&
        EC_KEY_get0_private_key(gctx->ec) != NULL) {
        DEBUG_LOG(">>>> encoder_encode: Encoding PRIVATE key path param_nid=%d (%s)",
                  gctx->param_nid, OBJ_nid2sn(gctx->param_nid));
        DEBUG_LOG(">>>> encoder_encode: Calling gost_priv_key_info_from_ec param_nid=%d",
                  gctx->param_nid);
        privinfo = gost_priv_key_info_from_ec(gctx->ec, gctx->param_nid);
        if (privinfo == NULL) {
            DEBUG_LOG(">>>> encoder_encode: gost_priv_key_info_from_ec returned NULL");
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        DEBUG_LOG(">>>> encoder_encode: Created privinfo=%p", privinfo);
        if (privinfo->algor != NULL) {
            int alg_nid = OBJ_obj2nid(privinfo->algor->algorithm);
            DEBUG_LOG(">>>> encoder_encode: privkey AlgorithmIdentifier alg_nid=%d (%s)",
                      alg_nid, OBJ_nid2sn(alg_nid));
        } else {
            DEBUG_LOG(">>>> encoder_encode: privinfo->algor is NULL");
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto end;
        }
        if (ctx->ispem) {
            DEBUG_LOG(">>>> encoder_encode: Serializing PEM private key");
            ret = PEM_write_bio_GOST_PRIVATE_KEY_INFO(out, privinfo);
            DEBUG_LOG(">>>> encoder_encode: PEM_write_bio_GOST_PRIVATE_KEY_INFO returned ret=%d", ret);
        } else {
            DEBUG_LOG(">>>> encoder_encode: Serializing DER private key");
            der_len = i2d_GOST_PRIVATE_KEY_INFO(privinfo, &der);
            DEBUG_LOG(">>>> encoder_encode: i2d_GOST_PRIVATE_KEY_INFO returned der_len=%d", der_len);
            if (der_len > 0) {
                DEBUG_LOG(">>>> encoder_encode: Writing %d bytes to BIO", der_len);
                if (der_len <= 32) {
                    DEBUG_LOG(">>>> encoder_encode: DER private key bytes:");
                    for (int i = 0; i < der_len; i++)
                        fprintf(stderr, "%02X ", der[i]);
                    fprintf(stderr, "\n");
                }
                ret = BIO_write(out, der, der_len) == der_len;
                DEBUG_LOG(">>>> encoder_encode: BIO_write returned ret=%d", ret);
#ifdef ENABLE_GOST_DEBUG
                {
                    FILE *f = fopen("/tmp/encoder_privkey.der", "wb");
                    if (f != NULL) {
                        fwrite(der, 1, der_len, f);
                        fclose(f);
                        DEBUG_LOG(">>>> encoder_encode: Saved private key DER to /tmp/encoder_privkey.der");
                    } else {
                        DEBUG_LOG(">>>> encoder_encode: Failed to open /tmp/encoder_privkey.der");
                    }
                }
#endif
            } else {
                DEBUG_LOG(">>>> encoder_encode: i2d_GOST_PRIVATE_KEY_INFO failed");
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
                ERR_print_errors_fp(stderr);
                ret = 0;
            }
        }
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 &&
               EC_KEY_get0_public_key(gctx->ec) != NULL) {
        DEBUG_LOG(">>>> encoder_encode: Encoding PUBLIC key path param_nid=%d (%s)",
                  gctx->param_nid, OBJ_nid2sn(gctx->param_nid));
        DEBUG_LOG(">>>> encoder_encode: Calling gost_pub_key_info_from_ec param_nid=%d",
                  gctx->param_nid);
        pubinfo = gost_pub_key_info_from_ec(gctx->ec, gctx->param_nid);
        if (pubinfo == NULL) {
            DEBUG_LOG(">>>> encoder_encode: gost_pub_key_info_from_ec returned NULL");
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        DEBUG_LOG(">>>> encoder_encode: Created pubinfo=%p", pubinfo);
        if (pubinfo->algor != NULL) {
            int alg_nid = OBJ_obj2nid(pubinfo->algor->algorithm);
            DEBUG_LOG(">>>> encoder_encode: pubkey AlgorithmIdentifier alg_nid=%d (%s)",
                      alg_nid, OBJ_nid2sn(alg_nid));
        } else {
            DEBUG_LOG(">>>> encoder_encode: pubinfo->algor is NULL");
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto end;
        }
        if (pubinfo->pub_key != NULL) {
            DEBUG_LOG(">>>> encoder_encode: pub_key length=%d", pubinfo->pub_key->length);
            if (pubinfo->pub_key->length > 0) {
                DEBUG_LOG(">>>> encoder_encode: First %d bytes of pub_key:",
                          pubinfo->pub_key->length < 16 ? pubinfo->pub_key->length : 16);
                for (int i = 0; i < pubinfo->pub_key->length && i < 16; i++)
                    fprintf(stderr, "%02X ", pubinfo->pub_key->data[i]);
                fprintf(stderr, "\n");
            }
        } else {
            DEBUG_LOG(">>>> encoder_encode: pubinfo->pub_key is NULL");
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto end;
        }
        if (ctx->ispem) {
            DEBUG_LOG(">>>> encoder_encode: Serializing PEM public key");
            ret = PEM_write_bio_GOST_PUBLIC_KEY_INFO(out, pubinfo);
            DEBUG_LOG(">>>> encoder_encode: PEM_write_bio_GOST_PUBLIC_KEY_INFO returned ret=%d", ret);
        } else {
            DEBUG_LOG(">>>> encoder_encode: Serializing DER public key");
            der_len = i2d_GOST_PUBLIC_KEY_INFO(pubinfo, &der);
            DEBUG_LOG(">>>> encoder_encode: i2d_GOST_PUBLIC_KEY_INFO returned der_len=%d", der_len);
            if (der_len > 0) {
                DEBUG_LOG(">>>> encoder_encode: Writing %d bytes to BIO", der_len);
                if (der_len <= 32) {
                    DEBUG_LOG(">>>> encoder_encode: DER public key bytes:");
                    for (int i = 0; i < der_len; i++)
                        fprintf(stderr, "%02X ", der[i]);
                    fprintf(stderr, "\n");
                }
                ret = BIO_write(out, der, der_len) == der_len;
                DEBUG_LOG(">>>> encoder_encode: BIO_write returned ret=%d", ret);
#ifdef ENABLE_GOST_DEBUG
                {
                    FILE *f = fopen("/tmp/encoder_pubkey.der", "wb");
                    if (f != NULL) {
                        fwrite(der, 1, der_len, f);
                        fclose(f);
                        DEBUG_LOG(">>>> encoder_encode: Saved public key DER to /tmp/encoder_pubkey.der");
                    } else {
                        DEBUG_LOG(">>>> encoder_encode: Failed to open /tmp/encoder_pubkey.der");
                    }
                }
#endif
            } else {
                DEBUG_LOG(">>>> encoder_encode: i2d_GOST_PUBLIC_KEY_INFO failed");
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
                ERR_print_errors_fp(stderr);
                ret = 0;
            }
        }
    } else {
        DEBUG_LOG(">>>> encoder_encode: Invalid selection=%d or no key available", selection);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        goto end;
    }

end:
    DEBUG_LOG(">>>> encoder_encode: Cleaning up");
    if (der) {
        DEBUG_LOG(">>>> encoder_encode: Freeing der, der_len=%d", der_len);
        OPENSSL_free(der);
    }
    if (privinfo) {
        DEBUG_LOG(">>>> encoder_encode: Freeing privinfo=%p", privinfo);
        GOST_PRIVATE_KEY_INFO_free(privinfo);
    }
    if (pubinfo) {
        DEBUG_LOG(">>>> encoder_encode: Freeing pubinfo=%p", pubinfo);
        GOST_PUBLIC_KEY_INFO_free(pubinfo);
    }
    if (out) {
        DEBUG_LOG(">>>> encoder_encode: Freeing BIO out=%p", out);
        BIO_free(out);
    }
    if (!ret) {
        DEBUG_LOG(">>>> encoder_encode: Operation failed");
        ERR_print_errors_fp(stderr);
    }
    DEBUG_LOG(">>>> encoder_encode: End, ret=%d", ret);
    return ret;
}

static int encoder_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    GOST_ENCODER_CTX *ctx = vctx;
    const char *type = ctx->ispem ? "PEM" : "DER";
    const char *structure = (ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                            "PrivateKeyInfo" : "SubjectPublicKeyInfo";
    const OSSL_PARAM *p;

    DEBUG_LOG(">>>> encoder_set_ctx_params: ctx=%p selection=%d ispem=%d",
              vctx, ctx->selection, ctx->ispem);
    DEBUG_LOG(">>>> encoder_set_ctx_params: Expected type=%s structure=%s", type, structure);
    debug_dump_params(params);

    if (params == NULL) {
        DEBUG_LOG(">>>> encoder_set_ctx_params: params is NULL, returning 1");
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL) {
        const char *t = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &t)) {
            DEBUG_LOG(">>>> encoder_set_ctx_params: Failed to get OSSL_ENCODER_PARAM_OUTPUT_TYPE");
            return 0;
        }
        DEBUG_LOG(">>>> encoder_set_ctx_params: output_type=%s", t);
        if (OPENSSL_strcasecmp(t, "PEM") == 0) {
            ctx->ispem = 1;
            DEBUG_LOG(">>>> encoder_set_ctx_params: Set ispem=1 (PEM)");
        } else if (OPENSSL_strcasecmp(t, "DER") == 0) {
            ctx->ispem = 0;
            DEBUG_LOG(">>>> encoder_set_ctx_params: Set ispem=0 (DER)");
        } else {
            DEBUG_LOG(">>>> encoder_set_ctx_params: Invalid output_type=%s", t);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_STRUCTURE);
    if (p != NULL) {
        const char *s = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &s)) {
            DEBUG_LOG(">>>> encoder_set_ctx_params: Failed to get OSSL_ENCODER_PARAM_STRUCTURE");
            return 0;
        }
        DEBUG_LOG(">>>> encoder_set_ctx_params: structure_param=%s", s);
        if (OPENSSL_strcasecmp(s, structure) != 0) {
            DEBUG_LOG(">>>> encoder_set_ctx_params: Ignoring mismatched structure %s, expected %s", s, structure);
        }
    }

    DEBUG_LOG(">>>> encoder_set_ctx_params: Success");
    return 1;
}

static int encoder_does_selection(void *provctx, int selection)
{
    int allowed = OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    DEBUG_LOG(">>>> encoder_does_selection: provctx=%p selection=%d allowed=%d",
              provctx, selection, allowed);
    if (selection == 0) {
        DEBUG_LOG(">>>> encoder_does_selection: Returning 1 (selection=0)");
        return 1;
    }
    if ((selection & ~allowed) != 0) {
        DEBUG_LOG(">>>> encoder_does_selection: Invalid selection bits=%d (allowed=%d)",
                  selection & ~allowed, allowed);
        return 0;
    }
    int result = (selection & allowed) != 0;
    DEBUG_LOG(">>>> encoder_does_selection: Result=%d (selection & allowed=%d)",
              result, selection & allowed);
    return result;
}

static int encoder_get_params_generic(OSSL_PARAM params[],
                                     const char *output_type,
                                     const char *structure)
{
    OSSL_PARAM *p;

    DEBUG_LOG(">>>> encoder_get_params_generic: output_type=%s structure=%s",
              output_type, structure);
    debug_dump_params(params);

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL) {
        DEBUG_LOG(">>>> encoder_get_params_generic: Setting OSSL_ENCODER_PARAM_OUTPUT_TYPE to %s", output_type);
        if (!OSSL_PARAM_set_utf8_string(p, output_type)) {
            DEBUG_LOG(">>>> encoder_get_params_generic: Failed to set OSSL_ENCODER_PARAM_OUTPUT_TYPE");
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_STRUCTURE);
    if (p != NULL) {
        DEBUG_LOG(">>>> encoder_get_params_generic: Setting OSSL_ENCODER_PARAM_STRUCTURE to %s", structure);
        if (!OSSL_PARAM_set_utf8_string(p, structure)) {
            DEBUG_LOG(">>>> encoder_get_params_generic: Failed to set OSSL_ENCODER_PARAM_STRUCTURE");
            return 0;
        }
    }
    DEBUG_LOG(">>>> encoder_get_params_generic: Success");
    return 1;
}

static int encoder_get_params(void *vctx, OSSL_PARAM params[])
{
    GOST_ENCODER_CTX *ctx = vctx;
    const char *type = ctx->ispem ? "PEM" : "DER";
    const char *structure = (ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                            "PrivateKeyInfo" : "SubjectPublicKeyInfo";
    if (ctx->selection == 0)
        structure = (ctx->init_selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                    "PrivateKeyInfo" : "SubjectPublicKeyInfo";

    DEBUG_LOG(">>>> encoder_get_params: ctx=%p selection=%d ispem=%d init_selection=%d",
              vctx, ctx->selection, ctx->ispem, ctx->init_selection);
    DEBUG_LOG(">>>> encoder_get_params: type=%s structure=%s", type, structure);
    return encoder_get_params_generic(params, type, structure);
}

static const OSSL_PARAM *encoder_gettable_params(void *provctx)
{
    static const OSSL_PARAM known_gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_OUTPUT_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_STRUCTURE, NULL, 0),
        OSSL_PARAM_END
    };
    DEBUG_LOG(">>>> encoder_gettable_params: provctx=%p returning known_gettable", provctx);
    return known_gettable;
}

typedef void (*fptr_t)(void);

#define MAKE_ENCODER_FUNCTIONS(alg, fmt, ispemflag, selflag, suffix)       \
    static void *alg##_##fmt##_##suffix##_encoder_newctx(void *provctx)    \
    {                                                                      \
        DEBUG_LOG(">>>> %s_%s_%s_encoder_newctx: Starting with provctx=%p", \
                  #alg, #fmt, #suffix, provctx);                         \
        GOST_ENCODER_CTX *ctx = encoder_newctx(provctx);                   \
        if (ctx != NULL) {                                                 \
            ctx->ispem = ispemflag;                                        \
            ctx->selection = selflag;                                      \
            ctx->init_selection = selflag;                                 \
            DEBUG_LOG(">>>> %s_%s_%s_encoder_newctx: Set ispem=%d selection=%d init_selection=%d", \
                      #alg, #fmt, #suffix, ctx->ispem, ctx->selection, ctx->init_selection); \
        }                                                                  \
        DEBUG_LOG(">>>> %s_%s_%s_encoder_newctx: Returning ctx=%p",        \
                  #alg, #fmt, #suffix, ctx);                             \
        return ctx;                                                        \
    }                                                                      \
    static const OSSL_DISPATCH alg##_##fmt##_##suffix##_encoder_functions[] = { \
        { OSSL_FUNC_ENCODER_NEWCTX,                                        \
          (fptr_t)alg##_##fmt##_##suffix##_encoder_newctx },               \
        { OSSL_FUNC_ENCODER_FREECTX, (fptr_t)encoder_freectx },            \
        { OSSL_FUNC_ENCODER_ENCODE, (fptr_t)encoder_encode },              \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (fptr_t)encoder_set_ctx_params },\
        { OSSL_FUNC_ENCODER_DOES_SELECTION, (fptr_t)encoder_does_selection },\
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,                               \
          (fptr_t)encoder_gettable_params },                               \
        { OSSL_FUNC_ENCODER_GET_PARAMS, (fptr_t)encoder_get_params },      \
        { 0, NULL }                                                       \
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
    { "gost2001", "provider=gostprov,output=DER,structure=PrivateKeyInfo", gost2001_der_priv_encoder_functions },
    { "gost2001", "provider=gostprov,output=PEM,structure=PrivateKeyInfo", gost2001_pem_priv_encoder_functions },
    { "gost2001", "provider=gostprov,output=DER,structure=SubjectPublicKeyInfo", gost2001_der_pub_encoder_functions },
    { "gost2001", "provider=gostprov,output=PEM,structure=SubjectPublicKeyInfo", gost2001_pem_pub_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=DER,structure=PrivateKeyInfo", gost2012_256_der_priv_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=PEM,structure=PrivateKeyInfo", gost2012_256_pem_priv_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=DER,structure=SubjectPublicKeyInfo", gost2012_256_der_pub_encoder_functions },
    { "gost2012_256", "provider=gostprov,output=PEM,structure=SubjectPublicKeyInfo", gost2012_256_pem_pub_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=DER,structure=PrivateKeyInfo", gost2012_512_der_priv_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=PEM,structure=PrivateKeyInfo", gost2012_512_pem_priv_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=DER,structure=SubjectPublicKeyInfo", gost2012_512_der_pub_encoder_functions },
    { "gost2012_512", "provider=gostprov,output=PEM,structure=SubjectPublicKeyInfo", gost2012_512_pem_pub_encoder_functions },
    { NULL, NULL, NULL }
};
