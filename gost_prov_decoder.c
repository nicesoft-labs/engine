#include <openssl/pem.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_object.h>
#include "gost_prov.h"
#include "gost_lcl.h"
#include "gost_asn1.h"

#ifndef OSSL_DECODER_PARAM_INPUT_TYPE
# define OSSL_DECODER_PARAM_INPUT_TYPE "input-type"
#endif
#ifndef OSSL_DECODER_PARAM_STRUCTURE
# define OSSL_DECODER_PARAM_STRUCTURE "structure"
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
    int ispem;        /* 0 = DER input, 1 = PEM input */
    int init_ispem_flag; /* исходный режим: 0=DER, 1=PEM */
    int selection;    /* expected key selection */
    int init_selection; /* initial selection from newctx */
    int expected_alg_nid; /* NID алгоритма, который этот декодер обязан принимать */
} GOST_DECODER_CTX;

static void *decoder_newctx(void *provctx, int expected_alg_nid, int ispem_flag)
{
    DEBUG_LOG(">>>> decoder_newctx: Creating new GOST_DECODER_CTX for provctx=%p", provctx);
    GOST_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        DEBUG_LOG(">>>> decoder_newctx: Failed to allocate ctx");
        return NULL;
    }
    ctx->provctx = provctx;
    ctx->expected_alg_nid = expected_alg_nid;
    (void)ispem_flag; /* ispem_flag stored by wrapper */
    DEBUG_LOG(">>>> decoder_newctx: ctx=%p provctx=%p", ctx, provctx);
    return ctx;
}

static void decoder_freectx(void *vctx)
{
    DEBUG_LOG(">>>> decoder_freectx: Freeing ctx=%p", vctx);
    OPENSSL_free(vctx);
}

/* Wrapper functions to specify expected algorithm NID for each decoder */
static void *gost2001_der_priv_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2001, 0);
    if (ctx != NULL)
        ctx->init_ispem_flag = 0;
    return ctx;
}
static void *gost2001_der_pub_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2001, 0);
    if (ctx != NULL)
        ctx->init_ispem_flag = 0;
    return ctx;
}
static void *gost2001_pem_priv_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2001, 1);
    if (ctx != NULL)
        ctx->init_ispem_flag = 1;
    return ctx;
}
static void *gost2001_pem_pub_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2001, 1);
    if (ctx != NULL)
        ctx->init_ispem_flag = 1;
    return ctx;
}

static void *gost2012_256_der_priv_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_256, 0);
    if (ctx != NULL)
        ctx->init_ispem_flag = 0;
    return ctx;
}
static void *gost2012_256_der_pub_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_256, 0);
    if (ctx != NULL)
        ctx->init_ispem_flag = 0;
    return ctx;
}
static void *gost2012_256_pem_priv_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_256, 1);
    if (ctx != NULL)
        ctx->init_ispem_flag = 1;
    return ctx;
}
static void *gost2012_256_pem_pub_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_256, 1);
    if (ctx != NULL)
        ctx->init_ispem_flag = 1;
    return ctx;
}

static void *gost2012_512_der_priv_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_512, 0);
    if (ctx != NULL)
        ctx->init_ispem_flag = 0;
    return ctx;
}
static void *gost2012_512_der_pub_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_512, 0);
    if (ctx != NULL)
        ctx->init_ispem_flag = 0;
    return ctx;
}
static void *gost2012_512_pem_priv_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_512, 1);
    if (ctx != NULL)
        ctx->init_ispem_flag = 1;
    return ctx;
}
static void *gost2012_512_pem_pub_decoder_newctx_base(void *provctx)
{
    GOST_DECODER_CTX *ctx = decoder_newctx(provctx, NID_id_GostR3410_2012_512, 1);
    if (ctx != NULL)
        ctx->init_ispem_flag = 1;
    return ctx;
}


/* Map parameter set NID to algorithm NID */
static int param_to_alg_nid(int param_nid)
{
    DEBUG_LOG(">>>> param_to_alg_nid: Mapping param_nid=%d (%s)", param_nid, OBJ_nid2sn(param_nid));
    switch (param_nid) {
    case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
    case NID_id_GostR3410_2001_TestParamSet:
    case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
    case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
        DEBUG_LOG(">>>> param_to_alg_nid: Returning NID_id_GostR3410_2001=%d", NID_id_GostR3410_2001);
        return NID_id_GostR3410_2001;

    case NID_id_tc26_gost_3410_2012_256_paramSetA:
    case NID_id_tc26_gost_3410_2012_256_paramSetB:
    case NID_id_tc26_gost_3410_2012_256_paramSetC:
    case NID_id_tc26_gost_3410_2012_256_paramSetD:
        DEBUG_LOG(">>>> param_to_alg_nid: Returning NID_id_GostR3410_2012_256=%d", NID_id_GostR3410_2012_256);
        return NID_id_GostR3410_2012_256;

    case NID_id_tc26_gost_3410_2012_512_paramSetA:
    case NID_id_tc26_gost_3410_2012_512_paramSetB:
    case NID_id_tc26_gost_3410_2012_512_paramSetC:
        DEBUG_LOG(">>>> param_to_alg_nid: Returning NID_id_GostR3410_2012_512=%d", NID_id_GostR3410_2012_512);
        return NID_id_GostR3410_2012_512;
    }
    DEBUG_LOG(">>>> param_to_alg_nid: Returning NID_undef=%d", NID_undef);
    return NID_undef;
}

static const char *alg_nid2name(int nid)
{
    DEBUG_LOG(">>>> alg_nid2name: Mapping nid=%d (%s)", nid, OBJ_nid2sn(nid));
    switch (nid) {
    case NID_id_GostR3410_2001:
        DEBUG_LOG(">>>> alg_nid2name: Returning gost2001");
        return "gost2001";
    case NID_id_GostR3410_2012_256:
        DEBUG_LOG(">>>> alg_nid2name: Returning gost2012_256");
        return "gost2012_256";
    case NID_id_GostR3410_2012_512:
        DEBUG_LOG(">>>> alg_nid2name: Returning gost2012_512");
        return "gost2012_512";
    }
    DEBUG_LOG(">>>> alg_nid2name: Returning NULL");
    return NULL;
}

/*
 * Parse AlgorithmIdentifier and extract algorithm and parameter OIDs.
 * Returns 1 on success with *alg_nid and *param_nid set.
 */
static int parse_algor(const X509_ALGOR *algor, int *alg_nid, int *param_nid)
{
    const ASN1_OBJECT *algobj = NULL;
    int ptype = V_ASN1_UNDEF;
    const ASN1_STRING *pval = NULL;
    const unsigned char *p;
    GOST_KEY_PARAMS *gkp = NULL;
    char buf[128];

    DEBUG_LOG(">>>> parse_algor: Starting with algor=%p", algor);
    if (algor == NULL) {
        DEBUG_LOG(">>>> parse_algor: algor is NULL");
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    X509_ALGOR_get0(&algobj, &ptype, (const void **)&pval, algor);
    DEBUG_LOG(">>>> parse_algor: algobj=%p ptype=%d pval=%p", algobj, ptype, pval);

    if (algobj != NULL) {
        OBJ_obj2txt(buf, sizeof(buf), algobj, 1);
        *alg_nid = OBJ_obj2nid(algobj);
        DEBUG_LOG(">>>> parse_algor: algobj OID=%s alg_nid=%d (%s)", buf, *alg_nid, OBJ_nid2sn(*alg_nid));
        if (*alg_nid == NID_undef ||
            (*alg_nid != NID_id_GostR3410_2001 &&
             *alg_nid != NID_id_GostR3410_2012_256 &&
             *alg_nid != NID_id_GostR3410_2012_512)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                           "unknown algorithm OID %s", OBJ_nid2sn(*alg_nid));
            DEBUG_LOG(">>>> parse_algor: Unsupported alg_nid=%d", *alg_nid);
            return 0;
        }
    } else {
        DEBUG_LOG(">>>> parse_algor: algobj is NULL");
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    if (ptype != V_ASN1_SEQUENCE || pval == NULL) {
        DEBUG_LOG(">>>> parse_algor: Invalid ptype=%d or pval=%p (expected V_ASN1_SEQUENCE)", ptype, pval);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    p = pval->data;
    DEBUG_LOG(">>>> parse_algor: Decoding GOST_KEY_PARAMS, pval->length=%d", pval->length);
    if (pval->length > 0) {
        DEBUG_LOG(">>>> parse_algor: First 16 bytes of pval->data:");
        for (int i = 0; i < pval->length && i < 16; i++)
            fprintf(stderr, "%02X ", pval->data[i]);
        fprintf(stderr, "\n");
    }
    gkp = d2i_GOST_KEY_PARAMS(NULL, &p, pval->length);
    if (gkp == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        DEBUG_LOG(">>>> parse_algor: Failed to decode GOST_KEY_PARAMS");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    OBJ_obj2txt(buf, sizeof(buf), gkp->key_params, 1);
    *param_nid = OBJ_obj2nid(gkp->key_params);
    DEBUG_LOG(">>>> parse_algor: key_params OID=%s param_nid=%d (%s)", buf, *param_nid, OBJ_nid2sn(*param_nid));
    if (*param_nid == NID_undef) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        DEBUG_LOG(">>>> parse_algor: Invalid param_nid=%d", *param_nid);
        GOST_KEY_PARAMS_free(gkp);
        return 0;
    }
    int expected_alg_nid = param_to_alg_nid(*param_nid);
    DEBUG_LOG(">>>> parse_algor: expected_alg_nid=%d (%s) from param_nid=%d", expected_alg_nid, OBJ_nid2sn(expected_alg_nid), *param_nid);
    if (expected_alg_nid != NID_undef && expected_alg_nid != *alg_nid) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        DEBUG_LOG(">>>> parse_algor: alg_nid=%d (%s) does not match expected_alg_nid=%d (%s)",
                  *alg_nid, OBJ_nid2sn(*alg_nid), expected_alg_nid, OBJ_nid2sn(expected_alg_nid));
        GOST_KEY_PARAMS_free(gkp);
        return 0;
    }

    GOST_KEY_PARAMS_free(gkp);
    DEBUG_LOG(">>>> parse_algor: Success, alg_nid=%d (%s) param_nid=%d (%s)",
              *alg_nid, OBJ_nid2sn(*alg_nid), *param_nid, OBJ_nid2sn(*param_nid));
    return 1;
}

static int read_der_from_bio(GOST_DECODER_CTX *ctx, OSSL_CORE_BIO *cin,
                             unsigned char **der, long *der_len, char **pem_name)
{
    BIO *in = NULL;
    BIO *mem = NULL;
    int ok = 0;

    DEBUG_LOG(">>>> read_der_from_bio: Starting with ctx=%p cin=%p", ctx, cin);
    if (ctx == NULL || cin == NULL) {
        DEBUG_LOG(">>>> read_der_from_bio: Invalid ctx=%p or cin=%p", ctx, cin);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    in = BIO_new_from_core_bio(ctx->provctx->libctx, cin);
    if (in == NULL) {
        DEBUG_LOG(">>>> read_der_from_bio: Failed to create BIO from core_bio");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    DEBUG_LOG(">>>> read_der_from_bio: ispem=%d", ctx->ispem);

    if (ctx->ispem) {
        char *label = NULL;
        char *header = NULL;
        DEBUG_LOG(">>>> read_der_from_bio: Reading PEM block");
        ok = PEM_read_bio(in, &label, &header, der, der_len) > 0;
        DEBUG_LOG(">>>> read_der_from_bio: PEM_read_bio returned ok=%d label=%s header=%s der_len=%ld",
                  ok, label ? label : "NULL", header ? header : "NULL", *der_len);
        OPENSSL_free(header);
        if (!ok) {
            DEBUG_LOG(">>>> read_der_from_bio: Failed to read PEM block");
            ERR_print_errors_fp(stderr);
            goto end;
        }

        if (strcmp(label, PEM_STRING_PKCS8INF) == 0 ||
            strcmp(label, PEM_STRING_PKCS8) == 0 ||
            strcmp(label, PEM_STRING_PUBLIC) == 0) {
            *pem_name = label;
            DEBUG_LOG(">>>> read_der_from_bio: Recognized PEM header=%s", label);
        } else {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
                           "unknown PEM header %s", label);
            DEBUG_LOG(">>>> read_der_from_bio: Unknown PEM header=%s", label);
            OPENSSL_free(label);
            ok = 0;
            goto end;
        }
    } else {
        char tbuf[4096];
        size_t n;
        DEBUG_LOG(">>>> read_der_from_bio: Reading DER data");
        mem = BIO_new(BIO_s_mem());
        if (mem == NULL) {
            DEBUG_LOG(">>>> read_der_from_bio: Failed to create memory BIO");
            ERR_print_errors_fp(stderr);
            goto end;
        }

        while (BIO_read_ex(in, tbuf, sizeof(tbuf), &n) && n > 0) {
            BIO_write(mem, tbuf, n);
            DEBUG_LOG(">>>> read_der_from_bio: Read %zu bytes from BIO", n);
        }

        char *tmpbuf = NULL;
        long tmplen = BIO_get_mem_data(mem, &tmpbuf);
        DEBUG_LOG(">>>> read_der_from_bio: BIO_get_mem_data returned tmplen=%ld", tmplen);
        if (tmplen <= 0) {
            DEBUG_LOG(">>>> read_der_from_bio: No data read from BIO");
            goto end;
        }
        *der = OPENSSL_memdup(tmpbuf, tmplen);
        *der_len = tmplen;
        ok = *der != NULL;
        if (!ok) {
            DEBUG_LOG(">>>> read_der_from_bio: Failed to allocate DER buffer");
            ERR_print_errors_fp(stderr);
        } else {
            DEBUG_LOG(">>>> read_der_from_bio: Allocated DER buffer, der_len=%ld", *der_len);
            if (*der_len > 0) {
                DEBUG_LOG(">>>> read_der_from_bio: First 32 bytes of DER:");
                for (size_t i = 0; i < (size_t)*der_len && i < 32; i++)
                    fprintf(stderr, "%02X ", (*der)[i]);
                fprintf(stderr, "\n");
            }
        }
    }

end:
    DEBUG_LOG(">>>> read_der_from_bio: Cleaning up, ok=%d der_len=%ld pem_name=%s",
              ok, *der_len, pem_name ? *pem_name : "NULL");
    BIO_free(in);
    BIO_free(mem);
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
    unsigned char *privbuf = NULL;
    int alg_nid = NID_undef, param_nid = NID_undef;
    GOST_KEYMGMT_CTX *gctx = NULL;
    const char *keytype = NULL;
    OSSL_PARAM params[4];
    size_t pidx = 0;
    int ok = 0;
    int sel = 0;

    DEBUG_LOG(">>>> decoder_decode: Starting with ctx=%p cin=%p selection=%d", vctx, cin, selection);
    DEBUG_LOG(">>>> decoder_decode: ctx->provctx=%p ctx->ispem=%d ctx->selection=%d ctx->init_selection=%d",
              ctx->provctx, ctx->ispem, ctx->selection, ctx->init_selection);
    DEBUG_LOG(">>>> decoder_decode: data_cb=%p data_cbarg=%p cb=%p cbarg=%p",
              data_cb, data_cbarg, cb, cbarg);

    if (ctx == NULL || cin == NULL) {
        DEBUG_LOG(">>>> decoder_decode: Invalid ctx=%p or cin=%p", ctx, cin);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        goto end;
    }

    if (selection != 0) {
        ctx->selection = selection;
        DEBUG_LOG(">>>> decoder_decode: Updated ctx->selection to %d", ctx->selection);
    }

    const char *type = ctx->ispem ? "PEM" : "DER";
    const char *structure = (ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                            "PrivateKeyInfo" : "SubjectPublicKeyInfo";
    DEBUG_LOG(">>>> decoder_decode: Processing type=%s structure=%s", type, structure);

    /* Read input data */
    DEBUG_LOG(">>>> decoder_decode: Calling read_der_from_bio");
    if (!read_der_from_bio(ctx, cin, &der, &der_len, &pem_name)) {
        DEBUG_LOG(">>>> decoder_decode: read_der_from_bio failed");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    DEBUG_LOG(">>>> decoder_decode: read_der_from_bio returned der_len=%ld pem_name=%s",
              der_len, pem_name ? pem_name : "NULL");

    /* Save DER for analysis */
#ifdef ENABLE_GOST_DEBUG
    {
        FILE *f = fopen("/tmp/decoder_input.der", "wb");
        if (f != NULL) {
            fwrite(der, 1, der_len, f);
            fclose(f);
            DEBUG_LOG(">>>> decoder_decode: Saved input DER to /tmp/decoder_input.der");
        } else {
            DEBUG_LOG(">>>> decoder_decode: Failed to open /tmp/decoder_input.der for writing");
        }
    }
#endif

    /* Create key management context */
    DEBUG_LOG(">>>> decoder_decode: Creating gctx with gost_keymgmt_new");
    gctx = gost_keymgmt_new(ctx->provctx);
    if (gctx == NULL) {
        DEBUG_LOG(">>>> decoder_decode: gost_keymgmt_new failed");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    DEBUG_LOG(">>>> decoder_decode: Created gctx=%p", gctx);

    p = der;

    /* Try decoding private key */
    if ((ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 || ctx->selection == 0) {
        DEBUG_LOG(">>>> decoder_decode: Attempting to decode PrivateKeyInfo");
        priv = d2i_GOST_PRIVATE_KEY_INFO(NULL, &p, der_len);
        if (priv == NULL) {
            DEBUG_LOG(">>>> decoder_decode: d2i_GOST_PRIVATE_KEY_INFO returned NULL, trying EncryptedPrivateKeyInfo");
            p = der;
            X509_SIG *epki = d2i_X509_SIG(NULL, &p, der_len);
            if (epki != NULL) {
                DEBUG_LOG(">>>> decoder_decode: Decoded EncryptedPrivateKeyInfo, attempting decryption");
                char pass[1024];
                size_t passlen = 0;
                if (cb == NULL || cb(pass, sizeof(pass), &passlen, NULL, cbarg) <= 0) {
                    ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
                    DEBUG_LOG(">>>> decoder_decode: Passphrase callback failed");
                    X509_SIG_free(epki);
                    goto end;
                }
                DEBUG_LOG(">>>> decoder_decode: Passphrase provided, length=%zu", passlen);
                PKCS8_PRIV_KEY_INFO *p8inf = PKCS8_decrypt_ex(epki, pass, (int)passlen,
                                                               ctx->provctx->libctx, NULL);
                OPENSSL_cleanse(pass, sizeof(pass));
                X509_SIG_free(epki);
                if (p8inf != NULL) {
                    DEBUG_LOG(">>>> decoder_decode: Decrypted PKCS8_PRIV_KEY_INFO");
                    unsigned char *tmp = NULL;
                    int tmplen = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &tmp);
                    DEBUG_LOG(">>>> decoder_decode: i2d_PKCS8_PRIV_KEY_INFO returned tmplen=%d", tmplen);
                    const unsigned char *q = tmp;
                    PKCS8_PRIV_KEY_INFO_free(p8inf);
                    if (tmplen > 0) {
                        priv = d2i_GOST_PRIVATE_KEY_INFO(NULL, &q, tmplen);
                        DEBUG_LOG(">>>> decoder_decode: d2i_GOST_PRIVATE_KEY_INFO from PKCS8 returned priv=%p", priv);
                        OPENSSL_clear_free(tmp, tmplen);
                    } else {
                        DEBUG_LOG(">>>> decoder_decode: i2d_PKCS8_PRIV_KEY_INFO failed");
                        OPENSSL_free(tmp);
                    }
                } else {
                    DEBUG_LOG(">>>> decoder_decode: PKCS8_decrypt_ex failed");
                    ERR_print_errors_fp(stderr);
                }
                if (priv == NULL) {
                    ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
                    DEBUG_LOG(">>>> decoder_decode: Failed to obtain GOST_PRIVATE_KEY_INFO");
                    goto end;
                }
            } else {
                DEBUG_LOG(">>>> decoder_decode: d2i_X509_SIG returned NULL");
                ERR_print_errors_fp(stderr);
            }
        } else {
            DEBUG_LOG(">>>> decoder_decode: Successfully decoded GOST_PRIVATE_KEY_INFO priv=%p", priv);
        }

        if (priv != NULL && parse_algor(priv->algor, &alg_nid, &param_nid)) {
            if (ctx->expected_alg_nid != NID_undef && alg_nid != ctx->expected_alg_nid) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
                goto end;
            }
            DEBUG_LOG(">>>> decoder_decode: parse_algor for PrivateKeyInfo succeeded, alg_nid=%d (%s) param_nid=%d (%s)",
                      alg_nid, OBJ_nid2sn(alg_nid), param_nid, OBJ_nid2sn(param_nid));
            int klen = priv->priv_key->length;
            DEBUG_LOG(">>>> decoder_decode: Private key length=%d", klen);
            privbuf = OPENSSL_malloc(klen);
            if (privbuf == NULL) {
                DEBUG_LOG(">>>> decoder_decode: Failed to allocate privbuf");
                ERR_print_errors_fp(stderr);
                goto end;
            }
            for (int i = 0; i < klen; i++)
                privbuf[i] = priv->priv_key->data[klen - 1 - i];
            DEBUG_LOG(">>>> decoder_decode: Reversed private key bytes");
            params[pidx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, privbuf, klen);
            sel |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
            DEBUG_LOG(">>>> decoder_decode: Added private key param, sel=%d pidx=%zu", sel, pidx);
        }
    }

    /* Try decoding public key */
    if (priv == NULL && ((ctx->selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 || ctx->selection == 0)) {
        DEBUG_LOG(">>>> decoder_decode: Attempting to decode SubjectPublicKeyInfo, der_len=%ld", der_len);
        if (der_len > 0) {
            DEBUG_LOG(">>>> decoder_decode: First %ld bytes of DER:", der_len < 32 ? der_len : 32);
            for (size_t i = 0; i < (size_t)der_len && i < 32; i++)
                fprintf(stderr, "%02X ", der[i]);
            fprintf(stderr, "\n");
        }
#ifdef ENABLE_GOST_DEBUG
        {
            FILE *f = fopen("/tmp/pubkey.der", "wb");
            if (f != NULL) {
                fwrite(der, 1, der_len, f);
                fclose(f);
                DEBUG_LOG(">>>> decoder_decode: Saved DER to /tmp/pubkey.der");
            } else {
                DEBUG_LOG(">>>> decoder_decode: Failed to open /tmp/pubkey.der for writing");
            }
        }
#endif
        p = der;
        DEBUG_LOG(">>>> decoder_decode: Calling d2i_GOST_PUBLIC_KEY_INFO with p=%p der_len=%ld", p, der_len);
        pub = d2i_GOST_PUBLIC_KEY_INFO(NULL, &p, der_len);
        if (pub == NULL) {
            DEBUG_LOG(">>>> decoder_decode: d2i_GOST_PUBLIC_KEY_INFO returned NULL");
            ERR_print_errors_fp(stderr);
            goto end;
        }
        DEBUG_LOG(">>>> decoder_decode: Decoded GOST_PUBLIC_KEY_INFO pub=%p", pub);
        DEBUG_LOG(">>>> decoder_decode: pub->algor=%p pub->pub_key=%p pub_key_len=%d",
                  pub->algor, pub->pub_key, pub->pub_key ? pub->pub_key->length : 0);
        int alg_ok = parse_algor(pub->algor, &alg_nid, &param_nid);
        if (alg_ok && ctx->expected_alg_nid != NID_undef && alg_nid != ctx->expected_alg_nid) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto end;
        }
        DEBUG_LOG(">>>> decoder_decode: parse_algor returned %d alg_nid=%d (%s) param_nid=%d (%s)",
                  alg_ok, alg_nid, OBJ_nid2sn(alg_nid), param_nid, OBJ_nid2sn(param_nid));
        if (alg_ok && pub->pub_key != NULL && pub->pub_key->length > 0) {
            params[pidx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                              pub->pub_key->data,
                                                              pub->pub_key->length);
            sel |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
            DEBUG_LOG(">>>> decoder_decode: Added public key param, sel=%d pidx=%zu pub_key_len=%d",
                      sel, pidx, pub->pub_key->length);
            if (pub->pub_key->length > 0) {
                DEBUG_LOG(">>>> decoder_decode: First %d bytes of pub_key:", pub->pub_key->length < 16 ? pub->pub_key->length : 16);
                for (int i = 0; i < pub->pub_key->length && i < 16; i++)
                    fprintf(stderr, "%02X ", pub->pub_key->data[i]);
                fprintf(stderr, "\n");
            }
        } else {
            DEBUG_LOG(">>>> decoder_decode: Invalid public key data or parse_algor failed");
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            goto end;
        }
    }

    if (alg_nid == NID_undef || param_nid == NID_undef) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        DEBUG_LOG(">>>> decoder_decode: Invalid alg_nid=%d (%s) or param_nid=%d (%s)",
                  alg_nid, OBJ_nid2sn(alg_nid), param_nid, OBJ_nid2sn(param_nid));
        goto end;
    }

    /* Try to get the key type name directly from the algorithm NID */
    keytype = alg_nid2name(alg_nid);
    DEBUG_LOG(">>>> decoder_decode: alg_nid=%d keytype=%s", alg_nid,
              keytype != NULL ? keytype : "(null)");

    /* Fallback to mapping the parameter set to an algorithm NID */
    if (keytype == NULL && param_nid != NID_undef) {
        int mapped_nid = param_to_alg_nid(param_nid);
        DEBUG_LOG(">>>> decoder_decode: mapped param_nid=%d to alg_nid=%d",
                  param_nid, mapped_nid);
        keytype = alg_nid2name(mapped_nid);
    }

    if (keytype == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        DEBUG_LOG(">>>> decoder_decode: Failed to determine keytype for alg_nid=%d param_nid=%d",
                  alg_nid, param_nid);
        goto end;
    }
    DEBUG_LOG(">>>> decoder_decode: keytype=%s", keytype);

    params[pidx++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                     (char *)OBJ_nid2sn(param_nid), 0);
    params[pidx] = OSSL_PARAM_construct_end();
    DEBUG_LOG(">>>> decoder_decode: Constructed params, pidx=%zu", pidx);
    debug_dump_params(params);

    DEBUG_LOG(">>>> decoder_decode: Importing key with sel=%d ctx->selection=%d", sel, ctx->selection);
    if ((sel & ctx->selection) == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        DEBUG_LOG(">>>> decoder_decode: Selection mismatch: sel=%d ctx->selection=%d", sel, ctx->selection);
        goto end;
    }

    DEBUG_LOG(">>>> decoder_decode: Calling gost_import with gctx=%p sel=%d", gctx, sel);
    if (!gost_import(gctx, sel, params)) {
        DEBUG_LOG(">>>> decoder_decode: gost_import failed");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    if (gctx->ec == NULL) {
        DEBUG_LOG(">>>> decoder_decode: gctx->ec is NULL after import");
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        goto end;
    }
    DEBUG_LOG(">>>> decoder_decode: Key import successful, gctx->ec=%p", gctx->ec);

    {
        int objtype = OSSL_OBJECT_PKEY;
        OSSL_PARAM out[4];
        DEBUG_LOG(">>>> decoder_decode: Preparing output params");
        out[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &objtype);
        out[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)keytype, 0);
        out[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &gctx, sizeof(gctx));
        out[3] = OSSL_PARAM_construct_end();
        DEBUG_LOG(">>>> decoder_decode: Output params constructed");
        debug_dump_params(out);
        DEBUG_LOG(">>>> decoder_decode: Calling data_cb with out=%p data_cbarg=%p", out, data_cbarg);
        ok = data_cb(out, data_cbarg);
        DEBUG_LOG(">>>> decoder_decode: data_cb returned ok=%d", ok);
        if (!ok) {
            DEBUG_LOG(">>>> decoder_decode: data_cb failed");
            ERR_print_errors_fp(stderr);
        }
    }

end:
    DEBUG_LOG(">>>> decoder_decode: Cleaning up");
    if (pem_name) {
        DEBUG_LOG(">>>> decoder_decode: Freeing pem_name=%s", pem_name);
        OPENSSL_free(pem_name);
    }
    if (der) {
        DEBUG_LOG(">>>> decoder_decode: Freeing der, der_len=%ld", der_len);
        OPENSSL_free(der);
    }
    if (privbuf) {
        DEBUG_LOG(">>>> decoder_decode: Freeing privbuf");
        OPENSSL_free(privbuf);
    }
    if (priv) {
        DEBUG_LOG(">>>> decoder_decode: Freeing priv=%p", priv);
        GOST_PRIVATE_KEY_INFO_free(priv);
    }
    if (pub) {
        DEBUG_LOG(">>>> decoder_decode: Freeing pub=%p", pub);
        GOST_PUBLIC_KEY_INFO_free(pub);
    }
    if (!ok) {
        DEBUG_LOG(">>>> decoder_decode: Operation failed, freeing gctx=%p", gctx);
        ERR_print_errors_fp(stderr);
        gost_keymgmt_free(gctx);
    }
    DEBUG_LOG(">>>> decoder_decode: End, ok=%d", ok);
    return ok;
}

static int decoder_export_object(void *vctx, const void *reference, size_t reference_sz,
                                 OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    GOST_DECODER_CTX *ctx = vctx;
    GOST_KEYMGMT_CTX *keydata;

    DEBUG_LOG(">>>> decoder_export_object: Starting with ctx=%p reference=%p reference_sz=%zu",
              vctx, reference, reference_sz);
    DEBUG_LOG(">>>> decoder_export_object: export_cb=%p export_cbarg=%p", export_cb, export_cbarg);

    if (reference_sz != sizeof(keydata)) {
        DEBUG_LOG(">>>> decoder_export_object: Invalid reference_sz=%zu, expected %zu",
                  reference_sz, sizeof(keydata));
        return 0;
    }

    keydata = *(GOST_KEYMGMT_CTX **)reference;
    if (keydata == NULL || keydata->ec == NULL) {
        DEBUG_LOG(">>>> decoder_export_object: No keydata or keydata->ec is NULL");
        return 0;
    }
    DEBUG_LOG(">>>> decoder_export_object: keydata=%p keydata->ec=%p", keydata, keydata->ec);

    if (ctx->selection == 0) {
        ctx->selection = OSSL_KEYMGMT_SELECT_ALL;
        DEBUG_LOG(">>>> decoder_export_object: Set ctx->selection to OSSL_KEYMGMT_SELECT_ALL");
    }

    DEBUG_LOG(">>>> decoder_export_object: Calling gost_export with selection=%d", ctx->selection);
    int ret = gost_export(keydata, ctx->selection, export_cb, export_cbarg);
    DEBUG_LOG(">>>> decoder_export_object: gost_export returned ret=%d", ret);
    return ret;
}

static int decoder_does_selection(void *vctx, int selection)
{
    GOST_DECODER_CTX *ctx = vctx;
    int allowed = ctx->selection;

    DEBUG_LOG(">>>> decoder_does_selection: ctx=%p selection=%d allowed=%d", vctx, selection, allowed);
    if (selection == 0 || allowed == 0) {
        DEBUG_LOG(">>>> decoder_does_selection: Returning 1 (selection=0 or allowed=0)");
        return 1;
    }
    int result = (selection & allowed) == selection;
    DEBUG_LOG(">>>> decoder_does_selection: Result=%d (selection & allowed = %d)", result, selection & allowed);
    return result;
}

static int decoder_get_params_generic(OSSL_PARAM params[], const char *input_type, const char *structure)
{
    OSSL_PARAM *p;

    DEBUG_LOG(">>>> decoder_get_params_generic: input_type=%s structure=%s", input_type, structure);
    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL) {
        DEBUG_LOG(">>>> decoder_get_params_generic: Setting OSSL_DECODER_PARAM_INPUT_TYPE to %s", input_type);
        if (!OSSL_PARAM_set_utf8_string(p, input_type)) {
            DEBUG_LOG(">>>> decoder_get_params_generic: Failed to set OSSL_DECODER_PARAM_INPUT_TYPE");
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_STRUCTURE);
    if (p != NULL) {
        DEBUG_LOG(">>>> decoder_get_params_generic: Setting OSSL_DECODER_PARAM_STRUCTURE to %s", structure);
        if (!OSSL_PARAM_set_utf8_string(p, structure)) {
            DEBUG_LOG(">>>> decoder_get_params_generic: Failed to set OSSL_DECODER_PARAM_STRUCTURE");
            return 0;
        }
    }
    DEBUG_LOG(">>>> decoder_get_params_generic: Success");
    return 1;
}

static int decoder_get_params(void *vctx, OSSL_PARAM params[])
{
    GOST_DECODER_CTX *ctx = vctx;
    const char *type = ctx->ispem ? "PEM" : "DER";
    const char *init_type = ctx->init_ispem_flag ? "PEM" : "DER";
    const char *structure = (ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                            "PrivateKeyInfo" : "SubjectPublicKeyInfo";
    if (ctx->selection == 0)
        structure = (ctx->init_selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                    "PrivateKeyInfo" : "SubjectPublicKeyInfo";

    DEBUG_LOG(">>>> decoder_get_params: ctx=%p selection=%d ispem=%d init_selection=%d",
              vctx, ctx->selection, ctx->ispem, ctx->init_selection);
    DEBUG_LOG(">>>> decoder_get_params: type=%s structure=%s", type, structure);
    debug_dump_params(params);
    int ret = decoder_get_params_generic(params, type, structure);
    DEBUG_LOG(">>>> decoder_get_params: decoder_get_params_generic returned %d", ret);
    return ret;
}

static const OSSL_PARAM *decoder_gettable_params(void *provctx)
{
    static const OSSL_PARAM known_gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_DECODER_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_DECODER_PARAM_STRUCTURE, NULL, 0),
        OSSL_PARAM_END
    };
    DEBUG_LOG(">>>> decoder_gettable_params: provctx=%p returning known_gettable", provctx);
    return known_gettable;
}

static int decoder_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    GOST_DECODER_CTX *ctx = vctx;
    const char *type = ctx->ispem ? "PEM" : "DER";
    const char *structure = (ctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                            "PrivateKeyInfo" : "SubjectPublicKeyInfo";
    const char *init_structure = (ctx->init_selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 ?
                                "PrivateKeyInfo" : "SubjectPublicKeyInfo";
    const OSSL_PARAM *p;

    DEBUG_LOG(">>>> decoder_set_ctx_params: ctx=%p selection=%d ispem=%d",
              vctx, ctx->selection, ctx->ispem);
    DEBUG_LOG(">>>> decoder_set_ctx_params: Expected type=%s structure=%s", type, structure);
    debug_dump_params(params);

    if (params == NULL) {
        DEBUG_LOG(">>>> decoder_set_ctx_params: params is NULL, returning 1");
        return 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL) {
        const char *t = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &t)) {
            DEBUG_LOG(">>>> decoder_set_ctx_params: Failed to get OSSL_DECODER_PARAM_INPUT_TYPE");
            return 0;
        }
        DEBUG_LOG(">>>> decoder_set_ctx_params: input_type=%s", t);
        if (OPENSSL_strcasecmp(t, init_type) != 0)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_DECODER_PARAM_STRUCTURE);
    if (p != NULL) {
        const char *s = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &s)) {
            DEBUG_LOG(">>>> decoder_set_ctx_params: Failed to get OSSL_DECODER_PARAM_STRUCTURE");
            return 0;
        }
        DEBUG_LOG(">>>> decoder_set_ctx_params: structure_param=%s", s);
        if (OPENSSL_strcasecmp(s, init_structure) != 0)
            return 0;
    }

    DEBUG_LOG(">>>> decoder_set_ctx_params: Success");
    return 1;
}

static const OSSL_PARAM *decoder_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM known_settable[] = {
        OSSL_PARAM_utf8_string(OSSL_DECODER_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_DECODER_PARAM_STRUCTURE, NULL, 0),
        OSSL_PARAM_END
    };
    DEBUG_LOG(">>>> decoder_settable_ctx_params: provctx=%p returning known_settable", provctx);
    return known_settable;
}

typedef void (*fptr_t)(void);

#define MAKE_DECODER_FUNCTIONS(alg, newctx_fn, fmt, ispemflag, selflag, suffix)        \
    static void *alg##_##fmt##_##suffix##_decoder_newctx(void *provctx)    \
    {                                                                      \
        DEBUG_LOG(">>>> %s_%s_%s_decoder_newctx: Starting with provctx=%p", #alg, #fmt, #suffix, provctx); \
        GOST_DECODER_CTX *ctx = newctx_fn(provctx);                        \
        if (ctx != NULL) {                                                 \
            ctx->ispem = ispemflag;                                        \
            ctx->selection = selflag;                                      \
            ctx->init_selection = selflag;                                 \
            DEBUG_LOG(">>>> %s_%s_%s_decoder_newctx: Set ispem=%d selection=%d init_selection=%d", \
                      #alg, #fmt, #suffix, ctx->ispem, ctx->selection, ctx->init_selection); \
        }                                                                  \
        DEBUG_LOG(">>>> %s_%s_%s_decoder_newctx: Returning ctx=%p", #alg, #fmt, #suffix, ctx); \
        return ctx;                                                        \
    }                                                                      \
    static int alg##_##fmt##_##suffix##_decoder_does_selection(            \
        void *provctx, int selection)                                     \
    {                                                                      \
        DEBUG_LOG(">>>> %s_%s_%s_decoder_does_selection: Starting with provctx=%p selection=%d", \
                  #alg, #fmt, #suffix, provctx, selection);              \
        int result;                                                        \
        if (selection == 0 || selflag == 0)                                \
            result = 1;                                                    \
        else                                                               \
            result = (selection & selflag) != 0;                           \
        DEBUG_LOG(">>>> %s_%s_%s_decoder_does_selection: selflag=%d selection=%d result=%d", \
                  #alg, #fmt, #suffix, selflag, selection, result);       \
        return result;                                                     \
    }                                                                      \
    static const OSSL_DISPATCH alg##_##fmt##_##suffix##_decoder_functions[] = { \
        { OSSL_FUNC_DECODER_NEWCTX,                                         \
          (fptr_t)alg##_##fmt##_##suffix##_decoder_newctx },                \
        { OSSL_FUNC_DECODER_FREECTX, (fptr_t)decoder_freectx },             \
        { OSSL_FUNC_DECODER_DECODE, (fptr_t)decoder_decode },               \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT, (fptr_t)decoder_export_object }, \
        { OSSL_FUNC_DECODER_DOES_SELECTION, (fptr_t)alg##_##fmt##_##suffix##_decoder_does_selection },\
        { OSSL_FUNC_DECODER_GETTABLE_PARAMS, (fptr_t)decoder_gettable_params },\
        { OSSL_FUNC_DECODER_GET_PARAMS, (fptr_t)decoder_get_params },        \
        { OSSL_FUNC_DECODER_SET_CTX_PARAMS, (fptr_t)decoder_set_ctx_params },\
        { OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,                             \
          (fptr_t)decoder_settable_ctx_params },                            \
        { 0, NULL }                                                        \
    }

MAKE_DECODER_FUNCTIONS(gost2001, gost2001_der_priv_decoder_newctx_base, der, 0, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_DECODER_FUNCTIONS(gost2001, gost2001_pem_priv_decoder_newctx_base, pem, 1, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_DECODER_FUNCTIONS(gost2001, gost2001_der_pub_decoder_newctx_base, der, 0, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);
MAKE_DECODER_FUNCTIONS(gost2001, gost2001_pem_pub_decoder_newctx_base, pem, 1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);

MAKE_DECODER_FUNCTIONS(gost2012_256, gost2012_256_der_priv_decoder_newctx_base, der, 0, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_DECODER_FUNCTIONS(gost2012_256, gost2012_256_pem_priv_decoder_newctx_base, pem, 1, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_DECODER_FUNCTIONS(gost2012_256, gost2012_256_der_pub_decoder_newctx_base, der, 0, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);
MAKE_DECODER_FUNCTIONS(gost2012_256, gost2012_256_pem_pub_decoder_newctx_base, pem, 1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);

MAKE_DECODER_FUNCTIONS(gost2012_512, gost2012_512_der_priv_decoder_newctx_base, der, 0, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_DECODER_FUNCTIONS(gost2012_512, gost2012_512_pem_priv_decoder_newctx_base, pem, 1, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, priv);
MAKE_DECODER_FUNCTIONS(gost2012_512, gost2012_512_der_pub_decoder_newctx_base, der, 0, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);
MAKE_DECODER_FUNCTIONS(gost2012_512, gost2012_512_pem_pub_decoder_newctx_base, pem, 1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, pub);

const OSSL_ALGORITHM GOST_prov_decoders[] = {
    { "gost2001", "provider=gostprov,input=DER,structure=PrivateKeyInfo", gost2001_der_priv_decoder_functions },
    { "gost2001", "provider=gostprov,input=PEM,structure=PrivateKeyInfo", gost2001_pem_priv_decoder_functions },
    { "gost2001", "provider=gostprov,input=DER,structure=SubjectPublicKeyInfo", gost2001_der_pub_decoder_functions },
    { "gost2001", "provider=gostprov,input=PEM,structure=SubjectPublicKeyInfo", gost2001_pem_pub_decoder_functions },

    { "gost2012_256", "provider=gostprov,input=DER,structure=PrivateKeyInfo", gost2012_256_der_priv_decoder_functions },
    { "gost2012_256", "provider=gostprov,input=PEM,structure=PrivateKeyInfo", gost2012_256_pem_priv_decoder_functions },
    { "gost2012_256", "provider=gostprov,input=DER,structure=SubjectPublicKeyInfo", gost2012_256_der_pub_decoder_functions },
    { "gost2012_256", "provider=gostprov,input=PEM,structure=SubjectPublicKeyInfo", gost2012_256_pem_pub_decoder_functions },

    { "gost2012_512", "provider=gostprov,input=DER,structure=PrivateKeyInfo", gost2012_512_der_priv_decoder_functions },
    { "gost2012_512", "provider=gostprov,input=PEM,structure=PrivateKeyInfo", gost2012_512_pem_priv_decoder_functions },
    { "gost2012_512", "provider=gostprov,input=DER,structure=SubjectPublicKeyInfo", gost2012_512_der_pub_decoder_functions },
    { "gost2012_512", "provider=gostprov,input=PEM,structure=SubjectPublicKeyInfo", gost2012_512_pem_pub_decoder_functions },
    { NULL, NULL, NULL }
};
