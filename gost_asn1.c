/**********************************************************************
 *                          gost_keytrans.c                           *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *   ASN1 structure definition for GOST key transport                 *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/proverr.h>
#include "gost_lcl.h"
#include "gost_prov.h"
#include "gost_asn1.h"

ASN1_NDEF_SEQUENCE(GOST_KEY_TRANSPORT) = {
    ASN1_SIMPLE(GOST_KEY_TRANSPORT, key_info, GOST_KEY_INFO),
    ASN1_IMP(GOST_KEY_TRANSPORT, key_agreement_info,
             GOST_KEY_AGREEMENT_INFO, 0)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_TRANSPORT)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_TRANSPORT)

ASN1_NDEF_SEQUENCE(GOST_KEY_INFO) =
{
    ASN1_SIMPLE(GOST_KEY_INFO, encrypted_key, ASN1_OCTET_STRING),
    ASN1_SIMPLE(GOST_KEY_INFO, imit, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_INFO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_INFO)

ASN1_NDEF_SEQUENCE(GOST_KEY_AGREEMENT_INFO) =
{
    ASN1_SIMPLE(GOST_KEY_AGREEMENT_INFO, cipher, ASN1_OBJECT),
    ASN1_IMP_OPT(GOST_KEY_AGREEMENT_INFO, ephem_key, X509_PUBKEY, 0),
    ASN1_SIMPLE(GOST_KEY_AGREEMENT_INFO, eph_iv, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_AGREEMENT_INFO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_AGREEMENT_INFO)

ASN1_NDEF_SEQUENCE(GOST_KEY_PARAMS) =
{
    ASN1_SIMPLE(GOST_KEY_PARAMS, key_params, ASN1_OBJECT),
    ASN1_OPT(GOST_KEY_PARAMS, hash_params, ASN1_OBJECT),
    ASN1_OPT(GOST_KEY_PARAMS, cipher_params, ASN1_OBJECT),
} ASN1_NDEF_SEQUENCE_END(GOST_KEY_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GOST_KEY_PARAMS)

ASN1_NDEF_SEQUENCE(GOST_CIPHER_PARAMS) =
{
    ASN1_SIMPLE(GOST_CIPHER_PARAMS, iv, ASN1_OCTET_STRING),
    ASN1_SIMPLE(GOST_CIPHER_PARAMS, enc_param_set, ASN1_OBJECT),
} ASN1_NDEF_SEQUENCE_END(GOST_CIPHER_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

ASN1_NDEF_SEQUENCE(GOST2015_CIPHER_PARAMS) = {
	ASN1_SIMPLE(GOST2015_CIPHER_PARAMS, ukm, ASN1_OCTET_STRING),
} ASN1_NDEF_SEQUENCE_END(GOST2015_CIPHER_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GOST2015_CIPHER_PARAMS)

ASN1_NDEF_SEQUENCE(GOST_CLIENT_KEY_EXCHANGE_PARAMS) =
{                               /* FIXME incomplete */
    ASN1_SIMPLE(GOST_CLIENT_KEY_EXCHANGE_PARAMS, gkt, GOST_KEY_TRANSPORT)
} ASN1_NDEF_SEQUENCE_END(GOST_CLIENT_KEY_EXCHANGE_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GOST_CLIENT_KEY_EXCHANGE_PARAMS)

ASN1_NDEF_SEQUENCE(MASKED_GOST_KEY) =
{
    ASN1_SIMPLE(MASKED_GOST_KEY, masked_priv_key, ASN1_OCTET_STRING),
    ASN1_SIMPLE(MASKED_GOST_KEY, public_key, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(MASKED_GOST_KEY)
IMPLEMENT_ASN1_FUNCTIONS(MASKED_GOST_KEY)

/* draft-smyshlyaev-tls12-gost-suites */
ASN1_NDEF_SEQUENCE(PSKeyTransport_gost) =
{
    ASN1_SIMPLE(PSKeyTransport_gost, psexp, ASN1_OCTET_STRING),
		ASN1_SIMPLE(PSKeyTransport_gost, ephem_key, X509_PUBKEY),
		ASN1_OPT(PSKeyTransport_gost, ukm, ASN1_OCTET_STRING)
} ASN1_NDEF_SEQUENCE_END(PSKeyTransport_gost)
IMPLEMENT_ASN1_FUNCTIONS(PSKeyTransport_gost)


/* Private and public key info wrappers for provider */
ASN1_SEQUENCE(GOST_PRIVATE_KEY_INFO) = {
    ASN1_SIMPLE(GOST_PRIVATE_KEY_INFO, algor, X509_ALGOR),
    ASN1_SIMPLE(GOST_PRIVATE_KEY_INFO, priv_key, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(GOST_PRIVATE_KEY_INFO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_PRIVATE_KEY_INFO)

ASN1_SEQUENCE(GOST_PUBLIC_KEY_INFO) = {
    ASN1_SIMPLE(GOST_PUBLIC_KEY_INFO, algor, X509_ALGOR),
    ASN1_SIMPLE(GOST_PUBLIC_KEY_INFO, pub_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(GOST_PUBLIC_KEY_INFO)
IMPLEMENT_ASN1_FUNCTIONS(GOST_PUBLIC_KEY_INFO)

int i2d_GOST_PRIVATE_KEY_INFO_bio(BIO *out, const GOST_PRIVATE_KEY_INFO *a)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(GOST_PRIVATE_KEY_INFO), out, a);
}

int i2d_GOST_PUBLIC_KEY_INFO_bio(BIO *out, const GOST_PUBLIC_KEY_INFO *a)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(GOST_PUBLIC_KEY_INFO), out, a);
}

int PEM_write_bio_GOST_PRIVATE_KEY_INFO(BIO *bp, const GOST_PRIVATE_KEY_INFO *x)
{
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_GOST_PRIVATE_KEY_INFO,
                              PEM_STRING_PKCS8INF, bp, (void *)x,
                              NULL, NULL, 0, NULL, NULL);
}

int PEM_write_bio_GOST_PUBLIC_KEY_INFO(BIO *bp, const GOST_PUBLIC_KEY_INFO *x)
{
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_GOST_PUBLIC_KEY_INFO,
                              PEM_STRING_PUBLIC, bp, (void *)x,
                              NULL, NULL, 0, NULL, NULL);
}


int gost_param_nid_to_alg_nid(int param_nid)
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

static X509_ALGOR *build_algor_from_param(int param_nid)
{
    X509_ALGOR *alg = NULL;
    ASN1_STRING *params = NULL;
    GOST_KEY_PARAMS *gkp = NULL;
    unsigned char *der = NULL;
    int derlen = 0;
    int alg_nid = gost_param_nid_to_alg_nid(param_nid);

    DEBUG_LOG("build_algor_from_param: param_nid=%d alg_nid=%d",
              param_nid, alg_nid);

    if (alg_nid == NID_undef || param_nid == NID_undef) {
        DEBUG_LOG("build_algor_from_param: unknown param_nid %d", param_nid);
        return NULL;
    }
    
    gkp = GOST_KEY_PARAMS_new();
    if (gkp == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    gkp->key_params = OBJ_nid2obj(param_nid);
    if (gkp->key_params == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto err;
    }
    switch (alg_nid) {
    case NID_id_GostR3410_2012_256:
        gkp->hash_params = OBJ_nid2obj(NID_id_GostR3411_2012_256);
        break;
    case NID_id_GostR3410_2012_512:
        gkp->hash_params = OBJ_nid2obj(NID_id_GostR3411_2012_512);
        break;
    case NID_id_GostR3410_2001:
        gkp->hash_params = OBJ_nid2obj(NID_id_GostR3411_94_CryptoProParamSet);
        break;
    }

    if (gkp->hash_params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto err;
    }


    derlen = i2d_GOST_KEY_PARAMS(gkp, &der);
    if (derlen <= 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto err;
    }

    params = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ASN1_STRING_set0(params, der, derlen);
    der = NULL;

    alg = X509_ALGOR_new();
    if (alg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    X509_ALGOR_set0(alg, OBJ_nid2obj(alg_nid), V_ASN1_SEQUENCE, params);
    params = NULL;

 err:
    GOST_KEY_PARAMS_free(gkp);
    ASN1_STRING_free(params);
    OPENSSL_free(der);
    return alg;
}

GOST_PRIVATE_KEY_INFO *gost_priv_key_info_from_ec(const EC_KEY *ec,
                                                  int param_nid)
{
    const EC_GROUP *group;
    const BIGNUM *priv;
    GOST_PRIVATE_KEY_INFO *info = NULL;
    unsigned char *buf = NULL;
    int buflen = 0;

    if (ec == NULL)
        return NULL;
    group = EC_KEY_get0_group(ec);
    priv = EC_KEY_get0_private_key(ec);
    if (group == NULL || priv == NULL)
        return NULL;

    info = GOST_PRIVATE_KEY_INFO_new();
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    info->algor = build_algor_from_param(param_nid);
    if (info->algor == NULL) {
        DEBUG_LOG("gost_priv_key_info_from_ec: build_algor_from_param returned NULL param_nid=%d",
                  param_nid);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto err;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    buf = OPENSSL_malloc(buflen);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (BN_bn2lebinpad(priv, buf, buflen) < 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!ASN1_OCTET_STRING_set(info->priv_key, buf, buflen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_ASN1_LIB);
        goto err;
    }

    OPENSSL_free(buf);
    return info;
 err:
    OPENSSL_free(buf);
    GOST_PRIVATE_KEY_INFO_free(info);
    return NULL;
}

GOST_PUBLIC_KEY_INFO *gost_pub_key_info_from_ec(const EC_KEY *ec,
                                                int param_nid)
{
    const EC_GROUP *group;
    const EC_POINT *point;
    unsigned char *buf = NULL;
    size_t buflen = 0;
    GOST_PUBLIC_KEY_INFO *info = NULL;

    if (ec == NULL)
        return NULL;
    group = EC_KEY_get0_group(ec);
    point = EC_KEY_get0_public_key(ec);
    if (group == NULL || point == NULL)
        return NULL;

    info = GOST_PUBLIC_KEY_INFO_new();
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    info->algor = build_algor_from_param(param_nid);
    if (info->algor == NULL) {
        DEBUG_LOG("gost_pub_key_info_from_ec: build_algor_from_param returned NULL param_nid=%d",
                  param_nid);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
        goto err;
    }

    buflen = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                &buf, NULL);
    if (buflen == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_EC_LIB);
        goto err;
    }
    if (!ASN1_BIT_STRING_set(info->pub_key, buf, (int)buflen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_ASN1_LIB);
        goto err;
    }

    /*
     * Ensure the BIT STRING reports zero unused bits.  This mirrors the
     * behaviour of ASN1_BIT_STRING_set_bit() but without altering the data.
     */
    info->pub_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    info->pub_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;

#ifdef ENABLE_GOST_DEBUG
    DEBUG_LOG("gost_pub_key_info_from_ec: pub_key length=%d bits_unused=%ld",
              info->pub_key->length, info->pub_key->flags & 0x7);
#endif

    
    OPENSSL_free(buf);
    return info;
 err:
    OPENSSL_free(buf);
    GOST_PUBLIC_KEY_INFO_free(info);
    return NULL;
}

int gost_register_oids(void)
{
    /* Reuse the OID registration from the provider */
    struct {
        const char *oid;
        const char *sn;
        const char *ln;
        int nid;
    } oids[] = {
        { "1.2.643.7.1.1.1.1", SN_id_GostR3410_2012_256,
          "GOST R 34.10-2012 with 256-bit", NID_id_GostR3410_2012_256 },
        { "1.2.643.7.1.1.1.2", SN_id_GostR3410_2012_512,
          "GOST R 34.10-2012 with 512-bit", NID_id_GostR3410_2012_512 },
        { "1.2.643.7.1.2.1.1.1", SN_id_tc26_gost_3410_2012_256_paramSetA,
          LN_id_tc26_gost_3410_2012_256_paramSetA,
          NID_id_tc26_gost_3410_2012_256_paramSetA },
        { "1.2.643.7.1.2.1.1.2", SN_id_tc26_gost_3410_2012_256_paramSetB,
          LN_id_tc26_gost_3410_2012_256_paramSetB,
          NID_id_tc26_gost_3410_2012_256_paramSetB },
        { "1.2.643.7.1.2.1.1.3", SN_id_tc26_gost_3410_2012_256_paramSetC,
          LN_id_tc26_gost_3410_2012_256_paramSetC,
          NID_id_tc26_gost_3410_2012_256_paramSetC },
        { "1.2.643.7.1.2.1.1.4", SN_id_tc26_gost_3410_2012_256_paramSetD,
          LN_id_tc26_gost_3410_2012_256_paramSetD,
          NID_id_tc26_gost_3410_2012_256_paramSetD },
        { "1.2.643.7.1.2.1.2.0", SN_id_tc26_gost_3410_2012_512_paramSetTest,
          LN_id_tc26_gost_3410_2012_512_paramSetTest,
          NID_id_tc26_gost_3410_2012_512_paramSetTest },
        { "1.2.643.7.1.2.1.2.1", SN_id_tc26_gost_3410_2012_512_paramSetA,
          LN_id_tc26_gost_3410_2012_512_paramSetA,
          NID_id_tc26_gost_3410_2012_512_paramSetA },
        { "1.2.643.7.1.2.1.2.2", SN_id_tc26_gost_3410_2012_512_paramSetB,
          LN_id_tc26_gost_3410_2012_512_paramSetB,
          NID_id_tc26_gost_3410_2012_512_paramSetB },
        { "1.2.643.7.1.2.1.2.3", SN_id_tc26_gost_3410_2012_512_paramSetC,
          LN_id_tc26_gost_3410_2012_512_paramSetC,
          NID_id_tc26_gost_3410_2012_512_paramSetC },
        { "1.2.643.7.1.1.2.2", SN_id_GostR3411_2012_256,
          "GOST R 34.11-2012 with 256-bit", NID_id_GostR3411_2012_256 },
        { "1.2.643.7.1.1.2.3", SN_id_GostR3411_2012_512,
          "GOST R 34.11-2012 with 512-bit", NID_id_GostR3411_2012_512 }
    };
    size_t i;

    for (i = 0; i < sizeof(oids)/sizeof(oids[0]); i++) {
        int nid = OBJ_txt2nid(oids[i].oid);

        if (nid == NID_undef) {
            nid = OBJ_create(oids[i].oid, oids[i].sn, oids[i].ln);
            ERR_clear_error();
        } else {
            ERR_clear_error();
        }
        if (nid != oids[i].nid)
            return 0;
    }
    return 1;
}



