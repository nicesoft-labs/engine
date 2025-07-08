#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include "gost_asn1.h"
#include "gost_lcl.h"
#include <stdio.h>
#include <string.h>

#define DBG(fmt, ...)                                                        \
    do {                                                                     \
        fprintf(stderr, "[%s:%d] >>>> " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        fflush(stderr);                                                      \
    } while (0)

#define T(e)                                                                 \
    do {                                                                     \
        if (!(e)) {                                                          \
            ERR_print_errors_fp(stderr);                                     \
            DBG("FAIL: Expression '%s' failed", #e);                        \
            goto err;                                                        \
        } else {                                                             \
            DBG("SUCCESS: Expression '%s' evaluated successfully", #e);     \
        }                                                                    \
    } while (0)

static const char *alg_nid2name(int nid)
{
    DBG("Entering alg_nid2name with nid=%d", nid);
    const char *result;
    switch (nid) {
    case NID_id_GostR3410_2001:
        result = "gost2001";
        break;
    case NID_id_GostR3410_2012_256:
        result = "gost2012_256";
        break;
    case NID_id_GostR3410_2012_512:
        result = "gost2012_512";
        break;
    default:
        result = NULL;
        break;
    }
    DBG("alg_nid2name returning: %s", result ? result : "NULL");
    return result;
}

int main(void)
{
    DBG("Starting main function");
    int ret = 1;
    OSSL_PROVIDER *defprov = NULL, *gostprov = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    int param_nid = NID_id_tc26_gost_3410_2012_256_paramSetA;

    DBG("Setting param_nid to %d (NID_id_tc26_gost_3410_2012_256_paramSetA)", param_nid);

    DBG("Configuring stdout and stderr to unbuffered mode");
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    DBG("Initializing OpenSSL algorithms");
    OPENSSL_add_all_algorithms_conf();

    DBG("Loading default provider");
    defprov = OSSL_PROVIDER_load(NULL, "default");
    T(defprov != NULL);
    DBG("Default provider loaded: %p", (void *)defprov);

    DBG("Loading gostprov provider");
    gostprov = OSSL_PROVIDER_load(NULL, "gostprov");
    T(gostprov != NULL);
    DBG("Gostprov provider loaded: %p", (void *)gostprov);

    DBG("Creating EVP_PKEY_CTX for algorithm gost2012_256");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    T(ctx != NULL);
    DBG("EVP_PKEY_CTX created: %p", (void *)ctx);

    DBG("Initializing key generation");
    T(EVP_PKEY_keygen_init(ctx) > 0);
    DBG("Key generation initialized");

    DBG("Generating key");
    T(EVP_PKEY_generate(ctx, &key) > 0);
    DBG("Key generated: %p", (void *)key);

    DBG("Freeing EVP_PKEY_CTX");
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    DBG("EVP_PKEY_CTX freed");

    /* Check direct GOST_PUBLIC_KEY_INFO encode/decode */
    DBG("Starting GOST_PUBLIC_KEY_INFO encode/decode test");
    {
        EC_KEY *ec = NULL;
        GOST_PUBLIC_KEY_INFO *info = NULL;
        unsigned char *der = NULL;
        const unsigned char *p = NULL;
        GOST_PUBLIC_KEY_INFO *info2 = NULL;
        int der_len;

        DBG("Creating new EC_KEY");
        ec = EC_KEY_new();
        T(ec != NULL);
        DBG("EC_KEY created: %p", (void *)ec);

        DBG("Filling GOST EC parameters with nid=%d", param_nid);
        T(fill_GOST_EC_params(ec, param_nid));
        DBG("GOST EC parameters filled");

        DBG("Generating GOST EC key");
        T(gost_ec_keygen(ec));
        DBG("GOST EC key generated");

        DBG("Creating GOST_PUBLIC_KEY_INFO from EC key");
        info = gost_pub_key_info_from_ec(ec, param_nid);
        T(info != NULL);
        DBG("GOST_PUBLIC_KEY_INFO created: %p", (void *)info);

        DBG("Freeing EC_KEY");
        EC_KEY_free(ec);
        DBG("EC_KEY freed");

        DBG("bits_unused after construction: %ld", info->pub_key->flags & 0x7);

        DBG("Encoding GOST_PUBLIC_KEY_INFO to DER");
        der_len = i2d_GOST_PUBLIC_KEY_INFO(info, &der);
        T(der_len > 0 && der != NULL);
        DBG("DER encoded, length: %d, buffer: %p", der_len, (void *)der);

#ifdef ENABLE_GOST_DEBUG
        DBG("Writing DER to file gost_pub.der");
        {
            FILE *f = fopen("gost_pub.der", "wb");
            if (f != NULL) {
                DBG("File opened for writing");
                size_t written = fwrite(der, 1, der_len, f);
                DBG("Wrote %zu bytes to file", written);
                fclose(f);
                DBG("File closed");
            } else {
                DBG("Failed to open file gost_pub.der for writing");
            }
        }
#endif

        DBG("Decoding DER back to GOST_PUBLIC_KEY_INFO");
        p = der;
        info2 = d2i_GOST_PUBLIC_KEY_INFO(NULL, &p, der_len);
        T(info2 != NULL);
        DBG("GOST_PUBLIC_KEY_INFO decoded: %p", (void *)info2);

        DBG("Freeing decoded GOST_PUBLIC_KEY_INFO");
        GOST_PUBLIC_KEY_INFO_free(info2);
        DBG("Decoded GOST_PUBLIC_KEY_INFO freed");

        DBG("Freeing DER buffer");
        OPENSSL_free(der);
        DBG("DER buffer freed");

        DBG("Freeing original GOST_PUBLIC_KEY_INFO");
        GOST_PUBLIC_KEY_INFO_free(info);
        DBG("Original GOST_PUBLIC_KEY_INFO freed");

        DBG("GOST_PUBLIC_KEY_INFO encode/decode completed successfully");
    }

    DBG("Starting key encode/decode cycles for public and private keys");
    {
        int is_priv;
        for (is_priv = 0; is_priv < 2; is_priv++) {
            int selection = is_priv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
            const char *structure = is_priv ? "PrivateKeyInfo" : "SubjectPublicKeyInfo";
            const char *format = NULL;
            unsigned char *der = NULL, *pem = NULL;
            size_t der_len = 0, pem_len = 0;
            EVP_PKEY *kder = NULL, *kpem = NULL;
            const unsigned char *p = NULL;
            OSSL_ENCODER_CTX *ectx = NULL;
            OSSL_DECODER_CTX *dctx = NULL;

            DBG("Starting %s key cycle (is_priv=%d, selection=%d, structure=%s)",
                is_priv ? "PRIVATE" : "PUBLIC", is_priv, selection, structure);

            /* Encode original key to DER */
            format = "DER";
            DBG("Creating encoder context: provider=gostprov, selection=%d, structure=%s, format=%s",
                selection, structure, format);
            ectx = OSSL_ENCODER_CTX_new_for_pkey(key, selection, format, structure, "provider=gostprov");
            T(ectx != NULL);
            DBG("Encoder context created: %p", (void *)ectx);

            DBG("Encoding key to DER");
            if (!OSSL_ENCODER_to_data(ectx, &der, &der_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL: OSSL_ENCODER_to_data failed");
                goto err;
            }
            DBG("DER encoded successfully, length: %zu, buffer: %p", der_len, (void *)der);

            DBG("First 16 bytes of DER:");
            for (size_t i = 0; i < der_len && i < 16; i++)
                fprintf(stderr, "%02X ", der[i]);
            fprintf(stderr, "\n");
            fflush(stderr);

            DBG("Freeing encoder context");
            OSSL_ENCODER_CTX_free(ectx);
            ectx = NULL;
            DBG("Encoder context freed");

            /* Decode DER back to a key */
            p = der;
            format = "DER";
            DBG("Creating decoder context: provider=gostprov, selection=%d, structure=%s, format=%s",
                selection, structure, format);
            dctx = OSSL_DECODER_CTX_new_for_pkey(&kder,
                                    "DER",
                                    structure,            /* "SubjectPublicKeyInfo" или "PrivateKeyInfo" */
                                    "gost2012_256",        /* keytype */
                                    selection,             /* OSSL_KEYMGMT_SELECT_PUBLIC_KEY или _PRIVATE_KEY */
                                    NULL,                  /* libctx */
                                    "provider=gostprov");  /* propq */

            T(dctx != NULL);
            DBG("Decoder context created: %p", (void *)dctx);

            DBG("Decoding DER to EVP_PKEY");
            if (!OSSL_DECODER_from_data(dctx, &p, &der_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL: OSSL_DECODER_from_data failed");
                goto err;
            }
            DBG("DER decoded successfully, key: %p", (void *)kder);

            DBG("Freeing decoder context");
            OSSL_DECODER_CTX_free(dctx);
            dctx = NULL;
            DBG("Decoder context freed");

            DBG("Comparing original and decoded keys");
            {
                int eqres = EVP_PKEY_eq(key, kder);
                DBG("EVP_PKEY_eq returned: %d", eqres);
                T(eqres);

                if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                    char gname[80];
                    size_t gname_len = 0;
                    int gnid;
                    const char *type_name;
                    const char *expected_type;
                    unsigned char pubbuf[256];
                    size_t pub_len = 0;

                    DBG("Retrieving group name parameter");
                    T(EVP_PKEY_get_utf8_string_param(kder, OSSL_PKEY_PARAM_GROUP_NAME,
                                                    gname, sizeof(gname), &gname_len));
                    DBG("Group name: %s, length: %zu", gname, gname_len);

                    DBG("Converting group name to NID");
                    gnid = OBJ_sn2nid(gname);
                    if (gnid == NID_undef)
                        gnid = OBJ_txt2nid(gname);
                    DBG("Group NID: %d, expected: %d", gnid, param_nid);
                    T(gnid == param_nid);

                    DBG("Retrieving key type name");
                    type_name = EVP_PKEY_get0_type_name(kder);
                    expected_type = alg_nid2name(gost_param_nid_to_alg_nid(param_nid));
                    DBG("Type name: %s, expected: %s", type_name ? type_name : "NULL",
                        expected_type ? expected_type : "NULL");
                    T(type_name != NULL && expected_type != NULL &&
                      strcmp(type_name, expected_type) == 0);

                    DBG("Retrieving public key data");
                    T(EVP_PKEY_get_octet_string_param(kder, OSSL_PKEY_PARAM_PUB_KEY,
                                                     pubbuf, sizeof(pubbuf), &pub_len));
                    DBG("Public key length: %zu", pub_len);
                    T(pub_len > 0);
                    DBG("First 16 bytes of public key:");
                    for (size_t i = 0; i < pub_len && i < 16; i++)
                        fprintf(stderr, "%02X ", pubbuf[i]);
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }
            }

            DBG("Creating EVP_PKEY_CTX for key check");
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL, kder, NULL);
            T(ctx != NULL);
            DBG("EVP_PKEY_CTX created: %p", (void *)ctx);

            if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                DBG("Performing public key check");
                T(EVP_PKEY_public_check(ctx) > 0);
                DBG("Public key check passed");
            } else {
                DBG("Performing private key check");
                T(EVP_PKEY_check(ctx) > 0);
                DBG("Private key check passed");
            }

            DBG("Freeing EVP_PKEY_CTX");
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            DBG("EVP_PKEY_CTX freed");

            /* Encode the decoded key to PEM and decode again */
            format = "PEM";
            DBG("Creating encoder context for PEM: provider=gostprov, selection=%d, structure=%s, format=%s",
                selection, structure, format);
            ectx = OSSL_ENCODER_CTX_new_for_pkey(kder, selection, format, structure, "provider=gostprov");
            T(ectx != NULL);
            DBG("Encoder context created: %p", (void *)ectx);

            DBG("Encoding key to PEM");
            if (!OSSL_ENCODER_to_data(ectx, &pem, &pem_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL: OSSL_ENCODER_to_data for PEM failed");
                goto err;
            }
            DBG("PEM encoded successfully, length: %zu, buffer: %p", pem_len, (void *)pem);
            DBG("PEM content (first 100 chars): %.100s", pem);

            DBG("Freeing encoder context");
            OSSL_ENCODER_CTX_free(ectx);
            ectx = NULL;
            DBG("Encoder context freed");

            p = pem;
            format = "PEM";
            DBG("Creating decoder context for PEM: provider=gostprov, selection=%d, structure=%s, format=%s",
                selection, structure, format);
            dctx = OSSL_DECODER_CTX_new_for_pkey(&kpem,
                                    "PEM",
                                    structure,
                                    "gost2012_256",
                                    selection,
                                    NULL,
                                    "provider=gostprov");
            T(dctx != NULL);
            DBG("Decoder context created: %p", (void *)dctx);

            DBG("Decoding PEM to EVP_PKEY");
            if (!OSSL_DECODER_from_data(dctx, &p, &pem_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL: OSSL_DECODER_from_data for PEM failed");
                goto err;
            }
            DBG("PEM decoded successfully, key: %p", (void *)kpem);

            DBG("Freeing decoder context");
            OSSL_DECODER_CTX_free(dctx);
            dctx = NULL;
            DBG("Decoder context freed");

            DBG("Comparing original and PEM-decoded keys");
            {
                int eqres = EVP_PKEY_eq(key, kpem);
                DBG("EVP_PKEY_eq returned: %d", eqres);
                T(eqres);

                if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                    char gname[80];
                    size_t gname_len = 0;
                    int gnid;
                    const char *type_name;
                    const char *expected_type;
                    unsigned char pubbuf[256];
                    size_t pub_len = 0;

                    DBG("Retrieving group name parameter for PEM-decoded key");
                    T(EVP_PKEY_get_utf8_string_param(kpem, OSSL_PKEY_PARAM_GROUP_NAME,
                                                    gname, sizeof(gname), &gname_len));
                    DBG("Group name: %s, length: %zu", gname, gname_len);

                    DBG("Converting group name to NID");
                    gnid = OBJ_sn2nid(gname);
                    if (gnid == NID_undef)
                        gnid = OBJ_txt2nid(gname);
                    DBG("Group NID: %d, expected: %d", gnid, param_nid);
                    T(gnid == param_nid);

                    DBG("Retrieving key type name for PEM-decoded key");
                    type_name = EVP_PKEY_get0_type_name(kpem);
                    expected_type = alg_nid2name(gost_param_nid_to_alg_nid(param_nid));
                    DBG("Type name: %s, expected: %s", type_name ? type_name : "NULL",
                        expected_type ? expected_type : "NULL");
                    T(type_name != NULL && expected_type != NULL &&
                      strcmp(type_name, expected_type) == 0);

                    DBG("Retrieving public key data for PEM-decoded key");
                    T(EVP_PKEY_get_octet_string_param(kpem, OSSL_PKEY_PARAM_PUB_KEY,
                                                     pubbuf, sizeof(pubbuf), &pub_len));
                    DBG("Public key length: %zu", pub_len);
                    T(pub_len > 0);
                    DBG("First 16 bytes of public key:");
                    for (size_t i = 0; i < pub_len && i < 16; i++)
                        fprintf(stderr, "%02X ", pubbuf[i]);
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }
            }

            DBG("Creating EVP_PKEY_CTX for PEM-decoded key check");
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL, kpem, NULL);
            T(ctx != NULL);
            DBG("EVP_PKEY_CTX created: %p", (void *)ctx);

            if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                DBG("Performing public key check for PEM-decoded key");
                T(EVP_PKEY_public_check(ctx) > 0);
                DBG("Public key check passed");
            } else {
                DBG("Performing private key check for PEM-decoded key");
                T(EVP_PKEY_check(ctx) > 0);
                DBG("Private key check passed");
            }

            DBG("Freeing EVP_PKEY_CTX");
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            DBG("EVP_PKEY_CTX freed");

            DBG("Freeing PEM-decoded key");
            EVP_PKEY_free(kpem);
            kpem = NULL;
            DBG("PEM-decoded key freed");

            DBG("Freeing DER-decoded key");
            EVP_PKEY_free(kder);
            kder = NULL;
            DBG("DER-decoded key freed");

            DBG("Freeing DER buffer");
            OPENSSL_free(der);
            DBG("DER buffer freed");

            DBG("Freeing PEM buffer");
            OPENSSL_free(pem);
            DBG("PEM buffer freed");

            DBG("%s key cycle completed successfully", is_priv ? "PRIVATE" : "PUBLIC");
        }
    }

    DBG("All tests completed successfully, setting return value to 0");
    ret = 0;

err:
    DBG("Entering error cleanup");
    if (ctx) {
        DBG("Freeing EVP_PKEY_CTX: %p", (void *)ctx);
        EVP_PKEY_CTX_free(ctx);
    }
    if (key) {
        DBG("Freeing EVP_PKEY: %p", (void *)key);
        EVP_PKEY_free(key);
    }
    if (gostprov) {
        DBG("Unloading gostprov provider: %p", (void *)gostprov);
        OSSL_PROVIDER_unload(gostprov);
    }
    if (defprov) {
        DBG("Unloading default provider: %p", (void *)defprov);
        OSSL_PROVIDER_unload(defprov);
    }
    DBG("Returning from main with ret=%d", ret);
    return ret;
}
