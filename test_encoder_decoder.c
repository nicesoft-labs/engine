#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define DBG(fmt, ...)                                                        \
    do {                                                                    \
        fprintf(stderr, ">>>> " fmt "\n", ##__VA_ARGS__);                 \
        fflush(stderr);                                                     \
    } while (0)

#define T(e)                                                                \
    if(!(e)) {                                                              \
        ERR_print_errors_fp(stderr);                                        \
        DBG("FAIL");                                                      \
        goto err;                                                           \
    }

int main(void)
{
    int ret = 1;
    OSSL_PROVIDER *defprov = NULL, *gostprov = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    OPENSSL_add_all_algorithms_conf();
    DBG("Loading providers");

    defprov = OSSL_PROVIDER_load(NULL, "default");
    gostprov = OSSL_PROVIDER_load(NULL, "gostprov");
    T(defprov != NULL && gostprov != NULL);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    T(ctx != NULL);
    T(EVP_PKEY_keygen_init(ctx) > 0);
    T(EVP_PKEY_generate(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

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
            DBG("Starting %s key cycle", is_priv ? "PRIVATE" : "PUBLIC");

            /* encode original key to DER */
            format = "DER";
            DBG("Creating encoder ctx: provider=gostprov selection=%d structure=%s format=%s", selection, structure, format);
            ectx = OSSL_ENCODER_CTX_new_for_pkey(key, selection, format, structure, "provider=gostprov");
            T(ectx != NULL);
            if (!OSSL_ENCODER_to_data(ectx, &der, &der_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL");
                goto err;
            }
            DBG("DER length: %zu", der_len);
            for (size_t i = 0; i < der_len && i < 16; i++)
                fprintf(stderr, "%02X ", der[i]);
            fprintf(stderr, "\n");
            fflush(stderr);
            OSSL_ENCODER_CTX_free(ectx);
            ectx = NULL;

            /* decode DER back to a key */
            p = der;
            format = "DER";
            DBG("Creating decoder ctx: provider=gostprov selection=%d structure=%s format=%s", selection, structure, format);
            dctx = OSSL_DECODER_CTX_new_for_pkey(&kder, format, structure,
                                                "gost2012_256", selection, NULL,
                                                "provider=gostprov");
            T(dctx != NULL);
            if (!OSSL_DECODER_from_data(dctx, &p, &der_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL");
                goto err;
            }
            OSSL_DECODER_CTX_free(dctx);
            dctx = NULL;

            {
                int eqres = EVP_PKEY_eq(key, kder);
                DBG("EVP_PKEY_eq returned: %d", eqres);
                T(eqres);
            }
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL, kder, NULL);
            T(ctx != NULL);
            if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                T(EVP_PKEY_public_check(ctx) > 0);
            } else {
                T(EVP_PKEY_check(ctx) > 0);
            }
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;

            /* encode the decoded key to PEM and decode again */
            format = "PEM";
            DBG("Creating encoder ctx: provider=gostprov selection=%d structure=%s format=%s", selection, structure, format);
            ectx = OSSL_ENCODER_CTX_new_for_pkey(kder, selection, format, structure, "provider=gostprov");
            T(ectx != NULL);
            if (!OSSL_ENCODER_to_data(ectx, &pem, &pem_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL");
                goto err;
            }
            DBG("PEM length: %zu", pem_len);
            OSSL_ENCODER_CTX_free(ectx);
            ectx = NULL;

            p = pem;
            format = "PEM";
            DBG("Creating decoder ctx: provider=gostprov selection=%d structure=%s format=%s", selection, structure, format);
            dctx = OSSL_DECODER_CTX_new_for_pkey(&kpem, format, structure,
                                                "gost2012_256", selection, NULL,
                                                "provider=gostprov");
            T(dctx != NULL);
            if (!OSSL_DECODER_from_data(dctx, &p, &pem_len)) {
                ERR_print_errors_fp(stderr);
                DBG("FAIL");
                goto err;
            }
            OSSL_DECODER_CTX_free(dctx);
            dctx = NULL;

            {
                int eqres = EVP_PKEY_eq(key, kpem);
                DBG("EVP_PKEY_eq returned: %d", eqres);
                T(eqres);
            }
            ctx = EVP_PKEY_CTX_new_from_pkey(NULL, kpem, NULL);
            T(ctx != NULL);
            if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
                T(EVP_PKEY_public_check(ctx) > 0);
            } else {
                T(EVP_PKEY_check(ctx) > 0);
            }
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            EVP_PKEY_free(kpem);
            kpem = NULL;

            EVP_PKEY_free(kder);
            kder = NULL;

            OPENSSL_free(der);
            OPENSSL_free(pem);
            DBG("SUCCESS");
        }
    }

    ret = 0;
err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (gostprov)
        OSSL_PROVIDER_unload(gostprov);
    if (defprov)
        OSSL_PROVIDER_unload(defprov);
    return ret;
}
