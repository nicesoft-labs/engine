#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define T(e) \
    if(!(e)) { \
        ERR_print_errors_fp(stderr); \
        goto err; \
    }

int main(void)
{
    int ret = 1;
    OSSL_PROVIDER *defprov = NULL, *gostprov = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    OPENSSL_add_all_algorithms_conf();

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
        unsigned char *der = NULL, *pem = NULL;
        size_t der_len = 0, pem_len = 0;
        EVP_PKEY *kder = NULL, *kpem = NULL;
        const unsigned char *p = NULL;
        OSSL_ENCODER_CTX *ectx = NULL;
        OSSL_DECODER_CTX *dctx = NULL;

            /* encode original key to DER */
            ectx = OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER", structure, "provider=gostprov");
            T(ectx != NULL);
            T(OSSL_ENCODER_to_data(ectx, &der, &der_len));
            OSSL_ENCODER_CTX_free(ectx);
            ectx = NULL;

            /* decode DER back to a key */
            p = der;
            dctx = OSSL_DECODER_CTX_new_for_pkey(&kder, "DER", NULL, "gost2012_256", selection, NULL, "provider=gostprov");
            T(dctx != NULL);
            T(OSSL_DECODER_from_data(dctx, &p, &der_len));
            OSSL_DECODER_CTX_free(dctx);
            dctx = NULL;

            T(EVP_PKEY_eq(key, kder));
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
            ectx = OSSL_ENCODER_CTX_new_for_pkey(kder, selection, "PEM", structure, "provider=gostprov");
            T(ectx != NULL);
            T(OSSL_ENCODER_to_data(ectx, &pem, &pem_len));
            OSSL_ENCODER_CTX_free(ectx);
            ectx = NULL;

            p = pem;
            dctx = OSSL_DECODER_CTX_new_for_pkey(&kpem, "PEM", NULL, "gost2012_256", selection, NULL, "provider=gostprov");
            T(dctx != NULL);
            T(OSSL_DECODER_from_data(dctx, &p, &pem_len));
            OSSL_DECODER_CTX_free(dctx);
            dctx = NULL;

            T(EVP_PKEY_eq(key, kpem));
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
