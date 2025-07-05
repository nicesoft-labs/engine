#include <openssl/evp.h>
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
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL, *key2 = NULL;
    OSSL_PARAM *params = NULL;
    char group[80];
    size_t gsz = 0;

    OPENSSL_add_all_algorithms_conf();

    prov = OSSL_PROVIDER_load(NULL, "gostprov");
    fprintf(stderr, "loaded provider\n");
    T(prov != NULL);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    fprintf(stderr, "ctx=%p\n", (void*)ctx);
    T(ctx != NULL);
    T(EVP_PKEY_keygen_init(ctx) > 0);
    T(EVP_PKEY_generate(ctx, &key) > 0);
    fprintf(stderr, "generated key\n");
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Export the key to params */
    T(EVP_PKEY_todata(key,
                      OSSL_KEYMGMT_SELECT_KEYPAIR |
                      OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                      &params) > 0);

    /* Import back into a new key */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    T(ctx != NULL);
    T(EVP_PKEY_fromdata_init(ctx) > 0);
    T(EVP_PKEY_fromdata(ctx, &key2,
                        OSSL_KEYMGMT_SELECT_KEYPAIR |
                        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                        params) > 0);
    fprintf(stderr, "imported key\n");
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key2, NULL);
    T(ctx != NULL);
    T(EVP_PKEY_check(ctx) > 0);
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    OSSL_PARAM_free(params);
    params = NULL;

    T(EVP_PKEY_eq(key, key2));
    T(EVP_PKEY_get_utf8_string_param(key2, OSSL_PKEY_PARAM_GROUP_NAME,
                                     group, sizeof(group), &gsz));
    fprintf(stderr, "group=%s\n", group);
    T(gsz > 0);
    fprintf(stderr, "bits=%d\n", EVP_PKEY_bits(key2));
    T(EVP_PKEY_bits(key2) > 0);

    ret = 0;
err:
    OSSL_PARAM_free(params);
    EVP_PKEY_free(key);
    EVP_PKEY_free(key2);
    EVP_PKEY_CTX_free(ctx);
    if(prov)
        OSSL_PROVIDER_unload(prov);
    return ret;
}
