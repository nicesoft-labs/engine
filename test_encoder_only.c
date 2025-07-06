#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define T(e) if(!(e)){ERR_print_errors_fp(stderr);goto err;}

int main(void)
{
    int ret = 1;
    OSSL_PROVIDER *prov = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY_CTX *ictx = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *key2 = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *mem = NULL;
    unsigned char *der = NULL;
    unsigned char *pem = NULL;
    long dersz = 0;
    long pemsz = 0;
    char group[80];
    size_t gsz = 0;

    OPENSSL_add_all_algorithms_conf();

    printf("Step: load provider\n");
    T(OSSL_PROVIDER_load(NULL, "base") != NULL);
    T(OSSL_PROVIDER_load(NULL, "default") != NULL);
    prov = OSSL_PROVIDER_load(NULL, "gostprov");
    T(prov != NULL);

    printf("Step: generate key\n");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    T(ctx != NULL);
    T(EVP_PKEY_keygen_init(ctx) > 0);
    T(EVP_PKEY_generate(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    printf("Step: export DER\n");
    mem = BIO_new(BIO_s_mem());
    T(mem != NULL);
    ectx = OSSL_ENCODER_CTX_new_for_pkey(key,
                                         OSSL_KEYMGMT_SELECT_KEYPAIR,
                                         "DER", NULL, NULL);
    T(ectx != NULL);
    T(OSSL_ENCODER_to_bio(ectx, mem));
    dersz = BIO_get_mem_data(mem, &der);
    T(dersz > 0);
    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;
    BIO_free(mem);
    mem = NULL;

    printf("Step: export PEM\n");
    mem = BIO_new(BIO_s_mem());
    T(mem != NULL);
    ectx = OSSL_ENCODER_CTX_new_for_pkey(key,
                                         OSSL_KEYMGMT_SELECT_KEYPAIR,
                                         "PEM", NULL, NULL);
    T(ectx != NULL);
    T(OSSL_ENCODER_to_bio(ectx, mem));
    pemsz = BIO_get_mem_data(mem, &pem);
    T(pemsz > 0);
    OSSL_ENCODER_CTX_free(ectx);
    ectx = NULL;
    BIO_free(mem);
    mem = NULL;

    T(dersz != pemsz);

    printf("Step: import params\n");
    T(EVP_PKEY_todata(key,
                      OSSL_KEYMGMT_SELECT_KEYPAIR |
                      OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                      &params) > 0);
    ictx = EVP_PKEY_CTX_new_from_name(NULL, "gost2012_256", NULL);
    T(ictx != NULL);
    T(EVP_PKEY_fromdata_init(ictx) > 0);
    T(EVP_PKEY_fromdata(ictx, &key2,
                        OSSL_KEYMGMT_SELECT_KEYPAIR |
                        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                        params) > 0);
    EVP_PKEY_CTX_free(ictx);
    ictx = NULL;
    OSSL_PARAM_free(params);
    params = NULL;

    printf("Step: compare keys\n");
    T(EVP_PKEY_eq(key, key2) == 1);
    ictx = EVP_PKEY_CTX_new_from_pkey(NULL, key2, NULL);
    T(ictx != NULL);
    T(EVP_PKEY_check(ictx) > 0);
    EVP_PKEY_CTX_free(ictx);
    ictx = NULL;

    T(EVP_PKEY_get_utf8_string_param(key2, OSSL_PKEY_PARAM_GROUP_NAME,
                                     group, sizeof(group), &gsz));
    T(gsz > 0);
    T(EVP_PKEY_bits(key2) > 0);

    ret = 0;
err:
    BIO_free(mem);
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_free(key);
    EVP_PKEY_free(key2);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(ictx);
    OSSL_PARAM_free(params);
    if(prov)
        OSSL_PROVIDER_unload(prov);
    return ret;
}
