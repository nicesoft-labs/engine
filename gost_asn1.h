#ifndef GOST_ASN1_H
#define GOST_ASN1_H

#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>


/* GOST PrivateKeyInfo like structure */
typedef struct {
    X509_ALGOR *algor;
    ASN1_OCTET_STRING *priv_key;
} GOST_PRIVATE_KEY_INFO;

DECLARE_ASN1_FUNCTIONS(GOST_PRIVATE_KEY_INFO)

/* GOST SubjectPublicKeyInfo like structure */
typedef struct {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *pub_key;
} GOST_PUBLIC_KEY_INFO;

DECLARE_ASN1_FUNCTIONS(GOST_PUBLIC_KEY_INFO)
int gost_param_nid_to_alg_nid(int param_nid);
GOST_PRIVATE_KEY_INFO *gost_priv_key_info_from_ec(const EC_KEY *ec,
                                                  int param_nid);
GOST_PUBLIC_KEY_INFO *gost_pub_key_info_from_ec(const EC_KEY *ec,
                                                int param_nid);

int i2d_GOST_PRIVATE_KEY_INFO_bio(BIO *out, const GOST_PRIVATE_KEY_INFO *a);
int i2d_GOST_PUBLIC_KEY_INFO_bio(BIO *out, const GOST_PUBLIC_KEY_INFO *a);
int PEM_write_bio_GOST_PRIVATE_KEY_INFO(BIO *bp, const GOST_PRIVATE_KEY_INFO *x);
int PEM_write_bio_GOST_PUBLIC_KEY_INFO(BIO *bp, const GOST_PUBLIC_KEY_INFO *x);


#endif /* GOST_ASN1_H */
