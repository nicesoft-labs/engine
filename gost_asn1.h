#ifndef GOST_ASN1_H
#define GOST_ASN1_H

#include <openssl/x509.h>
#include <openssl/asn1t.h>

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

#endif /* GOST_ASN1_H */
