/**********************************************************************
 *                 gost_prov.h - The provider itself                  *
 *                                                                    *
 *      Copyright (c) 2021 Richard Levitte <richard@levitte.org>      *
 *     This file is distributed under the same license as OpenSSL     *
 *                                                                    *
 *                Requires OpenSSL 3.0 for compilation                *
 **********************************************************************/

#include <openssl/core.h>
#include <openssl/engine.h>
#include <openssl/err.h>


struct provider_ctx_st {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;

    /*
     * "internal" GOST engine, which is the implementation that all the
     * provider functions will use to access the crypto functionality.
     * This is pure hackery, but allows us to quickly wrap all the ENGINE
     * function with provider wrappers.  There is no other supported way
     * to do this.
     */
    ENGINE *e;
};
typedef struct provider_ctx_st PROV_CTX;

#ifdef DEBUG
# define DEBUG_LOG(fmt, ...) \
    ERR_raise_data(ERR_LIB_PROV, 0, fmt, ##__VA_ARGS__)
#else
# define DEBUG_LOG(fmt, ...) ((void)0)
#endif
