#ifndef CMP_MOCK_SRV_H
#define CMP_MOCK_SRV_H

#include "openssl/cmp.h"

#ifdef OPENSSL_V3

OSSL_CMP_SRV_CTX *ossl_cmp_mock_srv_new( OSSL_LIB_CTX *libctx, const char *propq );
void ossl_cmp_mock_srv_free(OSSL_CMP_SRV_CTX *srv_ctx );

int ossl_cmp_mock_srv_set1_certOut( OSSL_CMP_SRV_CTX *srv_ctx, X509 *cert );
int ossl_cmp_mock_srv_set1_chainOut( OSSL_CMP_SRV_CTX *srv_ctx, STACK_OF(X509) *chain );
int ossl_cmp_mock_srv_set1_caPubsOut( OSSL_CMP_SRV_CTX *srv_ctx, STACK_OF(X509) *caPubs );
int ossl_cmp_mock_srv_set_statusInfo( OSSL_CMP_SRV_CTX *srv_ctx, int status, int fail_info, const char *text );
int ossl_cmp_mock_srv_set_send_error( OSSL_CMP_SRV_CTX *srv_ctx, int val );
int ossl_cmp_mock_srv_set_pollCount( OSSL_CMP_SRV_CTX *srv_ctx, int count );
int ossl_cmp_mock_srv_set_checkAfterTime( OSSL_CMP_SRV_CTX *srv_ctx, int sec );

#endif

#endif // CMP_MOCK_SRV_H
