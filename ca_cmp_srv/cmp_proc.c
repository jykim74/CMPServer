#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"

#include "cmp_srv.h"

extern BIN     g_binRootCert;
extern BIN     g_binCACert;
extern BIN     g_binCAPriKey;

extern BIN     g_binSignCert;
extern BIN     g_binSignPri;

int procCMP( const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    char    *pHex = NULL;

    OSSL_CMP_MSG    *pReqMsg = NULL;
    OSSL_CMP_MSG    *pRspMsg = NULL;

    OSSL_CMP_SRV_CTX *pSrvCTX = setupServerCTX();
    OSSL_CMP_CTX *pCTX = OSSL_CMP_SRV_CTX_get0_ctx( pSrvCTX );

    int     nOutLen = 0;
    unsigned char   *pOut = NULL;
    unsigned char   *pPosReq = pReq->pVal;
    STACK_OF(X509)  *pXCerts = NULL;
    X509            *pXSignCert = NULL;

    pXCerts = sk_X509_new_null();

    pReqMsg = d2i_OSSL_CMP_MSG( NULL, &pPosReq, pReq->nLen );
    if( pReqMsg == NULL )
    {
        fprintf( stderr, "ReqMsg is null\n" );
        ret = -1;
        goto end;
    }

    int nReqType = OSSL_CMP_MSG_get_bodytype( pReqMsg );

    if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR || nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        BIN binSecret = {0,0};

        JS_BIN_set( &binSecret, (unsigned char *)"0123456789ABCDEF", 16 );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );

        if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR )
        {
            unsigned char *pPosSignCert = g_binSignCert.pVal;

            pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
            sk_X509_push( pXCerts, pXSignCert );
            OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
            OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
        }
    }
    else if( nReqType == OSSL_CMP_PKIBODY_KUR )
    {
        unsigned char *pPosSignCert = g_binSignCert.pVal;

        pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );

        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_RR )
    {
        unsigned char *pPosSignCert = g_binSignCert.pVal;

        pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_CERTCONF )
    {
        unsigned char *pPosSignCert = g_binSignCert.pVal;

        pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
    }

    ret = OSSL_CMP_CTX_set_transfer_cb_arg( pCTX, pSrvCTX );
    ret = OSSL_CMP_mock_server_perform( pCTX, pReqMsg, &pRspMsg );

    printf( "mock_server ret: %d\n", ret );

    if( pRspMsg == NULL )
    {
        fprintf( stderr, "Rsp is null\n" );
        ret = -1;
        goto end;
    }

    nOutLen = i2d_OSSL_CMP_MSG( pRspMsg, &pOut );
    if( nOutLen > 0 )
    {
        JS_BIN_set( pRsp, pOut, nOutLen );
        JS_BIN_encodeHex( pRsp, &pHex );
        printf( "Rsp : %s\n", pHex );
    }

end :
    if( pReqMsg ) OSSL_CMP_MSG_free( pReqMsg );
    if( pRspMsg ) OSSL_CMP_MSG_free( pRspMsg );
    if( pHex ) JS_free( pHex );
    if( pOut ) OPENSSL_free( pOut );
    if( pSrvCTX ) OSSL_CMP_SRV_CTX_free( pSrvCTX );
//    if( pXSignCert ) X509_free( pXSignCert );

    return ret;
}

