#include <stdio.h>

#include "openssl/cmp.h"

#include "js_pki.h"
#include "js_http.h"
#include "js_db.h"

#include "js_process.h"
#include "cmp_srv.h"

BIN     g_binRootCert = {0,0};
BIN     g_binCACert = {0,0};
BIN     g_binCAPriKey = {0,0};

BIN     g_binSignCert = {0,0};
BIN     g_binSignPri = {0,0};

int     g_nCertPolicyNum = 1;
int     g_nIssuerNum = 1;

const char* g_dbPath = "/Users/jykim/work/CAMan/ca.db";

OSSL_CMP_SRV_CTX* setupServerCTX()
{
    OSSL_CMP_CTX        *pCTX = NULL;
    OSSL_CMP_SRV_CTX    *pSrvCTX = NULL;
    X509                *pXCACert = NULL;
    X509                *pXRootCACert = NULL;
    EVP_PKEY            *pECAPriKey = NULL;
 //   X509                *pXSignCert = NULL;
    X509_STORE          *pXStore = NULL;

    unsigned char *pPosCACert = g_binCACert.pVal;
    unsigned char *pPosCAPriKey = g_binCAPriKey.pVal;
    unsigned char *pPosRootCACert = g_binRootCert.pVal;
//    unsigned char *pPosSignCert = g_binSignCert.pVal;

    pSrvCTX = OSSL_CMP_SRV_CTX_new();
    if( pSrvCTX == NULL ) return NULL;

    pCTX = OSSL_CMP_SRV_CTX_get0_ctx( pSrvCTX );

    pXRootCACert = d2i_X509( NULL, &pPosRootCACert, g_binRootCert.nLen );
    pXCACert = d2i_X509( NULL, &pPosCACert, g_binCACert.nLen );
    pECAPriKey = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosCAPriKey, g_binCAPriKey.nLen );

    /* 결과 인증서를 테스트로 미리 넣어줌 */
//    pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
//    OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );

    pXStore = X509_STORE_new();
    X509_STORE_add_cert( pXStore, pXRootCACert );
    X509_STORE_add_cert( pXStore, pXCACert );
    OSSL_CMP_CTX_set0_trustedStore( pCTX, pXStore );

    OSSL_CMP_CTX_set1_clCert( pCTX, pXCACert );
//    OSSL_CMP_CTX_set1_srvCert( pCTX, pXCACert );

    X509_free( pXCACert );

    OSSL_CMP_CTX_set0_pkey( pCTX, pECAPriKey );
//    OSSL_CMP_SRV_CTX_set_pollCount( pSrvCTX, 2 );
    OSSL_CMP_SRV_CTX_set_checkAfterTime( pSrvCTX, 1 );

    int nStatus = 0;
    int nFailInfo = -1;

    OSSL_CMP_SRV_CTX_set_statusInfo( pSrvCTX, nStatus, nFailInfo, "Status" );


    return pSrvCTX;
}

OSSL_CMP_MSG* makeReq( OSSL_CMP_CTX *pCTX, int nType )
{
    int     ret = 0;
    int     nErrCode = -1;

    int     nOutLen = 0;
    unsigned char       *pOut = NULL;
    char        *pHex = NULL;
    X509        *pXSignCert = NULL;
    EVP_PKEY    *pESignPri = NULL;

    const unsigned char *pPosSignCert = NULL;
    const unsigned char *pPosSignPri = NULL;


    OSSL_CMP_MSG    *pMsg = NULL;

    pPosSignCert = g_binSignCert.pVal;
    pPosSignPri = g_binSignPri.pVal;

    pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
    pESignPri = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosSignPri, g_binSignPri.nLen );

    if( nType == OSSL_CMP_PKIBODY_IR || nType == OSSL_CMP_PKIBODY_CR  )
    {
        BIN binRef = {0,0};
        BIN binSecret = {0,0};

        JS_BIN_set( &binRef, (unsigned char *)"0123456789", 10 );
        JS_BIN_set( &binSecret, (unsigned char *)"0123456789ABCDEF", 16 );

        OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );

        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
        OSSL_CMP_CTX_set1_newPkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_KUR )
    {
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
        OSSL_CMP_CTX_set1_newPkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_RR )
    {
        int nReason = CRL_REASON_SUPERSEDED;
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
        OSSL_CMP_CTX_set1_oldClCert( pCTX, pXSignCert );
        (void)OSSL_CMP_CTX_set_option( pCTX, OSSL_CMP_OPT_REVOCATION_REASON, nReason );
    }
    else if( nType == OSSL_CMP_PKIBODY_GENM )
    {
        BIN binRef = {0,0};
        BIN binSecret = {0,0};

        JS_BIN_set( &binRef, (unsigned char *)"0123456789", 10 );
        JS_BIN_set( &binSecret, (unsigned char *)"0123456789ABCDEF", 16 );

        OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
//        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
//        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_CERTCONF )
    {
//        OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );
//        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );

        CMP_CTX_set1_newClCert( pCTX, pXSignCert );
    }



    if( nType == OSSL_CMP_PKIBODY_CR
            || nType == OSSL_CMP_PKIBODY_IR
            || nType == OSSL_CMP_PKIBODY_P10CR
            || nType == OSSL_CMP_PKIBODY_KUR )
    {
        pMsg = OSSL_CMP_certreq_new( pCTX, nType, nErrCode );
    }
    else if( nType == OSSL_CMP_PKIBODY_RR )
    {
        pMsg = OSSL_CMP_rr_new( pCTX );
    }
    else if( nType == OSSL_CMP_PKIBODY_GENM )
    {
        pMsg = OSSL_CMP_genm_new( pCTX );
    }
    else if( nType == OSSL_CMP_PKIBODY_CERTCONF )
    {
        pMsg = OSSL_CMP_certConf_new( pCTX, nErrCode, "CertConf" );
    }
    else
    {
        fprintf( stderr, "Invalid Req Type(%d)\n", nType );
        return -1;
    }

    if( pMsg == NULL )
    {
        fprintf( stderr, "fail to get CMP_MSG\n" );
        return NULL;
    }

    return pMsg;
}

int CMP_TestService( JThreadInfo *pThInfo )
{
    int ret = 0;

//    int     nType = OSSL_CMP_PKIBODY_IR;
//    int     nType = OSSL_CMP_PKIBODY_CR;
//    int     nType = OSSL_CMP_PKIBODY_RR;
    int     nType = OSSL_CMP_PKIBODY_KUR;
//    int     nType = OSSL_CMP_PKIBODY_GENM;
//    int     nType = OSSL_CMP_PKIBODY_CERTCONF;

    BIN     binRsp = {0,0};
    char    *pHex = NULL;

    OSSL_CMP_MSG    *pReqMsg = NULL;
    OSSL_CMP_MSG    *pRspMsg = NULL;

    OSSL_CMP_CTX *pCliCTX = OSSL_CMP_CTX_new();
    OSSL_CMP_SRV_CTX *pSrvCTX = setupServerCTX();
    OSSL_CMP_CTX *pCTX = OSSL_CMP_SRV_CTX_get0_ctx( pSrvCTX );
    STACK_OF(X509) *pXCerts = NULL;

    int     nOutLen = 0;
    unsigned char   *pOut = NULL;

    /* read request body */

    pReqMsg = makeReq( pCliCTX, nType );
    if( pReqMsg == NULL )
    {
        fprintf( stderr, "ReqMsg is null\n" );
        return -1;
    }

    int nReqType = OSSL_CMP_MSG_get_bodytype( pReqMsg );
    pXCerts = sk_X509_new_null();

    if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR || nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        BIN binSecret = {0,0};

        JS_BIN_set( &binSecret, (unsigned char *)"0123456789ABCDEF", 16 );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_KUR )
    {
        unsigned char *pPosSignCert = g_binSignCert.pVal;
        X509 *pXSignCert = NULL;

        pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_RR )
    {
        unsigned char *pPosSignCert = g_binSignCert.pVal;
        X509 *pXSignCert = NULL;

        pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );

        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_CERTCONF )
    {
        unsigned char *pPosSignCert = g_binSignCert.pVal;
        X509 *pXSignCert = NULL;

        sk_X509_push( pXCerts, pXSignCert );
        pXSignCert = d2i_X509( NULL, &pPosSignCert, g_binSignCert.nLen );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXCerts );
    }

    ret = OSSL_CMP_CTX_set_transfer_cb_arg( pCTX, pSrvCTX );
    ret = OSSL_CMP_mock_server_perform( pCTX, pReqMsg, &pRspMsg );

    printf( "mock_server ret: %d\n", ret );

    if( pRspMsg == NULL )
    {
        fprintf( stderr, "Rsp is null\n" );
        return -1;
    }

    nOutLen = i2d_OSSL_CMP_MSG( pRspMsg, &pOut );
    if( nOutLen > 0 )
    {
        JS_BIN_set( &binRsp, pOut, nOutLen );
        JS_BIN_encodeHex( &binRsp, &pHex );
        printf( "Rsp : %s\n", pHex );
    }

    /* send response body */

    return 0;
}


int CMP_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    int nType = -1;
    char *pPath = NULL;

    BIN     binReq = {0,0};
    BIN     binRsp = {0,0};

    char    *pMethInfo = NULL;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath );

    if( strcasecmp( pPath, "/PING") == 0 )
    {

    }
    else if( strcasecmp( pPath, "/CMP" ) == 0 )
    {
        /* read request body */
        ret = procCMP( db, &binReq, &binRsp );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to run CMP(%d)\n", ret );
            goto end;
        }
    }

    JS_UTIL_createNameValList2("accept", "application/cmp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/cmp-response");

    ret = JS_HTTP_sendBin( pThInfo->nSockFd, JS_HTTP_OK, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        goto end;
    }
    /* send response body */
end:
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pHeaderList ) JS_UTIL_resetNameValList( &pHeaderList );
    if( pRspHeaderList ) JS_UTIL_resetNameValList( &pRspHeaderList );

    if( pMethInfo ) JS_free( pMethInfo );
    if( db ) JS_DB_close( db );
    if( pPath ) JS_free( pPath );

    return 0;
}


int CMP_SSL_Service( JThreadInfo *pThInfo )
{
    return 0;
}

int Init()
{
    const char  *pRootCertPath = "/Users/jykim/work/PKITester/data/root_ca_cert.der";
    const char  *pCACertPath = "/Users/jykim/work/PKITester/data/ca_cert.der";
    const char  *pCAPriKeyPath = "/Users/jykim/work/PKITester/data/ca_prikey.der";

    const char *pSignCertPath = "/Users/jykim/work/PKITester/data/user_cert.der";
    const char *pSignPriPath = "/Users/jykim/work/PKITester/data/user_prikey.der";

    JS_BIN_fileRead( pRootCertPath, &g_binRootCert );
    JS_BIN_fileRead( pCACertPath, &g_binCACert );
    JS_BIN_fileRead( pCAPriKeyPath, &g_binCAPriKey );
    JS_BIN_fileRead( pSignCertPath, &g_binSignCert );
    JS_BIN_fileRead( pSignPriPath, &g_binSignPri );

    return 0;
}

int main( int argc, char *argv[] )
{
    Init();

//    return CMP_TestService( NULL );


    JS_THD_logInit( "./log", "cmp", 2 );
    JS_THD_registerService( "JS_CMP", NULL, 9000, 4, NULL, CMP_Service );
    JS_THD_registerService( "JS_CMP_SSL", NULL, 9100, 4, NULL, CMP_SSL_Service );
    JS_THD_serviceStartAll();


    return 0;
}
