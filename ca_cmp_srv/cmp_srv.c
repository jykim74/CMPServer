#include <stdio.h>

#include "openssl/cmp.h"

#include "js_pki.h"
#include "js_process.h"
#include "cmp_srv.h"

BIN     g_binRootCert = {0,0};
BIN     g_binCACert = {0,0};
BIN     g_binCAPriKey = {0,0};

OSSL_CMP_SRV_CTX* setupServerCTX()
{
    OSSL_CMP_CTX        *pCTX = NULL;
    OSSL_CMP_SRV_CTX    *pSrvCTX = NULL;
    X509                *pXCACert = NULL;
    EVP_PKEY            *pECAPriKey = NULL;

    unsigned char *pPosCACert = g_binCACert.pVal;
    unsigned char *pPosCAPriKey = g_binCAPriKey.pVal;

    pSrvCTX = OSSL_CMP_SRV_CTX_new();
    if( pSrvCTX == NULL ) return -1;

    pCTX = OSSL_CMP_SRV_CTX_get0_ctx( pSrvCTX );

    pXCACert = d2i_X509( NULL, &pPosCACert, g_binCACert.nLen );
    pECAPriKey = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosCAPriKey, g_binCAPriKey.nLen );

    OSSL_CMP_CTX_set1_clCert( pCTX, pXCACert );
    X509_free( pXCACert );

    OSSL_CMP_CTX_set0_pkey( pCTX, pECAPriKey );
    OSSL_CMP_SRV_CTX_set_pollCount( pSrvCTX, 2 );
    OSSL_CMP_SRV_CTX_set_checkAfterTime( pSrvCTX, 1 );

    int nStatus = 0;
    int nFailInfo = -1;

    OSSL_CMP_SRV_CTX_set_statusInfo( pSrvCTX, nStatus, nFailInfo, "Status" );


    return pSrvCTX;
}

int CMP_Service( JThreadInfo *pThInfo )
{
    int ret = 0;
    OSSL_CMP_MSG    *pReqMsg = NULL;
    OSSL_CMP_MSG    *pRspMsg = NULL;

    OSSL_CMP_CTX *pCTX = OSSL_CMP_CTX_new();
    OSSL_CMP_SRV_CTX *pSrvCTX = setupServerCTX();

    /* read request body */

    ret = OSSL_CMP_CTX_set_transfer_cb( pCTX, pSrvCTX );
    ret = OSSL_CMP_mock_server_perform( pCTX, pReqMsg, &pRspMsg );

    /* send response body */

    return 0;
}

int CMP_SSL_Service( JThreadInfo *pThInfo )
{
    return 0;
}

int Init()
{
    const char  *pRootCertPath = "./root_ca_cert.der";
    const char  *pCACertPath = "./ca_cert.der";
    const char  *pCAPriKeyPath = "./ca_pri_key.der";

    JS_BIN_fileRead( pRootCertPath, &g_binRootCert );
    JS_BIN_fileRead( pCACertPath, &g_binCACert );
    JS_BIN_fileRead( pCAPriKeyPath, &g_binCAPriKey );

    return 0;
}

int main( int argc, char *argv[] )
{
    Init();

    JS_THD_logInit( "./log", "cmp", 2 );
    JS_THD_registerService( "JS_CMP", NULL, 9010, 4, NULL, CMP_Service );
    JS_THD_registerService( "JS_CMP_SSL", NULL, 9110, 4, NULL, CMP_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
