#include <stdio.h>
#include <getopt.h>

#include "openssl/cmp.h"

#include "js_pki.h"
#include "js_http.h"
#include "js_db.h"

#include "js_process.h"
#include "cmp_srv.h"

BIN     g_binRootCert = {0,0};
BIN     g_binCACert = {0,0};
BIN     g_binCAPriKey = {0,0};

int     g_nCertPolicyNum = 1;
int     g_nIssuerNum = 1;

const char* g_dbPath = "/Users/jykim/work/CAMan/ca.db";
static char g_sBuildInfo[1024];

int g_nVerbose = 0;
static char g_sConfigPath[1024];

const char *getBuildInfo()
{
    sprintf( g_sBuildInfo, "Version: %s Build Date : %s %s",
             JS_CMP_SRV_VERSION, __DATE__, __TIME__ );

    return g_sBuildInfo;
}

OSSL_CMP_SRV_CTX* setupServerCTX()
{
    OSSL_CMP_CTX        *pCTX = NULL;
    OSSL_CMP_SRV_CTX    *pSrvCTX = NULL;
    X509                *pXCACert = NULL;
    X509                *pXRootCACert = NULL;
    EVP_PKEY            *pECAPriKey = NULL;
    X509_STORE          *pXStore = NULL;

    unsigned char *pPosCACert = g_binCACert.pVal;
    unsigned char *pPosCAPriKey = g_binCAPriKey.pVal;
    unsigned char *pPosRootCACert = g_binRootCert.pVal;

    pSrvCTX = OSSL_CMP_SRV_CTX_new();
    if( pSrvCTX == NULL ) return NULL;

    pCTX = OSSL_CMP_SRV_CTX_get0_ctx( pSrvCTX );

    pXRootCACert = d2i_X509( NULL, &pPosRootCACert, g_binRootCert.nLen );
    pXCACert = d2i_X509( NULL, &pPosCACert, g_binCACert.nLen );
    pECAPriKey = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosCAPriKey, g_binCAPriKey.nLen );

    pXStore = X509_STORE_new();
    X509_STORE_add_cert( pXStore, pXRootCACert );
    X509_STORE_add_cert( pXStore, pXCACert );
    OSSL_CMP_CTX_set0_trustedStore( pCTX, pXStore );

    OSSL_CMP_CTX_set1_clCert( pCTX, pXCACert );

    X509_free( pXCACert );

    OSSL_CMP_CTX_set0_pkey( pCTX, pECAPriKey );
//    OSSL_CMP_SRV_CTX_set_pollCount( pSrvCTX, 2 );
    OSSL_CMP_SRV_CTX_set_checkAfterTime( pSrvCTX, 1 );

    int nStatus = 0;
    int nFailInfo = -1;

    OSSL_CMP_SRV_CTX_set_statusInfo( pSrvCTX, nStatus, nFailInfo, "Status" );


    return pSrvCTX;
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
    JNameValList    *pParamList = NULL;

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

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

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
    if( pParamList ) JS_UTIL_resetNameValList( &pParamList );

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

    return 0;
}

void printUsage()
{
    printf( "JS CA_CMP Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config : set config file(%s)\n", g_sConfigPath );
    printf( "-h         : Print this message\n" );
}

int main( int argc, char *argv[] )
{
    int     nOpt = 0;

    sprintf( g_sConfigPath, "%s", "ca_cmp.cfg" );

    while(( nOpt = getopt( argc, argv, "c:vh")) != -1 )
    {
        switch ( nOpt ) {
        case 'h' :
            printUsage();
            return 0;

       case 'v' :
            g_nVerbose = 1;
            break;

        case 'c' :
            sprintf( g_sConfigPath, "%s", optarg );
            break;
        }
    }

    Init();

    JS_THD_logInit( "./log", "cmp", 2 );
    JS_THD_registerService( "JS_CMP", NULL, 9000, 4, NULL, CMP_Service );
    JS_THD_registerService( "JS_CMP_SSL", NULL, 9100, 4, NULL, CMP_SSL_Service );
    JS_THD_serviceStartAll();


    return 0;
}
