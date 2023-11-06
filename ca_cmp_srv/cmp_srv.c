#include <stdio.h>
#include <getopt.h>

#include "openssl/cmp.h"

#include "js_pki.h"
#include "js_http.h"
#include "js_db.h"
#include "js_cfg.h"
#include "js_log.h"
#include "js_pkcs11.h"

#include "js_process.h"
#include "cmp_srv.h"
#include "cmp_mock_srv.h"

#ifdef OPENSSL_V3
#include "cmp_mock_srv.h"
#endif

BIN     g_binRootCert = {0,0};
BIN     g_binCACert = {0,0};
BIN     g_binCAPriKey = {0,0};
JP11_CTX        *g_pP11CTX = NULL;

int     g_nCertProfileNum = -1;
int     g_nIssuerNum = -1;
int     g_nPort = 9000;
int     g_nSSLPort = 9100;
int     g_nLogLevel = JS_LOG_LEVEL_INFO;

SSL_CTX     *g_pSSLCTX = NULL;

JEnvList    *g_pEnvList = NULL;

const char* g_dbPath = NULL;
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

    int nStatus = 0;
    int nFailInfo = -2;

    pSrvCTX = ossl_cmp_mock_srv_new( NULL, NULL );
    if( pSrvCTX == NULL ) return NULL;

    OSSL_CMP_SRV_CTX_set_grant_implicit_confirm( pSrvCTX, 1 );

    pCTX = OSSL_CMP_SRV_CTX_get0_cmp_ctx( pSrvCTX );

    pXRootCACert = d2i_X509( NULL, &pPosRootCACert, g_binRootCert.nLen );
    pXCACert = d2i_X509( NULL, &pPosCACert, g_binCACert.nLen );
    pECAPriKey = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosCAPriKey, g_binCAPriKey.nLen );

    pXStore = X509_STORE_new();
    X509_STORE_add_cert( pXStore, pXRootCACert );
    X509_STORE_add_cert( pXStore, pXCACert );
    OSSL_CMP_CTX_set0_trustedStore( pCTX, pXStore );

    OSSL_CMP_CTX_set1_cert( pCTX, pXCACert );

    X509_free( pXCACert );

    OSSL_CMP_CTX_set1_pkey( pCTX, pECAPriKey );

    ossl_cmp_mock_srv_set_checkAfterTime( pSrvCTX, 10 );
    ossl_cmp_mock_srv_set_statusInfo( pSrvCTX, nStatus, nFailInfo, "Status" );

end :
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

    const char *pRspMethod = NULL;

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

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "RecvBin Len: %d", binReq.nLen );

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Path: %s", pPath );

    if( strcasecmp( pPath, "/PING") == 0 )
    {
        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/pkiclient.exe") == 0 )
    {
        ret = procSCEP( db, pParamList, &binReq, &binRsp );
    }
    else if( strcasecmp( pPath, "/CMP" ) == 0 )
    {
        /* read request body */
        ret = procCMP( db, &binReq, &binRsp );
    }

    if( ret != 0 )
    {
        fprintf( stderr, "fail to run ca(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to run ca(%d)", ret );
        goto end;
    }

    pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    JS_UTIL_createNameValList2("accept", "application/cmp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/cmp-response");


    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pRspMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to send message(%d)\n", ret );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to send message(%d)", ret );
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
    int ret = 0;
    int nType = -1;
    char *pPath = NULL;

    BIN     binReq = {0,0};
    BIN     binRsp = {0,0};

    char    *pMethInfo = NULL;
    JNameValList   *pHeaderList = NULL;
    JNameValList   *pRspHeaderList = NULL;
    JNameValList    *pParamList = NULL;
    SSL         *pSSL = NULL;

    const char *pRspMethod = NULL;

    sqlite3* db = JS_DB_open( g_dbPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to accept SSL(%d)\n", ret );
        goto end;
    }

    ret = JS_HTTPS_recvBin( pSSL, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive message(%d)\n", ret );
        goto end;
    }

    JS_HTTP_getMethodPath( pMethInfo, &nType, &pPath, &pParamList );

    if( strcasecmp( pPath, "/PING") == 0 )
    {
        pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    }
    else if( strcasecmp( pPath, "/pkiclient.exe") == 0 )
    {
        ret = procSCEP( db, pParamList, &binReq, &binRsp );
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

    pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    JS_UTIL_createNameValList2("accept", "application/cmp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/cmp-response");


    ret = JS_HTTPS_sendBin( pSSL, pRspMethod, pRspHeaderList, &binRsp );
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
    if( pSSL ) JS_SSL_clear( pSSL );
    if( db ) JS_DB_close( db );
    if( pPath ) JS_free( pPath );

    return 0;
}

int loginHSM()
{
    int ret = 0;
    int nFlags = 0;


    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    int nSlotID = -1;
    const char *pLibPath = NULL;
    const char *pPIN = NULL;
    int nPINLen = 0;
    const char *value = NULL;

    pLibPath = JS_CFG_getValue( g_pEnvList, "CMP_HSM_LIB_PATH" );
    if( pLibPath == NULL )
    {
        fprintf( stderr, "You have to set 'CMP_HSM_LIB_PATH'\n" );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CMP_HSM_SLOT_ID" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CMP_HSM_SLOT_ID'\n" );
        exit(0);
    }

    nSlotID = atoi( value );

    pPIN = JS_CFG_getValue( g_pEnvList, "CMP_HSM_PIN" );
    if( pPIN == NULL )
    {
        fprintf( stderr, "You have to set 'CMP_HSM_PIN'\n" );
        exit(0);
    }

    nPINLen = atoi( pPIN );

    value = JS_CFG_getValue( g_pEnvList, "CMP_HSM_KEY_ID" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CMP_HSM_KEY_ID'\n" );
        exit( 0);
    }

    JS_BIN_decodeHex( value, &g_binCAPriKey );

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, pLibPath );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to load library(%s:%d)\n", value, ret );
        exit(0);
    }

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run initialize(%d)\n", ret );
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, pPIN, nPINLen );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    printf( "HSM login ok\n" );

    return 0;
}

int readPriKey()
{
    int ret = 0;
    const char *value = NULL;

    value = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_ENC" );
    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'CA_PRIKEY_PATH'" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &g_binCAPriKey );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }
    }
    else
    {
        BIN binEnc = {0,0};
        const char *pPasswd = NULL;

        pPasswd = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_PASSWD" );
        if( pPasswd == NULL )
        {
            fprintf( stderr, "You have to set 'CA_PRIKEY_PASSWD'\n" );
            exit(0);
        }

        value = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_PATH" );
        if( value == NULL )
        {
            fprintf( stderr, "You have to set 'CA_PRIKEY_PATH'" );
            exit(0);
        }

        ret = JS_BIN_fileReadBER( value, &binEnc );
        if( ret <= 0 )
        {
            fprintf( stderr, "fail to read private key file(%s:%d)\n", value, ret );
            exit( 0 );
        }

        ret = JS_PKI_decryptPrivateKey( pPasswd, &binEnc, NULL, &g_binCAPriKey );
        if( ret != 0 )
        {
            fprintf( stderr, "invalid password (%d)\n", ret );
            exit(0);
        }
    }
    return 0;
}


int Init()
{
    int ret = 0;
    const char *value = NULL;

    ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) g_nLogLevel = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        ret = JS_LOG_open( value, "CMP", JS_LOG_TYPE_DAILY );
    else
        ret = JS_LOG_open( "log", "CMP", JS_LOG_TYPE_DAILY );

    if( ret != 0 )
    {
        fprintf( stderr, "fail to open logfile:%d\n", ret );
        exit(0);
    }


    value = JS_CFG_getValue( g_pEnvList, "ROOTCA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'ROOTCA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binRootCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to open rootca cert(%s)\n", value );
        exit(0);
    }


    value = JS_CFG_getValue( g_pEnvList, "CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binCACert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to open ca cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        ret = loginHSM();
        if( ret != 0 )
        {
            fprintf( stderr, "fail to login HSM:%d\n", ret );
            exit(0);
        }
    }
    else
    {
        ret = readPriKey();
        if( ret != 0 )
        {
            fprintf( stderr, "fail to read private key:%d\n", ret );
            exit( 0 );
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'DB_PATH'\n" );
        exit(0);
    }

    g_dbPath = JS_strdup( value );

    value = JS_CFG_getValue( g_pEnvList, "CERT_PROFILE" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'CERT_PROFILE'\n" );
        exit(0);
    }

    g_nCertProfileNum = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "ISSUER_NUM" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'ISSUER_NUM'\n" );
        exit(0);
    }

    g_nIssuerNum = atoi( value );

    ret = JS_LOG_open( "./log", "cmp", JS_LOG_TYPE_DAILY );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to open log file\n" );
    }
    JS_LOG_setLevel( JS_LOG_LEVEL_VERBOSE );
    JS_LOG_write( JS_LOG_LEVEL_INFO, "Start CMP Server" );

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCA );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl ca cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &binSSLPri );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl private key(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "CMP_PORT" );
    if( value ) g_nPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "CMP_SSL_PORT" );
    if( value ) g_nSSLPort = atoi( value );

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &binSSLPri, &binSSLCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &binSSLCA );

    JS_BIN_reset( &binSSLCA );
    JS_BIN_reset( &binSSLCert );
    JS_BIN_reset( &binSSLPri );


    printf( "CMP Server Init OK [Port:%d SSL:%d]\n", g_nPort, g_nSSLPort );
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

    sprintf( g_sConfigPath, "%s", "../ca_cmp.cfg" );

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

    JS_THD_logInit( "./log", "net", 2 );
    JS_THD_registerService( "JS_CMP", NULL, g_nPort, 4, NULL, CMP_Service );
    JS_THD_registerService( "JS_CMP_SSL", NULL, g_nSSLPort, 4, NULL, CMP_SSL_Service );
    JS_THD_serviceStartAll();


    return 0;
}
