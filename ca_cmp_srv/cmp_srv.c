#include <stdio.h>
#include <getopt.h>

#include "openssl/cmp.h"

#include "js_gen.h"
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
int     g_nMsgDump = 0;

int     g_nCertProfileNum = -1;
int     g_nIssuerNum = -1;
int     g_nPort = 9000;
int     g_nSSLPort = 9100;
int     g_nLogLevel = JS_LOG_LEVEL_INFO;

SSL_CTX     *g_pSSLCTX = NULL;

JEnvList    *g_pEnvList = NULL;

int     g_nConfigDB = 0;
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
        LE( "fail to open db file(%s)", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_HTTP_recvBin( pThInfo->nSockFd, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
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
        LE( "fail to run ca(%d)", ret );
        goto end;
    }

    pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    JS_UTIL_createNameValList2("accept", "application/cmp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/cmp-response");


    ret = JS_HTTP_sendBin( pThInfo->nSockFd, pRspMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        LE( "fail to send message(%d)", ret );
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
        LE( "fail to open db file(%s)", g_dbPath );
        ret = -1;
        goto end;
    }

    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        LE( "fail to accept SSL(%d)", ret );
        goto end;
    }

    ret = JS_HTTPS_recvBin( pSSL, &pMethInfo, &pHeaderList, &binReq );
    if( ret != 0 )
    {
        LE( "fail to receive message(%d)", ret );
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
            LE( "fail to run CMP(%d)", ret );
            goto end;
        }
    }

    pRspMethod = JS_HTTP_getStatusMsg( JS_HTTP_STATUS_OK );
    JS_UTIL_createNameValList2("accept", "application/cmp-response", &pRspHeaderList);
    JS_UTIL_appendNameValList2( pRspHeaderList, "content-type", "application/cmp-response");


    ret = JS_HTTPS_sendBin( pSSL, pRspMethod, pRspHeaderList, &binRsp );
    if( ret != 0 )
    {
        LE( "fail to send message(%d)", ret );
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
        LE( "You have to set 'CMP_HSM_LIB_PATH'" );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "CMP_HSM_SLOT_ID" );
    if( value == NULL )
    {
        LE( "You have to set 'CMP_HSM_SLOT_ID'" );
        return -1;
    }

    nSlotID = atoi( value );

    pPIN = JS_CFG_getValue( g_pEnvList, "CMP_HSM_PIN" );
    if( pPIN == NULL )
    {
        LE( "You have to set 'CMP_HSM_PIN'" );
        return -1;
    }

    nPINLen = atoi( pPIN );

    value = JS_CFG_getValue( g_pEnvList, "CMP_HSM_KEY_ID" );
    if( value == NULL )
    {
        LE( "You have to set 'CMP_HSM_KEY_ID'" );
        return -1;
    }

    JS_BIN_decodeHex( value, &g_binCAPriKey );

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, pLibPath );
    if( ret != 0 )
    {
        LE( "fail to load library(%s:%d)", value, ret );
        return -1;
    }

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
    if( ret != CKR_OK )
    {
        LE( "fail to run initialize(%d)", ret );
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        LE( "fail to run getSlotList fail(%d)", ret );
        return -1;
    }

    if( uSlotCnt < 1 )
    {
        LE( "there is no slot(%d)", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[nSlotID], nFlags );
    if( ret != CKR_OK )
    {
        LE( "fail to run opensession(%s:%x)", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, pPIN, nPINLen );
    if( ret != 0 )
    {
        LE( "fail to run login hsm(%d)", ret );
        return -1;
    }

    LI( "HSM login ok\n" );

    return 0;
}

int readPriKeyDB( sqlite3 *db )
{
    int ret = 0;
    const char *value = NULL;
    JDB_KeyPair sKeyPair;

    memset( &sKeyPair, 0x00, sizeof(sKeyPair));

    value = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_NUM" );
    if( value == NULL )
    {
        LE( "You have to set 'CA_PRIKEY_NUM'" );
        return -1;
    }

    ret = JS_DB_getKeyPair(db, atoi(value), &sKeyPair );
    if( ret != 1 )
    {
        LE( "There is no key pair: %d", atoi(value));
        return -1;
    }

    // 암호화 경우 복호화 필요함
    value = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_ENC" );

    if( value && strcasecmp( value, "NO" ) == 0 )
    {
        JS_BIN_decodeHex( sKeyPair.pPrivate, &g_binCAPriKey );

        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -1;
        }
    }
    else
    {
        BIN binEnc = {0,0};
        const char *pPasswd = NULL;

        pPasswd = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_PASSWD" );
        if( pPasswd == NULL )
        {
            LE( "You have to set 'CA_PRIKEY_PASSWD'" );
            return -1;
        }

        JS_BIN_decodeHex( sKeyPair.pPrivate, &binEnc );

        ret = JS_PKI_decryptPrivateKey( pPasswd, &binEnc, NULL, &g_binCAPriKey );
        if( ret != 0 )
        {
            LE( "invalid password (%d)", ret );
            return -1;
        }

        JS_BIN_reset( &binEnc );
    }

    JS_DB_resetKeyPair( &sKeyPair );

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
            LE( "You have to set 'CA_PRIKEY_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binCAPriKey );
        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -1;
        }
    }
    else
    {
        BIN binEnc = {0,0};
        const char *pPasswd = NULL;

        pPasswd = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_PASSWD" );
        if( pPasswd == NULL )
        {
            LE( "You have to set 'CA_PRIKEY_PASSWD'" );
            return -1;
        }

        value = JS_CFG_getValue( g_pEnvList, "CA_PRIKEY_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_PRIKEY_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &binEnc );
        if( ret <= 0 )
        {
            LE( "fail to read private key file(%s:%d)", value, ret );
            return -1;
        }

        ret = JS_PKI_decryptPrivateKey( pPasswd, &binEnc, NULL, &g_binCAPriKey );
        if( ret != 0 )
        {
            LE( "invalid password (%d)", ret );
            return -1;
        }
    }
    return 0;
}


int Init( sqlite3* db )
{
    int ret = 0;
    const char *value = NULL;

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

    value = JS_CFG_getValue( g_pEnvList, "CMP_MSG_DUMP" );
    if( value )
    {
        if( strcasecmp( value, "yes" ) == 0 )
            g_nMsgDump = 1;
    }

    if( g_nConfigDB == 1 )
    {

        JDB_Cert sCert;
        memset( &sCert, 0x00, sizeof(sCert));

        value = JS_CFG_getValue( g_pEnvList, "ROOTCA_CERT_NUM" );
        if( value == NULL )
        {
            LE( "You have to set 'ROOTCA_CERT_NUM'" );
            return -1;
        }

        JS_DB_getCert( db, atoi(value), &sCert );
        ret = JS_BIN_decodeHex( sCert.pCert, &g_binRootCert );

        JS_DB_resetCert( &sCert );

        value = JS_CFG_getValue( g_pEnvList, "CA_CERT_NUM" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_CERT_NUM'" );
            return -1;
        }

        JS_DB_getCert( db, atoi(value), &sCert );
        ret = JS_BIN_decodeHex( sCert.pCert, &g_binCACert );

        JS_DB_resetCert( &sCert );
    }
    else
    {
        value = JS_CFG_getValue( g_pEnvList, "ROOTCA_CERT_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'ROOTCA_CERT_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binRootCert );
        if( ret <= 0 )
        {
            LE( "fail to open rootca cert(%s)", value );
            return -1;
        }

        value = JS_CFG_getValue( g_pEnvList, "CA_CERT_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'CA_CERT_PATH'" );
            return -1;
        }

        ret = JS_BIN_fileReadBER( value, &g_binCACert );
        if( ret <= 0 )
        {
            LE( "fail to open ca cert(%s)", value );
            return -1;
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "CA_HSM_USE" );
    if( value && strcasecmp( value, "YES" ) == 0 )
    {
        ret = loginHSM();
        if( ret != 0 )
        {
            LE( "fail to login HSM:%d", ret );
            return -1;
        }
    }
    else
    {
        if( g_nConfigDB == 1 )
            ret = readPriKeyDB( db );
        else
            ret = readPriKey();

        if( ret != 0 )
        {
            LE( "fail to read private key:%d", ret );
            return ret;
        }
    }

    if( g_dbPath == NULL || g_nConfigDB == 0 )
    {
        value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
        if( value == NULL )
        {
            LE( "You have to set 'DB_PATH'" );
            return -1;
        }

        g_dbPath = JS_strdup( value );
        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            LE( "The data file is no exist[%s]", g_dbPath );
            return -1;
        }
    }

    value = JS_CFG_getValue( g_pEnvList, "CERT_PROFILE" );
    if( value == NULL )
    {
        LE( "You have to set 'CERT_PROFILE'" );
        return -1;
    }

    g_nCertProfileNum = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "ISSUER_NUM" );
    if( value == NULL )
    {
        LE( "You have to set 'ISSUER_NUM'" );
        return -1;
    }

    g_nIssuerNum = atoi( value );

    BIN binSSLCA = {0,0};
    BIN binSSLCert = {0,0};
    BIN binSSLPri = {0,0};

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_CA_CERT_PATH'" );
        return -1;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCA );
    if( ret <= 0 )
    {
        LE( "fail to read ssl ca cert(%s)", value );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_CERT_PATH'" );
        return -1;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLCert );
    if( ret <= 0 )
    {
        LE( "fail to read ssl cert(%s)", value );
        return -1;
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        LE( "You have to set 'SSL_PRIKEY_PATH'" );
        return -1;
    }

    ret = JS_BIN_fileReadBER( value, &binSSLPri );
    if( ret <= 0 )
    {
        LE( "fail to read ssl private key(%s)", value );
        return -1;
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


    LI( "CMP Server Init OK [Port:%d SSL:%d]", g_nPort, g_nSSLPort );
    return 0;
}

void printUsage()
{
    printf( "JS CA_CMP Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config : set config file(%s)\n", g_sConfigPath );
    printf( "-d dbfile  : Use DB config(%d)\n", g_nConfigDB );
    printf( "-h         : Print this message\n" );
}

int main( int argc, char *argv[] )
{
    int     ret = 0;
    int     nOpt = 0;
    sqlite3*    db = NULL;

    sprintf( g_sConfigPath, "%s", "../ca_cmp.cfg" );

    while(( nOpt = getopt( argc, argv, "c:d:vh")) != -1 )
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

        case 'd' :
            g_dbPath = JS_strdup( optarg );
            g_nConfigDB = 1;
            break;
        }
    }

    if( g_nConfigDB == 1 )
    {
        JDB_ConfigList *pConfigList = NULL;

        if( JS_UTIL_isFileExist( g_dbPath ) == 0 )
        {
            fprintf( stderr, "The data file is no exist[%s]\n", g_dbPath );
            exit(0);
        }

        db = JS_DB_open( g_dbPath );
        if( db == NULL )
        {
            fprintf( stderr, "fail to open db file(%s)\n", g_dbPath );
            exit(0);
        }

        ret = JS_DB_getConfigListByKind( db, JS_GEN_KIND_CMP_SRV, &pConfigList );

        ret = JS_CFG_readConfigFromDB( pConfigList, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }


        if( pConfigList ) JS_DB_resetConfigList( &pConfigList );
    }
    else
    {
        ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
            exit(0);
        }
    }

    ret = Init( db );
    if( ret != 0 )
    {
        LE( "fail to initialize server: %d", ret );
        exit( 0 );
    }

    if( g_nConfigDB == 1 )
    {
        if( db ) JS_DB_close( db );
    }

    JS_THD_logInit( "./log", "net", 2 );
    JS_THD_registerService( "JS_CMP", NULL, g_nPort, 4, CMP_Service );
    JS_THD_registerService( "JS_CMP_SSL", NULL, g_nSSLPort, 4, CMP_SSL_Service );
    JS_THD_registerAdmin( NULL, g_nPort+10 );
    JS_THD_serviceStartAll();


    return 0;
}
