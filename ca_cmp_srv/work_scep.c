#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"
#include "js_db.h"
#include "js_pki_ext.h"
#include "js_pki_internal.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_log.h"
#include "js_pkcs7.h"
#include "js_scep.h"

#include "cmp_srv.h"


extern BIN     g_binRootCert;
extern BIN     g_binCACert;
extern BIN     g_binCAPriKey;

extern BIN     g_binSignCert;
extern BIN     g_binSignPri;

extern int      g_nCertPolicyNum;
extern int      g_nIssuerNum;

int runPKIReq( sqlite3* db, const BIN *pSignCert, const BIN *pEnvData, BIN *pCertRsp )
{
    int ret = 0;
    BIN binDevData = {0,0};
    JReqInfo sReqInfo;

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));

    ret = JS_PKCS7_makeDevelopedData( pEnvData, &g_binCAPriKey, &g_binCACert, &binDevData );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to develop data : %d\n", ret );
        goto end;
    }

    ret = JS_PKI_getReqInfo( &binDevData, &sReqInfo, NULL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to parse request : %d\n", ret );
        goto end;
    }

end :
    JS_BIN_reset( &binDevData );
    JS_PKI_resetReqInfo( &sReqInfo );

    return ret;
}

int workPKIOperation( sqlite3* db, const BIN *pPKIReq, BIN *pCertRsp )
{
    int ret = 0;
    int nType = 0;

    BIN binSignCert = {0,0};
    BIN binSenderNonce = {0,0};
    char *pTransID = NULL;
    BIN binData = {0,0};

    ret = JS_SCEP_verifyParseSignedData( pPKIReq, &nType, &binSignCert, &binSenderNonce, &pTransID, &binData );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to veriyf signeddata : %d\n", ret );
        goto end;
    }

    if( nType == JS_SCEP_REQUEST_PKCSREQ )
    {
        ret = runPKIReq( db, &binSignCert, &binData, pCertRsp );
    }
    else if( nType == JS_SCEP_REQUEST_GETCRL )
    {

    }
    else if( nType == JS_SCEP_REQUEST_GETCERT )
    {

    }
    else if( nType == JS_SCEP_REQUEST_GETCERTINIT )
    {

    }
    else
    {
        fprintf( stderr, "Invalid request type : %d\n", nType );
        ret = -1;
        goto end;
    }


end :
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binSenderNonce );
    JS_BIN_reset( &binData );
    if( pTransID ) JS_free( pTransID );

    return ret;
}


int procSCEP( sqlite3* db, const JNameValList *pParamList, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    const char *pOper = NULL;
    JS_UTIL_printNameValList( stdout, "ParamList", pParamList );

    pOper = JS_UTIL_valueFromNameValList( pParamList, "operation" );

    if( pOper == NULL )
    {
        fprintf( stderr, "There is no operation\n" );
        return -1;
    }

    if( strcasecmp( pOper, "GetCACaps") == 0 )
    {
        const char *pMsg = "POSTPKIOperation\r\nRenewal\r\nSHA-1";
        JS_BIN_set( pRsp, pMsg, strlen( pMsg ) );
    }
    else if( strcasecmp( pOper, "GetCACert" ) == 0 )
    {
        JS_BIN_copy( pRsp, &g_binCACert );
    }
    else if( strcasecmp( pOper, "PKIOperation" ) == 0 )
    {
        ret = workPKIOperation( db, pReq, pRsp );
    }
    else
    {
        fprintf( stderr, "invalid operation : %s\n", pOper );
        return -1;
    }

    return ret;
}
