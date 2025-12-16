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
#include "js_log.h"
#include "js_gen.h"

#include "cmp_srv.h"


extern BIN     g_binRootCert;
extern BIN     g_binCACert;
extern BIN     g_binCAPriKey;

extern BIN     g_binSignCert;
extern BIN     g_binSignPri;

extern JP11_CTX *g_pP11CTX;

extern int      g_nCertProfileNum;
extern int      g_nIssuerNum;

int runPKIReq( sqlite3* db, const BIN *pSignCert, const BIN *pData, BIN *pSignedData )
{
    int ret = 0;

    JReqInfo sReqInfo;
    JDB_CertProfile sDBCertProfile;
    JDB_ProfileExtList *pDBProfileExtList = NULL;
    JIssueCertInfo sIssueCertInfo;
    time_t tNotBefore = -1;
    time_t tNotAfter = -1;

    char    sSerial[128];
    int nSeq = 0;
    int nKeyType = -1;
    BIN binPub = {0,0};
    BIN binNewCert = {0,0};

    JCertInfo   sNewCertInfo;
    JDB_Cert    sNewDBcert;
    char        sKeyID[128];

    char        *pHexCert = NULL;

    memset( &sReqInfo, 0x00, sizeof(sReqInfo));
    memset( &sDBCertProfile, 0x00, sizeof(sDBCertProfile));
    memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
    memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));
    memset( &sNewDBcert, 0x00, sizeof(sNewDBcert));
    memset( &sKeyID, 0x00, sizeof(sKeyID));

    ret = JS_DB_getCertProfile( db, g_nCertProfileNum, &sDBCertProfile );
    if( ret != 1 )
    {
        LE( "fail get certificate profile: %d", ret );
        goto end;
    }

    ret = JS_DB_getCertProfileExtList( db, sDBCertProfile.nNum, &pDBProfileExtList );

    time_t now_t = time(NULL);

    if( sDBCertProfile.tNotBefore <= 0 )
    {
        tNotBefore = 0;
        tNotAfter = sDBCertProfile.tNotAfter * 60 * 60 * 24;
        tNotBefore = 0;
    }
    else
    {
        tNotBefore = sDBCertProfile.tNotBefore - now_t;
        tNotAfter = sDBCertProfile.tNotAfter - now_t;
    }

    ret = JS_PKI_getReqInfo( pData, &sReqInfo, 1, NULL );
    if( ret != 0 )
    {
        LE( "fail to parse request : %d", ret );
        goto end;
    }

    JS_BIN_decodeHex( sReqInfo.pPublicKey, &binPub );
    nKeyType = JS_PKI_getPubKeyType( &binPub );
    JS_PKI_getKeyIdentifier( &binPub, sKeyID );

    nSeq = JS_DB_getNextVal( db, "TB_CERT" );

    sprintf( sSerial, "%d", nSeq );

    JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                             sDBCertProfile.nVersion,
                             sSerial,
                             sDBCertProfile.pHash,
                             sReqInfo.pSubjectDN,
                             tNotBefore,
                             tNotAfter,
                             nKeyType,
                             sReqInfo.pPublicKey );

    ret = makeCert( &sDBCertProfile, pDBProfileExtList, &sIssueCertInfo, &binNewCert );
    if( ret != 0 )
    {
        LE( "fail to make certificate : %d", ret );
        goto end;
    }

    JS_BIN_encodeHex( &binNewCert, &pHexCert );

    ret = JS_PKI_getCertInfo( &binNewCert, &sNewCertInfo, NULL );
    if( ret != 0 )
    {
        LE( "fail to get certificate information: %d", ret );
        goto end;
    }

    JS_DB_setCert( &sNewDBcert,
                   -1,
                   now_t,
                  tNotBefore,
                  tNotAfter,
                   -1,
                   -1,
                   sNewCertInfo.pSignAlgorithm,
                   pHexCert,
                   0,
                   0,
                   g_nIssuerNum,
                   sNewCertInfo.pSubjectName,
                   0,
                   sNewCertInfo.pSerial,
                   sNewCertInfo.pDNHash,
                   sKeyID,
                   "" );

    ret = JS_DB_addCert( db, &sNewDBcert );
    if( ret != 0 )
    {
        LE( "fail to add certifciate information to db: %d", ret );
        goto end;
    }

    ret = JS_SCEP_genSignedDataWithoutSign( &binNewCert, NULL, pSignedData );
    if( ret != 0 )
    {
        LE( "fail to make response signeddata : %d", ret );
        goto end;
    }

    LI( "SignedData Length : %d", pSignedData->nLen );

end :
    JS_PKI_resetReqInfo( &sReqInfo );
    JS_DB_resetCertProfile( &sDBCertProfile );
    if( pDBProfileExtList ) JS_DB_resetProfileExtList( &pDBProfileExtList );
    JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
    JS_BIN_reset( &binPub );
    JS_PKI_resetCertInfo( &sNewCertInfo );
    JS_DB_resetCert( &sNewDBcert );
    if( pHexCert ) JS_free( pHexCert );
    JS_BIN_reset( &binNewCert );

    return ret;
}

int runGetCRL( sqlite3* db, const BIN *pSignCert, const BIN *pData, BIN *pSignedData )
{
    int ret = 0;
    PKCS7_ISSUER_AND_SERIAL *pXIAS = NULL;
    const unsigned char *pPos = pData->pVal;
    BIN binCRL = {0,0};
    JDB_CRL sDBCRL;

    memset( &sDBCRL, 0x00, sizeof(sDBCRL));

    pXIAS = d2i_PKCS7_ISSUER_AND_SERIAL( NULL, &pPos, pData->nLen );

    ret = JS_DB_getLatestCRL( db, g_nIssuerNum, &sDBCRL );
    if( ret < 1 )
    {
        LE( "fail to get latest CRL [IssuerNum: %d]", g_nIssuerNum );
        goto end;
    }

    JS_BIN_decodeHex( sDBCRL.pCRL, &binCRL );

    ret = JS_SCEP_genSignedDataWithoutSign( NULL, &binCRL, pSignedData );

end :
    if( pXIAS ) PKCS7_ISSUER_AND_SERIAL_free( pXIAS );
    JS_DB_resetCRL( &sDBCRL );
    JS_BIN_reset( &binCRL );

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
    BIN binDevData = {0,0};
    BIN binResData = {0,0};
    BIN binEnvData = {0,0};

    BIN binSrvSenderNonce = {0,0};

    ret = JS_SCEP_verifyParseSignedData( pPKIReq, &nType, &binSignCert, &binSenderNonce, &pTransID, &binData );
    if( ret != 0 )
    {
        LE( "fail to veriyf signeddata : %d", ret );
        goto end;
    }

    if( g_pP11CTX )
    {
        ret = JS_PKCS7_makeDevelopedDataByP11( &binData, &g_binCAPriKey, g_pP11CTX, &g_binCACert, &binDevData );
    }
    else
    {
        ret = JS_PKCS7_makeDevelopedData( &binData, &g_binCAPriKey, &g_binCACert, &binDevData );
    }

    if( ret != 0 )
    {
        LE( "fail to develop data : %d", ret );
        goto end;
    }

    if( nType == JS_SCEP_REQUEST_PKCSREQ )
    {
        LI( "REQUEST_PKCSREQ" );
        ret = runPKIReq( db, &binSignCert, &binDevData, &binResData );
        if( ret == 0 ) JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_SCEP_PKCS_REQ, "Admin", NULL );
    }
    else if( nType == JS_SCEP_REQUEST_GETCRL )
    {
        LI( "REQUEST_GETCRL" );
        ret = runGetCRL( db, &binSignCert, &binDevData, &binResData );
        if( ret == 0 ) JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_SCEP_GET_CRL, "Admin", NULL );
    }
    else if( nType == JS_SCEP_REQUEST_GETCERT )
    {
        LI( "REQUEST_GETCERT" );
        LE( "Not implemented" );
    }
    else if( nType == JS_SCEP_REQUEST_GETCERTINIT )
    {
        LI( "REQUEST_GETCERTINIT" );
        LE( "Not implemented" );
    }
    else
    {
        LE( "Invalid request type : %d", nType );
        ret = -1;
        goto end;
    }

    ret = JS_PKCS7_makeEnvelopedData( "aes-256-cbc", &binResData, &binSignCert, &binEnvData );

    JS_PKI_genRandom( 16, &binSrvSenderNonce );

    if( g_pP11CTX )
    {
        ret = JS_SCEP_makeSignedDataByP11( JS_SCEP_REPLY_CERTREP,
                                     "SHA256",
                                     &binEnvData,
                                     &g_binCAPriKey,
                                     g_pP11CTX,
                                     &g_binCACert,
                                     &binSrvSenderNonce,
                                     &binSenderNonce,
                                     pTransID,
                                     "0",
                                     pCertRsp );
    }
    else
    {
        ret = JS_SCEP_makeSignedData( JS_SCEP_REPLY_CERTREP,
                            "SHA256",
                            &binEnvData,
                            &g_binCAPriKey,
                            &g_binCACert,
                            &binSrvSenderNonce,
                            &binSenderNonce,
                            pTransID,
                            "0",
                            pCertRsp );
    }

end :
    JS_BIN_reset( &binSignCert );
    JS_BIN_reset( &binSenderNonce );
    JS_BIN_reset( &binSrvSenderNonce );
    JS_BIN_reset( &binData );
    JS_BIN_reset( &binDevData );
    if( pTransID ) JS_free( pTransID );
    JS_BIN_reset( &binResData );
    JS_BIN_reset( &binEnvData );

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
        LE( "There is no operation" );
        return -1;
    }

    LI( "SCEP Operation: %s", pOper );

    if( strcasecmp( pOper, "GetCACaps") == 0 )
    {
        const char *pMsg = "POSTPKIOperation\r\nRenewal\r\nSHA-1";
        JS_BIN_set( pRsp, pMsg, strlen( pMsg ) );
    }
    else if( strcasecmp( pOper, "GetCACert" ) == 0 )
    {
        if( g_binCACert.nLen <= 0 )
        {
            LE( "CA certificate is empty" );
        }
        else
        {
            JS_BIN_copy( pRsp, &g_binCACert );
        }
    }
    else if( strcasecmp( pOper, "PKIOperation" ) == 0 )
    {
        ret = workPKIOperation( db, pReq, pRsp );
    }
    else
    {
        LE( "invalid operation : %s", pOper );
        return -1;
    }

    return ret;
}
