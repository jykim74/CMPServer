#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"
#include "js_db.h"
#include "js_pki_ext.h"
#include "js_pki_internal.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_log.h"

#include "cmp_srv.h"


extern BIN     g_binRootCert;
extern BIN     g_binCACert;
extern BIN     g_binCAPriKey;

extern BIN     g_binSignCert;
extern BIN     g_binSignPri;

extern int      g_nCertPolicyNum;
extern int      g_nIssuerNum;

int procGENM( OSSL_CMP_CTX *pCTX, void *pBody )
{
    STACK_OF(OSSL_CMP_ITAV) *pITAVs = pBody;

    int nCnt = sk_OSSL_CMP_ITAV_num( pITAVs );

    for( int i=0; i < nCnt; i++ )
    {
        unsigned char sBuf[1024];

        memset( sBuf, 0x00, sizeof(sBuf));

        OSSL_CMP_ITAV   *pITAV = sk_OSSL_CMP_ITAV_value(  pITAVs, i );
        ASN1_OBJECT *pAObj = OSSL_CMP_ITAV_get0_type( pITAV );
        ASN1_TYPE *pAType = OSSL_CMP_ITAV_get0_value( pITAV );
        ASN1_TYPE_get_octetstring( pAType, sBuf, 1024 );
    }

    return 0;
}

int makeCert( JDB_CertPolicy *pDBCertPolicy, JDB_PolicyExtList *pDBPolicyExtList, JIssueCertInfo *pIssueCertInfo, int nKeyType, BIN *pCert )
{
    int ret = 0;

    JExtensionInfoList  *pExtInfoList = NULL;
    JDB_PolicyExtList   *pDBCurList = NULL;
    int nExtCnt = JS_DB_countPolicyExtList( pDBPolicyExtList );

    pDBCurList = pDBPolicyExtList;

    while( pDBCurList )
    {
        JExtensionInfo sExtInfo;

        memset( &sExtInfo,0x00, sizeof(sExtInfo));


        if( strcasecmp( pDBCurList->sPolicyExt.pSN, JS_PKI_ExtNameSKI ) == 0 )
        {
            BIN binPub = {0,0};
            char    sHexID[128];

            memset( sHexID, 0x00, sizeof(sHexID));
            JS_BIN_decodeHex(pIssueCertInfo->pPublicKey, &binPub);
            JS_PKI_getKeyIdentifier( &binPub, sHexID );

            if( pDBCurList->sPolicyExt.pValue )
            {
                JS_free( pDBCurList->sPolicyExt.pValue );
                pDBCurList->sPolicyExt.pValue = NULL;
            }

            pDBCurList->sPolicyExt.pValue = JS_strdup( sHexID );
            JS_BIN_reset( &binPub );
        }
        else if( strcasecmp( pDBCurList->sPolicyExt.pSN, JS_PKI_ExtNameAKI ) == 0 )
        {
            char    sHexID[128];
            char    sHexSerial[128];
            char    sHexIssuer[1024];

            char    sBuf[2048];

            memset( sHexID, 0x00, sizeof(sHexID));
            memset( sHexSerial, 0x00, sizeof(sHexSerial));
            memset( sHexIssuer, 0x00, sizeof(sHexIssuer));
            memset( sBuf, 0x00, sizeof(sBuf));

            JS_PKI_getAuthorityKeyIdentifier( &g_binCACert, sHexID, sHexSerial, sHexIssuer );
            sprintf( sBuf, "KEYID$%s#ISSUER$%s#SERIAL$%s", sHexID, sHexIssuer, sHexSerial );
            if( pDBCurList->sPolicyExt.pValue )
            {
                JS_free( pDBCurList->sPolicyExt.pValue );
                pDBCurList->sPolicyExt.pValue = NULL;
            }

            pDBCurList->sPolicyExt.pValue = JS_strdup( sBuf );
        }

        JS_PKI_transExtensionFromDBRec( &sExtInfo, &pDBCurList->sPolicyExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );

        pDBCurList = pDBCurList->pNext;
    }

    ret = JS_PKI_makeCertificate( 0, pIssueCertInfo, pExtInfoList, nKeyType, &g_binCAPriKey, &g_binCACert, pCert );


    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return ret;
}

int procIR( sqlite3* db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, void *pBody, BIN *pNewCert )
{
    int ret = 0;
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;
    const char *pHash = "SHA1";

    JDB_CertPolicy sDBCertPolicy;
    JDB_PolicyExtList *pDBPolicyExtList = NULL;

    memset( &sDBCertPolicy, 0x00, sizeof(sDBCertPolicy));
    JS_DB_getCertPolicy( db, g_nCertPolicyNum, &sDBCertPolicy );
    JS_DB_getCertPolicyExtList( db, sDBCertPolicy.nNum, &pDBPolicyExtList );


    int nNum  = sk_OSSL_CRMF_MSG_num( pMsgs );
    for( int i = 0; i < nNum; i++ )
    {
        BIN binPub = {0,0};
        unsigned char *pOut = NULL;
        int nOutLen = 0;
        JIssueCertInfo       sIssueCertInfo;
        JCertInfo       sNewCertInfo;
        JDB_Cert        sDBNewCert;

        int nKeyType = -1;
        char sSerial[128];

        long uNotBefore = -1;
        long uNotAfter = -1;
        char sSubjectName[1024];
        char *pPubKey = NULL;
        char *pHexCert = NULL;

        char    sKeyID[128];

        memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
        memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));
        memset( &sDBNewCert, 0x00, sizeof(sDBNewCert));
        memset( sKeyID, 0x00, sizeof(sKeyID));

        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );
        X509_PUBKEY *pXPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );

        nOutLen = i2d_X509_PUBKEY( pXPubKey, &pOut );
        JS_BIN_set( &binPub, pOut, nOutLen );


        nKeyType = JS_PKI_getPubKeyType( &binPub );
        JS_PKI_getKeyIdentifier( &binPub, sKeyID );
        JS_BIN_encodeHex( &binPub, &pPubKey );


        int nSeq = JS_DB_getSeq( db, "TB_CERT" );
        nSeq++;

        sprintf( sSerial, "%d", nSeq );

        sprintf( sSubjectName, "CN=%s,C=kr", pDBUser->pName );
        time_t now_t = time(NULL);

        if( sDBCertPolicy.nNotBefore <= 0 )
        {
            uNotBefore = 0;
            uNotAfter = sDBCertPolicy.nNotAfter * 60 * 60 * 24;
            uNotBefore = 0;
        }
        else
        {
            uNotBefore = sDBCertPolicy.nNotBefore - now_t;
            uNotAfter = sDBCertPolicy.nNotAfter - now_t;
        }

        JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                                sDBCertPolicy.nVersion,
                                sSerial,
                                sDBCertPolicy.pHash,
                                sSubjectName,
                                uNotBefore,
                                uNotAfter,
                                nKeyType,
                                pPubKey );


        ret = makeCert( &sDBCertPolicy, pDBPolicyExtList, &sIssueCertInfo, nKeyType, pNewCert );
        if( ret != 0 )
        {
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to make certificate(ret:%d)", ret );
            JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
            break;
        }

        JS_BIN_encodeHex( pNewCert, &pHexCert );

        JS_PKI_getCertInfo( pNewCert, &sNewCertInfo, NULL );
        JS_DB_setCert( &sDBNewCert,
                       -1,
                       now_t,
                       -1,
                       pDBUser->nNum,
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

        ret = JS_DB_addCert( db, &sDBNewCert );

        JS_BIN_reset( &binPub );
        JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
        JS_PKI_resetCertInfo( &sNewCertInfo);
        JS_DB_resetCert( &sDBNewCert);
        if( pPubKey ) JS_free( pPubKey );
        if( pHexCert ) JS_free( pHexCert );

        break;
    }

    JS_DB_resetCertPolicy( &sDBCertPolicy );
    if( pDBPolicyExtList ) JS_DB_resetPolicyExtList( &pDBPolicyExtList );

    return ret;
}

int procRR( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody )
{
    OSSL_CRMF_CERTID    *pCertID = NULL;
    OSSL_CRMF_CERTTEMPLATE  *pTmpl = NULL;
    OSSL_CMP_REVDETAILS *pDetails = NULL;
    X509_EXTENSIONS     *pXExts = NULL;
    X509_EXTENSION      *pXReason = NULL;
    STACK_OF(OSSL_CMP_REVDETAILS) *pRevDetails = pBody;

    BIN binData = {0,0};
    int nReason = 0;
    JDB_Revoked sDBRevoked;

    memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

    pDetails = sk_OSSL_CMP_REVDETAILS_value( pRevDetails, 0 );
    pTmpl = OSSL_CMP_REVDETAILS_get0_certDetails( pDetails );
    pXExts = OSSL_CMP_REVDETAILS_get0_crlEntryDetails( pDetails );

    pXReason = sk_X509_EXTENSION_value( pXExts, 0 );
    ASN1_OCTET_STRING *pAOctet = X509_EXTENSION_get_data( pXReason );
    JS_BIN_set( &binData, pAOctet->data, pAOctet->length );
    JS_PKI_getCRLReasonValue( &binData, &nReason );

    JS_DB_setRevoked( &sDBRevoked, -1, pDBCert->nNum, g_nIssuerNum, pDBCert->pSerial, time(NULL), nReason, pDBCert->pCRLDP );

    JS_DB_addRevoked( db, &sDBRevoked );
    JS_DB_changeCertStatus( db, pDBCert->nNum, 2 );

    JS_DB_resetRevoked( &sDBRevoked );
    JS_BIN_reset( &binData );
    return 0;
}

int procKUR( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody, BIN *pNewCert )
{
    int ret = 0;
    JDB_Revoked sDBRevoked;
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;

    JDB_CertPolicy sDBCertPolicy;
    JDB_PolicyExtList *pDBPolicyExtList = NULL;

    memset( &sDBCertPolicy, 0x00, sizeof(sDBCertPolicy));
    memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

    JS_DB_getCertPolicy( db, g_nCertPolicyNum, &sDBCertPolicy );
    JS_DB_getCertPolicyExtList( db, sDBCertPolicy.nNum, &pDBPolicyExtList );

    int nNum  = sk_OSSL_CRMF_MSG_num( pMsgs );
    for( int i = 0; i < nNum; i++ )
    {
        BIN binPub = {0,0};
        unsigned char *pOut = NULL;
        int nOutLen = 0;
        JIssueCertInfo       sIssueCertInfo;
        JCertInfo       sNewCertInfo;
        JDB_Cert        sDBNewCert;

        int nKeyType = -1;
        char sSerial[128];

        long uNotBefore = -1;
        long uNotAfter = -1;
        char sSubjectName[1024];
        char *pPubKey = NULL;
        char *pHexCert = NULL;
        char sKeyID[128];

        memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
        memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));
        memset( &sDBNewCert, 0x00, sizeof(sDBNewCert));
        memset( sKeyID, 0x00, sizeof(sKeyID));

        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );
        X509_PUBKEY *pXPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );

        nOutLen = i2d_X509_PUBKEY( pXPubKey, &pOut );
        JS_BIN_set( &binPub, pOut, nOutLen );

        nKeyType = JS_PKI_getPubKeyType( &binPub );
        JS_BIN_encodeHex( &binPub, &pPubKey );
        JS_PKI_getKeyIdentifier( &binPub, sKeyID );

        int nSeq = JS_DB_getSeq( db, "TB_CERT" );
        sprintf( sSerial, "%d", nSeq );

        sprintf( sSubjectName, "%s", pDBCert->pSubjectDN );
        time_t now_t = time(NULL);

        if( sDBCertPolicy.nNotBefore <= 0 )
        {
            uNotBefore = 0;
            uNotAfter = sDBCertPolicy.nNotAfter * 60 * 60 * 24;
            uNotBefore = 0;
        }
        else
        {
            uNotBefore = sDBCertPolicy.nNotBefore - now_t;
            uNotAfter = sDBCertPolicy.nNotAfter - now_t;
        }

        JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                                sDBCertPolicy.nVersion,
                                sSerial,
                                sDBCertPolicy.pHash,
                                sSubjectName,
                                uNotBefore,
                                uNotAfter,
                                nKeyType,
                                pPubKey );


        ret = makeCert( &sDBCertPolicy, pDBPolicyExtList, &sIssueCertInfo, nKeyType, pNewCert );
        if( ret != 0 )
        {
            JS_LOG_write( JS_LOG_LEVEL_ERROR, "fail to make certificate (ret:%d)", ret );
            JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
            break;
        }

        JS_BIN_encodeHex( pNewCert, &pHexCert );

        JS_PKI_getCertInfo( pNewCert, &sNewCertInfo, NULL );
        JS_DB_setCert( &sDBNewCert,
                       -1,
                       now_t,
                       -1,
                       pDBCert->nUserNum,
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

        ret = JS_DB_addCert( db, &sDBNewCert );

        JS_BIN_reset( &binPub );
        JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
        JS_PKI_resetCertInfo( &sNewCertInfo);
        JS_DB_resetCert( &sDBNewCert);
        if( pPubKey ) JS_free( pPubKey );
        if( pHexCert ) JS_free( pHexCert );

        break;
    }

    JS_DB_setRevoked( &sDBRevoked, -1, pDBCert->nNum, g_nIssuerNum, pDBCert->pSerial, time(NULL), 1, pDBCert->pCRLDP );

    JS_DB_addRevoked( db, &sDBRevoked );
    JS_DB_changeCertStatus( db, pDBCert->nNum, 2 );

    JS_DB_resetRevoked( &sDBRevoked );

    return 0;
}

int procCertConf( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, JDB_Cert *pDBCert, void *pBody, BIN *pCert )
{
    int nUserNum = -1;
    JDB_Cert    sDBLatestCert;

    STACK_OF(OSSL_CMP_CERTSTATUS) *pCertStatus = pBody;

    memset( &sDBLatestCert, 0x00, sizeof(sDBLatestCert));

    int nCnt = sk_OSSL_CMP_CERTSTATUS_num( pCertStatus );
    for( int i=0; i < nCnt; i++ )
    {
        OSSL_CMP_CERTSTATUS *pStat = sk_OSSL_CMP_CERTSTATUS_value( pCertStatus, i );

        ASN1_OCTET_STRING *pAHash = OSSL_CMP_CERTSTATUS_get0_certHash( pStat );
        ASN1_INTEGER *pAReqId = OSSL_CMP_CERTSTATUS_get0_certReqId( pStat );
        OSSL_CMP_PKISI *pInfo = OSSL_CMP_CERTSTATUS_get0_statusInfo( pStat );
    }

    if( pDBUser && pDBUser->nNum > 0 )
        nUserNum = pDBUser->nNum;
    else
    {
        if( pDBCert ) nUserNum = pDBCert->nUserNum;
    }

    if( nUserNum <= 0 ) return -1;

    JS_DB_getLatestCertByUserNum( db, nUserNum, &sDBLatestCert );
    JS_BIN_decodeHex( sDBLatestCert.pCert, pCert );

    JS_DB_resetCert( &sDBLatestCert );

    return 0;
}

int procCMP( sqlite3* db, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    char    *pReqHex = NULL;
    char    *pRspHex = NULL;

    OSSL_CMP_MSG    *pReqMsg = NULL;
    OSSL_CMP_MSG    *pRspMsg = NULL;

    OSSL_CMP_SRV_CTX *pSrvCTX = setupServerCTX();
    OSSL_CMP_CTX *pCTX = OSSL_CMP_SRV_CTX_get0_ctx( pSrvCTX );
    OSSL_CMP_PKIHEADER *pHeader = NULL;

    int     nOutLen = 0;
    unsigned char   *pOut = NULL;
    unsigned char   *pPosReq = pReq->pVal;
    STACK_OF(X509)  *pXCerts = NULL;
    X509            *pXSignCert = NULL;

    BIN             binKID = {0,0};
    char            *pKID = NULL;
    JDB_Cert        sDBCert;
    JDB_User        sDBUser;

    memset( &sDBCert, 0x00, sizeof(sDBCert));
    memset( &sDBUser, 0x00, sizeof(sDBUser));

    JS_BIN_encodeHex( pReq, &pReqHex );
    if( pReqHex ) JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Req:%s", pReqHex );

    pXCerts = sk_X509_new_null();

    pReqMsg = d2i_OSSL_CMP_MSG( NULL, &pPosReq, pReq->nLen );
    if( pReqMsg == NULL )
    {
        fprintf( stderr, "ReqMsg is null\n" );
        ret = -1;
        goto end;
    }


    int nReqType = OSSL_CMP_MSG_get_bodytype( pReqMsg );
    pHeader = OSSL_CMP_MSG_get0_header( pReqMsg );
    void *pBody = OSSL_CMP_MSG_get0_body( pReqMsg );

    ASN1_OCTET_STRING *pARecipNonce = OSSL_CMP_HDR_get0_recipNonce( pHeader );
    ASN1_OCTET_STRING *pASenderNonce = OSSL_CMP_HDR_get0_senderNonce( pHeader );
    ASN1_OCTET_STRING *pATransID = OSSL_CMP_HDR_get0_transactionID( pHeader );
    ASN1_OCTET_STRING *pASenderKID = OSSL_CMP_HDR_get0_senderKID( pHeader );

    /* KID 값은 RefCode 값이거나 클라이언트 인증서의 KeyIdentifier 값이 셋팅 됨 */
    if( pASenderKID == NULL )
    {
        fprintf( stderr, "There is no SendKID value\n" );
        ret = -1;
        goto end;
    }

    JS_BIN_set( &binKID, pASenderKID->data, pASenderKID->length );
    JS_BIN_string( &binKID, &pKID );


    ret = JS_DB_getUserByRefNum( db, pKID, &sDBUser );
    if( ret >= 0 && strlen( sDBUser.pAuthCode ) > 0 )
    {
        BIN binSecret = {0,0};
        JS_BIN_set( &binSecret, sDBUser.pAuthCode, strlen( sDBUser.pAuthCode) );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
        JS_BIN_reset( &binSecret );
    }
    else
    {
        BIN         binCert;
        unsigned char   *pPosCert = NULL;
        if( pKID )
        {
            JS_free( pKID );
            pKID = NULL;
        }

        JS_BIN_encodeHex( &binKID, &pKID );
        JS_DB_getCertByKeyHash( db, pKID, &sDBCert );
        JS_BIN_decodeHex( sDBCert.pCert, &binCert );

        pPosCert = binCert.pVal;
        pXSignCert = d2i_X509( NULL, &pPosCert, binCert.nLen );
        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
        OSSL_CMP_CTX_set1_srvCert( pCTX, pXSignCert );

        JS_BIN_reset( &binCert );
//        JS_DB_resetCert( &sDBCert );
    }

    if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR )
    {
        printf( "Req : IR or CR\n" );
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;
        procIR( db, pCTX, &sDBUser, pBody, &binNewCert );

        pPosNewCert = binNewCert.pVal;
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXNewCert );
        JS_BIN_reset( &binNewCert );
        if( pXNewCert ) X509_free( pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_KUR )
    {
        printf( "Req : KUR\n" );
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;

        procKUR( db, pCTX, &sDBCert, pBody, &binNewCert );

        pPosNewCert = binNewCert.pVal;
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );

        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXNewCert );
//        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
        JS_BIN_reset( &binNewCert );
        if( pXNewCert ) X509_free( pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_RR )
    {
        printf( "Req : RR\n" );
        procRR( db, pCTX, &sDBCert, pBody );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        printf( "Req : GENM\n");
        procGENM( pCTX, pBody );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_CERTCONF )
    {
        printf( "Req : CERTCONF\n" );
        BIN binCert = {0,0};
        const unsigned char *pPosCert = NULL;
        procCertConf( db, pCTX, &sDBUser, &sDBCert, pBody, &binCert );

        pPosCert = binCert.pVal;
        X509 *pXCert = d2i_X509( NULL, &pPosCert, binCert.nLen );
        if( pXCert )
        {
            OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXCert );
            X509_free( pXCert );
        }

        JS_BIN_reset( &binCert );
    }

    ret = OSSL_CMP_CTX_set_transfer_cb_arg( pCTX, pSrvCTX );
    ret = OSSL_CMP_mock_server_perform( pCTX, pReqMsg, &pRspMsg );

    OSSL_CMP_print_errors( pCTX );

    printf( "mock_server ret: %d\n", ret );

    if( pRspMsg == NULL )
    {
        fprintf( stderr, "Rsp is null\n" );
        JS_LOG_write( JS_LOG_LEVEL_ERROR, "Rsp is null" );
        ret = -1;
        goto end;
    }

    nOutLen = i2d_OSSL_CMP_MSG( pRspMsg, &pOut );
    if( nOutLen > 0 )
    {
        JS_BIN_set( pRsp, pOut, nOutLen );
        JS_BIN_encodeHex( pRsp, &pRspHex );
        printf( "Rsp : %s\n", pRspHex );
        if( pReqHex ) JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "Rsp:%s", pRspHex );
    }

end :
    if( pReqMsg ) OSSL_CMP_MSG_free( pReqMsg );
    if( pRspMsg ) OSSL_CMP_MSG_free( pRspMsg );
    if( pReqHex ) JS_free( pReqHex );
    if( pRspHex ) JS_free( pRspHex );
    if( pOut ) OPENSSL_free( pOut );
    if( pSrvCTX ) OSSL_CMP_SRV_CTX_free( pSrvCTX );
//    if( pXSignCert ) X509_free( pXSignCert );
    if( pKID ) JS_free( pKID );
    JS_BIN_reset( &binKID );

    return ret;
}
