#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "js_gen.h"
#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"
#include "js_db.h"
#include "js_pki_ext.h"
#include "js_pki_internal.h"
#include "js_pki_x509.h"
#include "js_pki_tools.h"
#include "js_log.h"
#include "js_scep.h"
#include "js_define.h"

#include "cmp_mock_srv.h"
#include "cmp_srv.h"


extern BIN     g_binRootCert;
extern BIN     g_binCACert;
extern BIN     g_binCAPriKey;
extern  JP11_CTX        *g_pP11CTX;
extern int g_nMsgDump;

extern BIN     g_binSignCert;
extern BIN     g_binSignPri;

extern int      g_nCertProfileNum;
extern int      g_nIssuerNum;

extern const char* g_pParam;
extern const char* g_pKeyGen;
extern int g_nKeyType;

int msgDump( int nIsReq, int nReqType, const BIN *pMsg )
{
    char        sSavePath[1024];
    const char *pName = NULL;

    if( pMsg == NULL || pMsg->nLen <= 0 ) return -1;

    if( nReqType == OSSL_CMP_PKIBODY_IR )
        pName = "ir";
    else if( nReqType == OSSL_CMP_PKIBODY_CR )
        pName = "cr";
    else if( nReqType == OSSL_CMP_PKIBODY_P10CR )
        pName = "p10cr";
    else if( nReqType == OSSL_CMP_PKIBODY_KUR )
        pName = "kur";
    else if( nReqType == OSSL_CMP_PKIBODY_RR )
        pName = "rr";
    else if( nReqType == OSSL_CMP_PKIBODY_GENM )
        pName = "genm";
    else if( nReqType == OSSL_CMP_PKIBODY_CERTCONF )
        pName = "certconf";
    else
    {
        LE( "Invalid ReqType: %d", nReqType );
        return -1;
    }

    if( JS_UTIL_isFolderExist( "dump" ) == 0 )
    {
#ifdef WIN32
        mkdir( "dump" );
#else
        mkdir( "dump", 0755 );
#endif
    }

    if( nIsReq )
    {
        sprintf( sSavePath, "dump/cmp_req_%d_%d.bin", time(NULL), getpid() );
    }
    else
    {
        sprintf( sSavePath, "dump/cmp_rsp_%d_%d.bin", time(NULL), getpid());
    }


    return JS_BIN_fileWrite( pMsg, sSavePath );
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


int procGENM( sqlite3 *db, OSSL_CMP_CTX *pCTX, void *pBody )
{
    int ret = 0;

    ASN1_UTF8STRING *pText = NULL;
    char sFreeText[1024];

    STACK_OF(OSSL_CMP_ITAV) *pITAVs = pBody;
//    const char *msg = "alg=RSA$keylen=2048$keygen=user";

    int nCnt = sk_OSSL_CMP_ITAV_num( pITAVs );

    sprintf( sFreeText, "alg=%s&param=%s&keygen=%s", JS_PKI_getKeyAlgName( g_nKeyType ), g_pParam, g_pKeyGen );
    LV( "GENM FreeText: %s", sFreeText );

    pText = ASN1_UTF8STRING_new();
    ASN1_STRING_set0( pText, strdup( sFreeText ), strlen(sFreeText) );

#ifdef CMP_MOD
    OSSL_CMP_set0_freeText( pCTX, pText );
#else
    JS_OSSL_CMP_set0_freeText( pCTX, pText );
#endif

    for( int i=0; i < nCnt; i++ )
    {
        unsigned char sBuf[1024];

        memset( sBuf, 0x00, sizeof(sBuf));

        OSSL_CMP_ITAV   *pITAV = sk_OSSL_CMP_ITAV_value(  pITAVs, i );
        ASN1_OBJECT *pAObj = OSSL_CMP_ITAV_get0_type( pITAV );
        ASN1_TYPE *pAType = OSSL_CMP_ITAV_get0_value( pITAV );

        if( pAObj )
        {
            char buf[1024];
            memset( buf, 0x00, sizeof(buf));
            OBJ_obj2txt( buf, sizeof(buf), pAObj, 1 );
            LD( "ITAV Type: %s", buf );
        }
    }



    ret = 0;
    JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_CMP_GENM, "Admin", NULL );

 end :

    return ret;
}

int makeCert( JDB_CertProfile *pDBCertProfile, JDB_ProfileExtList *pDBProfileExtList, JIssueCertInfo *pIssueCertInfo, BIN *pCert )
{
    int ret = 0;

    JExtensionInfoList  *pExtInfoList = NULL;
    JDB_ProfileExtList   *pDBCurList = NULL;
    int nExtCnt = JS_DB_countProfileExtList( pDBProfileExtList );

    pDBCurList = pDBProfileExtList;

    while( pDBCurList )
    {
        JExtensionInfo sExtInfo;

        memset( &sExtInfo,0x00, sizeof(sExtInfo));


        if( strcasecmp( pDBCurList->sProfileExt.pSN, JS_PKI_ExtNameSKI ) == 0 )
        {
            BIN binPub = {0,0};
            BIN binPubKeyID = {0,0};
            char    *pPubKeyIDHex = NULL;

            JS_BIN_decodeHex(pIssueCertInfo->pPublicKey, &binPub);
            ret = JS_PKI_getKeyIdentifier( &binPub, &binPubKeyID );
            if( ret != 0 )
            {
                LE( "fail to get KeyIdentifier: %d", ret );
                goto end;
            }

            JS_BIN_encodeHex( &binPubKeyID, &pPubKeyIDHex );

            if( pDBCurList->sProfileExt.pValue )
            {
                JS_free( pDBCurList->sProfileExt.pValue );
                pDBCurList->sProfileExt.pValue = NULL;
            }

            pDBCurList->sProfileExt.pValue = pPubKeyIDHex;
            JS_BIN_reset( &binPub );
            JS_BIN_reset( &binPubKeyID );
        }
        else if( strcasecmp( pDBCurList->sProfileExt.pSN, JS_PKI_ExtNameAKI ) == 0 )
        {
            char    sHexID[128];
            char    sHexSerial[128];
            char    sHexIssuer[1024];

            char    sBuf[2048];

            memset( sHexID, 0x00, sizeof(sHexID));
            memset( sHexSerial, 0x00, sizeof(sHexSerial));
            memset( sHexIssuer, 0x00, sizeof(sHexIssuer));
            memset( sBuf, 0x00, sizeof(sBuf));

            ret = JS_PKI_getAuthorityKeyIdentifier( &g_binCACert, sHexID, sHexSerial, sHexIssuer );
            if( ret != 0 )
            {
                LE( "fail to get AuthorityKeyIdentifier: %d", ret );
                goto end;
            }

            sprintf( sBuf, "KEYID$%s#ISSUER$%s#SERIAL$%s", sHexID, sHexIssuer, sHexSerial );
            if( pDBCurList->sProfileExt.pValue )
            {
                JS_free( pDBCurList->sProfileExt.pValue );
                pDBCurList->sProfileExt.pValue = NULL;
            }

            pDBCurList->sProfileExt.pValue = JS_strdup( sBuf );
        }

        JS_PKI_transExtensionFromDBRec( &sExtInfo, &pDBCurList->sProfileExt );

        if( pExtInfoList == NULL )
            JS_PKI_createExtensionInfoList( &sExtInfo, &pExtInfoList );
        else
            JS_PKI_appendExtensionInfoList( pExtInfoList, &sExtInfo );

        pDBCurList = pDBCurList->pNext;
    }

    if( g_pP11CTX )
        ret = JS_PKI_makeCertificateByP11( 0, pIssueCertInfo, pExtInfoList, &g_binCAPriKey, &g_binCACert, g_pP11CTX, pCert );
    else
        ret = JS_PKI_makeCertificate( 0, pIssueCertInfo, pExtInfoList, &g_binCAPriKey, &g_binCACert, pCert );

end :
    if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );

    return ret;
}

int procIR( sqlite3* db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, void *pBody, BIN *pNewCert )
{
    int ret = 0;
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;
    const char *pHash = "SHA1";

    JDB_CertProfile sDBCertProfile;
    JDB_ProfileExtList *pDBProfileExtList = NULL;

    if( pDBUser == NULL )
    {
        LE( "DBUser is null" );
        return -1;
    }

    memset( &sDBCertProfile, 0x00, sizeof(sDBCertProfile));
    JS_DB_getCertProfile( db, g_nCertProfileNum, &sDBCertProfile );
    JS_DB_getCertProfileExtList( db, sDBCertProfile.nNum, &pDBProfileExtList );


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

//        char    sKeyID[128];
        BIN binKeyID = {0,0};
        char *pKeyIDHex = NULL;

        memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
        memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));
        memset( &sDBNewCert, 0x00, sizeof(sDBNewCert));

        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );

#ifdef CMP_MOD
        X509_PUBKEY *pXPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
#else
        X509_PUBKEY *pXPubKey = JS_OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
#endif

        nOutLen = i2d_X509_PUBKEY( pXPubKey, &pOut );
        JS_BIN_set( &binPub, pOut, nOutLen );


        nKeyType = JS_PKI_getPubKeyType( &binPub );
        JS_PKI_getKeyIdentifier( &binPub, &binKeyID );
        JS_BIN_encodeHex( &binPub, &pPubKey );
        JS_BIN_encodeHex( &binKeyID, &pKeyIDHex );

        int nSeq = JS_DB_getNextVal( db, "TB_CERT" );

        sprintf( sSerial, "%d", nSeq );

        sprintf( sSubjectName, "CN=%s,C=kr", pDBUser->pName );
        time_t now_t = time(NULL);

        if( sDBCertProfile.nNotBefore <= 0 )
        {
            uNotBefore = 0;
            uNotAfter = sDBCertProfile.nNotAfter * 60 * 60 * 24;
            uNotBefore = 0;
        }
        else
        {
            uNotBefore = sDBCertProfile.nNotBefore - now_t;
            uNotAfter = sDBCertProfile.nNotAfter - now_t;
        }

        JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                                sDBCertProfile.nVersion,
                                sSerial,
                                sDBCertProfile.pHash,
                                sSubjectName,
                                uNotBefore,
                                uNotAfter,
                                nKeyType,
                                pPubKey );


        ret = makeCert( &sDBCertProfile, pDBProfileExtList, &sIssueCertInfo, pNewCert );
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
                       pKeyIDHex,
                       "" );

        ret = JS_DB_addCert( db, &sDBNewCert );
        if( ret == 0 )
        {
            if( pDBUser->pAuthCode )
            {
                JS_free( pDBUser->pAuthCode );
                pDBUser->pAuthCode = NULL;
            }

            pDBUser->nStatus = JS_USER_STATUS_ISSUED;
            JS_DB_modUser( db, pDBUser->nNum, pDBUser );
            JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_CMP_IR, "Admin", NULL );
        }

        JS_BIN_reset( &binPub );
        JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
        JS_PKI_resetCertInfo( &sNewCertInfo);
        JS_DB_resetCert( &sDBNewCert);
        JS_BIN_reset( &binKeyID );
        if( pKeyIDHex ) JS_free( pKeyIDHex );
        if( pPubKey ) JS_free( pPubKey );
        if( pHexCert ) JS_free( pHexCert );

        break;
    }

    JS_DB_resetCertProfile( &sDBCertProfile );
    if( pDBProfileExtList ) JS_DB_resetProfileExtList( &pDBProfileExtList );

    return ret;

}

int procP10CR( sqlite3* db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, void *pBody, BIN *pNewCert )
{
    int ret = 0;
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;
    const char *pHash = "SHA1";

    JDB_CertProfile sDBCertProfile;
    JDB_ProfileExtList *pDBProfileExtList = NULL;

    if( pDBUser == NULL )
    {
        LE( "DBUser is null" );
        return -1;
    }

    memset( &sDBCertProfile, 0x00, sizeof(sDBCertProfile));
    JS_DB_getCertProfile( db, g_nCertProfileNum, &sDBCertProfile );
    JS_DB_getCertProfileExtList( db, sDBCertProfile.nNum, &pDBProfileExtList );


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

        //        char    sKeyID[128];
        BIN binKeyID = {0,0};
        char *pKeyIDHex = NULL;

        memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
        memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));
        memset( &sDBNewCert, 0x00, sizeof(sDBNewCert));



        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );

#ifdef CMP_MOD
        X509_PUBKEY *pXPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
#else
        X509_PUBKEY *pXPubKey = JS_OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
#endif

        nOutLen = i2d_X509_PUBKEY( pXPubKey, &pOut );
        JS_BIN_set( &binPub, pOut, nOutLen );



        nKeyType = JS_PKI_getPubKeyType( &binPub );
        JS_PKI_getKeyIdentifier( &binPub, &binKeyID );
        JS_BIN_encodeHex( &binPub, &pPubKey );
        JS_BIN_encodeHex( &binKeyID, &pKeyIDHex );

        int nSeq = JS_DB_getNextVal( db, "TB_CERT" );

        sprintf( sSerial, "%d", nSeq );

        sprintf( sSubjectName, "CN=%s,C=kr", pDBUser->pName );
        time_t now_t = time(NULL);

        if( sDBCertProfile.nNotBefore <= 0 )
        {
            uNotBefore = 0;
            uNotAfter = sDBCertProfile.nNotAfter * 60 * 60 * 24;
            uNotBefore = 0;
        }
        else
        {
            uNotBefore = sDBCertProfile.nNotBefore - now_t;
            uNotAfter = sDBCertProfile.nNotAfter - now_t;
        }

        JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                                sDBCertProfile.nVersion,
                                sSerial,
                                sDBCertProfile.pHash,
                                sSubjectName,
                                uNotBefore,
                                uNotAfter,
                                nKeyType,
                                pPubKey );


        ret = makeCert( &sDBCertProfile, pDBProfileExtList, &sIssueCertInfo, pNewCert );
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
                      pKeyIDHex,
                      "" );

        ret = JS_DB_addCert( db, &sDBNewCert );
        if( ret == 0 )
        {
            if( pDBUser->pAuthCode )
            {
                JS_free( pDBUser->pAuthCode );
                pDBUser->pAuthCode = NULL;
            }

            pDBUser->nStatus = JS_USER_STATUS_ISSUED;
            JS_DB_modUser( db, pDBUser->nNum, pDBUser );
            JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_CMP_IR, "Admin", NULL );
        }

        JS_BIN_reset( &binPub );
        JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
        JS_PKI_resetCertInfo( &sNewCertInfo);
        JS_DB_resetCert( &sDBNewCert);
        JS_BIN_reset( &binKeyID );
        if( pKeyIDHex ) JS_free( pKeyIDHex );
        if( pPubKey ) JS_free( pPubKey );
        if( pHexCert ) JS_free( pHexCert );

        break;
    }

    JS_DB_resetCertProfile( &sDBCertProfile );
    if( pDBProfileExtList ) JS_DB_resetProfileExtList( &pDBProfileExtList );

    return ret;

}

int procRR( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody )
{
    OSSL_CRMF_CERTID    *pCertID = NULL;
    X509_EXTENSIONS     *pXExts = NULL;
    X509_EXTENSION      *pXReason = NULL;

    BIN binData = {0,0};
    int nReason = 0;
    JDB_Revoked sDBRevoked;

    memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

#ifdef CMP_MOD
    pXExts = OSSL_CMP_get0_crlEntryDetails( pBody, 0 );
#else
    pXExts = JS_OSSL_CMP_get0_crlEntryDetails( pBody, 0 );
#endif

    pXReason = sk_X509_EXTENSION_value( pXExts, 0 );
    ASN1_OCTET_STRING *pAOctet = X509_EXTENSION_get_data( pXReason );
    JS_BIN_set( &binData, pAOctet->data, pAOctet->length );
    JS_PKI_getCRLReasonValue( &binData, &nReason );

    JS_DB_setRevoked( &sDBRevoked, -1, pDBCert->nNum, g_nIssuerNum, pDBCert->pSerial, time(NULL), nReason, pDBCert->pCRLDP );

    JS_DB_addRevoked( db, &sDBRevoked );
    JS_DB_changeCertStatus( db, pDBCert->nNum, 2 );
    JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_CMP_RR, "Admin", NULL );

    JS_DB_resetRevoked( &sDBRevoked );
    JS_BIN_reset( &binData );

    return 0;
}

int procKUR( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody, BIN *pNewCert )
{
    int ret = 0;
    JDB_Revoked sDBRevoked;
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;

    JDB_CertProfile sDBCertProfile;
    JDB_ProfileExtList *pDBProfileExtList = NULL;

    memset( &sDBCertProfile, 0x00, sizeof(sDBCertProfile));
    memset( &sDBRevoked, 0x00, sizeof(sDBRevoked));

    JS_DB_getCertProfile( db, g_nCertProfileNum, &sDBCertProfile );
    JS_DB_getCertProfileExtList( db, sDBCertProfile.nNum, &pDBProfileExtList );

    int nNum  = sk_OSSL_CRMF_MSG_num( pMsgs );
    for( int i = 0; i < nNum; i++ )
    {
        BIN binPub = {0,0};
        unsigned char *pOut = NULL;
        int nOutLen = 0;
        JIssueCertInfo       sIssueCertInfo;
        JCertInfo       sNewCertInfo;
        JDB_Cert        sDBNewCert;
        BIN binPubKeyID = {0,0};
        char *pKeyIDHex = NULL;

        int nKeyType = -1;
        char sSerial[128];

        long uNotBefore = -1;
        long uNotAfter = -1;
        char sSubjectName[1024];
        char *pPubKey = NULL;
        char *pHexCert = NULL;

        memset( &sIssueCertInfo, 0x00, sizeof(sIssueCertInfo));
        memset( &sNewCertInfo, 0x00, sizeof(sNewCertInfo));
        memset( &sDBNewCert, 0x00, sizeof(sDBNewCert));

        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );

#ifdef CMP_MOD
        X509_PUBKEY *pXPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
#else
        X509_PUBKEY *pXPubKey = JS_OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
#endif

        nOutLen = i2d_X509_PUBKEY( pXPubKey, &pOut );
        JS_BIN_set( &binPub, pOut, nOutLen );

        nKeyType = JS_PKI_getPubKeyType( &binPub );
        JS_BIN_encodeHex( &binPub, &pPubKey );
        JS_PKI_getKeyIdentifier( &binPub, &binPubKeyID );
        JS_BIN_encodeHex( &binPubKeyID, &pKeyIDHex );

 //       int nSeq = JS_DB_getSeq( db, "TB_CERT" );
        int nSeq = JS_DB_getLastVal( db, "TB_CERT" );
        sprintf( sSerial, "%d", nSeq );

        sprintf( sSubjectName, "%s", pDBCert->pSubjectDN );
        time_t now_t = time(NULL);

        if( sDBCertProfile.nNotBefore <= 0 )
        {
            uNotBefore = 0;
            uNotAfter = sDBCertProfile.nNotAfter * 60 * 60 * 24;
            uNotBefore = 0;
        }
        else
        {
            uNotBefore = sDBCertProfile.nNotBefore - now_t;
            uNotAfter = sDBCertProfile.nNotAfter - now_t;
        }

        JS_PKI_setIssueCertInfo( &sIssueCertInfo,
                                sDBCertProfile.nVersion,
                                sSerial,
                                sDBCertProfile.pHash,
                                sSubjectName,
                                uNotBefore,
                                uNotAfter,
                                nKeyType,
                                pPubKey );


        ret = makeCert( &sDBCertProfile, pDBProfileExtList, &sIssueCertInfo, pNewCert );
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
                       pKeyIDHex,
                       "" );

        ret = JS_DB_addCert( db, &sDBNewCert );
        if( ret == 0 )
        {
            JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_CMP_KUR, "Admin", NULL );
        }

        JS_BIN_reset( &binPub );
        JS_BIN_reset( &binPubKeyID );
        JS_PKI_resetIssueCertInfo( &sIssueCertInfo );
        JS_PKI_resetCertInfo( &sNewCertInfo);
        JS_DB_resetCert( &sDBNewCert);
        if( pKeyIDHex ) JS_free( pKeyIDHex );
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
#ifdef CMP_MOD
        ASN1_OCTET_STRING *pAHash = OSSL_CMP_CERTSTATUS_get0_certHash( pStat );
        ASN1_INTEGER *pAReqId = OSSL_CMP_CERTSTATUS_get0_certReqId( pStat );
        OSSL_CMP_PKISI *pInfo = OSSL_CMP_CERTSTATUS_get0_statusInfo( pStat );
#else
        ASN1_OCTET_STRING *pAHash = JS_OSSL_CMP_CERTSTATUS_get0_certHash( pStat );
        ASN1_INTEGER *pAReqId = JS_OSSL_CMP_CERTSTATUS_get0_certReqId( pStat );
        OSSL_CMP_PKISI *pInfo = JS_OSSL_CMP_CERTSTATUS_get0_statusInfo( pStat );
#endif
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
    JS_DB_addAuditInfo( db, JS_GEN_KIND_CMP_SRV, JS_GEN_OP_CMP_CERT_CONF, "Admin", NULL );

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
    OSSL_CMP_CTX *pCTX = OSSL_CMP_SRV_CTX_get0_cmp_ctx( pSrvCTX );
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

    if( pSrvCTX == NULL || pCTX == NULL )
    {
        LE( "SrvCTX or CTX is null" );
        return -1;
    }

    memset( &sDBCert, 0x00, sizeof(sDBCert));
    memset( &sDBUser, 0x00, sizeof(sDBUser));

    JS_BIN_encodeHex( pReq, &pReqHex );
    if( pReqHex ) JS_LOG_write( JS_LOG_LEVEL_VERBOSE, "CMP Req: %s", pReqHex );

    pXCerts = sk_X509_new_null();

    pReqMsg = d2i_OSSL_CMP_MSG( NULL, &pPosReq, pReq->nLen );
    if( pReqMsg == NULL )
    {
        LE( "ReqMsg is null" );
        ret = -1;
        goto end;
    }

    int nReqType = OSSL_CMP_MSG_get_bodytype( pReqMsg );
    pHeader = OSSL_CMP_MSG_get0_header( pReqMsg );

#ifdef CMP_MOD
    void *pBody = OSSL_CMP_MSG_get0_body( pReqMsg );
#else
    void *pBody = JS_OSSL_CMP_MSG_get0_body( pReqMsg );
#endif

    ASN1_OCTET_STRING *pARecipNonce = OSSL_CMP_HDR_get0_recipNonce( pHeader );
//    ASN1_OCTET_STRING *pASenderNonce = OSSL_CMP_HDR_get0_senderNonce( pHeader );
    ASN1_OCTET_STRING *pATransID = OSSL_CMP_HDR_get0_transactionID( pHeader );

#ifdef CMP_MOD
    ASN1_OCTET_STRING *pASenderKID = OSSL_CMP_HDR_get0_senderKID( pHeader );
#else
    ASN1_OCTET_STRING *pASenderKID = JS_OSSL_CMP_HDR_get0_senderKID( pHeader );
#endif

    if( g_nMsgDump ) msgDump( 1, nReqType, pReq );

    /* KID 값은 RefNum 값이거나 클라이언트 인증서의 KeyIdentifier 값이 셋팅 됨 */
    if( pASenderKID == NULL )
    {
        LE( "There is no SendKID value" );
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
        ret = JS_DB_getCertByKeyHash( db, pKID, &sDBCert );
        if( ret <= 0 )
        {
            LE( "There is no certificate data(KID:%s)", pKID );
            ret = -1;
            goto end;
        }

        JS_BIN_decodeHex( sDBCert.pCert, &binCert );

        pPosCert = binCert.pVal;
        pXSignCert = d2i_X509( NULL, &pPosCert, binCert.nLen );
        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted( pCTX, pXCerts );
        OSSL_CMP_CTX_set1_srvCert( pCTX, pXSignCert );

        JS_BIN_reset( &binCert );
    }

    if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR  )
    {
        LV( "Req : IR or CR" );
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;
        ret = procIR( db, pCTX, &sDBUser, pBody, &binNewCert );
        if( ret != 0 ) LE( "fail procIR: %d", ret );

        pPosNewCert = binNewCert.pVal;
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );
        ossl_cmp_mock_srv_set1_certOut( pSrvCTX, pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_P10CR )
    {
        LV( "Req : P10CR" );
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;
        ret = procP10CR( db, pCTX, &sDBUser, pBody, &binNewCert );
        if( ret != 0 ) LE( "fail procP10CR: %d", ret );

        pPosNewCert = binNewCert.pVal;
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );
        ossl_cmp_mock_srv_set1_certOut( pSrvCTX, pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_KUR )
    {
        LV( "Req : KUR" );
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;

        ret = procKUR( db, pCTX, &sDBCert, pBody, &binNewCert );
        if( ret != 0 ) LE( "fail procKUR: %d", ret );

        pPosNewCert = binNewCert.pVal;
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );
        ossl_cmp_mock_srv_set1_certOut( pSrvCTX, pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_RR )
    {
        LV( "Req : RR" );
        ret = procRR( db, pCTX, &sDBCert, pBody );
        if( ret != 0 ) LE( "fail procRR: %d", ret );
        ossl_cmp_mock_srv_set1_certOut( pSrvCTX, pXSignCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        LV( "Req : GENM");

        ret = procGENM( db, pCTX, pBody );
        if( ret != 0 ) LE( "fail procGENM: %d", ret );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_CERTCONF )
    {
        LV( "Req : CERTCONF" );
        BIN binCert = {0,0};
        const unsigned char *pPosCert = NULL;
        ret = procCertConf( db, pCTX, &sDBUser, &sDBCert, pBody, &binCert );
        if( ret != 0 ) LE( "fail procCertConf: %d", ret );

        pPosCert = binCert.pVal;
        X509 *pXCert = d2i_X509( NULL, &pPosCert, binCert.nLen );
        if( pXCert )
        {
            OSSL_CMP_CTX_set1_cert( pCTX, pXCert );
            X509_free( pXCert );
        }

        JS_BIN_reset( &binCert );
        OSSL_CMP_CTX_set1_transactionID( pCTX, pATransID );
    }


    ret = OSSL_CMP_CTX_set_transfer_cb_arg( pCTX, pSrvCTX );
    if( ret != 1 )
    {
        LE( "OSSL_CMP_CTX_set_transfer_cb_arg fail:%d", ret );
        ret = -1;
        goto end;
    }


    pRspMsg = OSSL_CMP_CTX_server_perform( pCTX, pReqMsg );

    /*
    if( nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        ASN1_UTF8STRING *pText = NULL;
        pText = ASN1_UTF8STRING_new();
        ASN1_STRING_set0( pText, strdup( "Hello" ), 5 );

        OSSL_CMP_set0_freeText( OSSL_CMP_MSG_get0_header( pRspMsg ), pText );
    }
    */


    OSSL_CMP_CTX_print_errors( pCTX );
    LV( "mock_server ret: %d", ret );

    if( pRspMsg == NULL )
    {
        LE( "Rsp is null" );
        ret = -1;
        goto end;
    }

    nOutLen = i2d_OSSL_CMP_MSG( pRspMsg, &pOut );
    if( nOutLen > 0 )
    {
        JS_BIN_set( pRsp, pOut, nOutLen );
        JS_BIN_encodeHex( pRsp, &pRspHex );
        LV( "Rsp[Len:%d] : %s", nOutLen, pRspHex );
        if( pReqHex ) LV( "CMP Rsp: %s", pRspHex );
    }

    if( g_nMsgDump ) msgDump( 0, nReqType, pRsp );
    ret = 0;

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



