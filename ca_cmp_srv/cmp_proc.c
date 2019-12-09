#include "js_bin.h"
#include "js_pki.h"
#include "js_cmp.h"
#include "js_db.h"
#include "js_pki_ext.h"

#include "cmp_srv.h"

extern BIN     g_binRootCert;
extern BIN     g_binCACert;
extern BIN     g_binCAPriKey;

extern BIN     g_binSignCert;
extern BIN     g_binSignPri;

static int     s_nPrevType = -1;

int procGENM( OSSL_CMP_CTX *pCTX, void *pBody )
{
    STACK_OF(OSSL_CMP_ITAV) *pITAVs = pBody;


    return 0;
}

int procIR( OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, void *pBody, BIN *pNewCert )
{
    int ret = 0;
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;
    const char *pHash = "SHA1";


    int nNum  = sk_OSSL_CRMF_MSG_num( pMsgs );
    for( int i = 0; i < nNum; i++ )
    {
        BIN binPub = {0,0};
        unsigned char *pOut = NULL;
        int nOutLen = 0;
        JCertInfo       sCertInfo;
        JExtensionInfoList  *pExtInfoList = NULL;

        memset( &sCertInfo, 0x00, sizeof(sCertInfo));

        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );
        X509_PUBKEY *pPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );

        nOutLen = i2d_X509_PUBKEY( pPubKey, &pOut );
        JS_BIN_set( &binPub, pOut, nOutLen );

        ret = JS_PKI_makeCertificate( 0, &sCertInfo, pExtInfoList, pHash, &g_binCAPriKey, &g_binCACert, pNewCert );

        JS_BIN_reset( &binPub );
        JS_PKI_resetCertInfo( &sCertInfo );
        if( pExtInfoList ) JS_PKI_resetExtensionInfoList( &pExtInfoList );
        break;
    }

    return ret;
}

int procRR( OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody )
{
    OSSL_CMP_REVREPCONTENT *pRevRepContents = (OSSL_CMP_REVREPCONTENT *)pBody;
    return 0;
}

int procKUR( OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody, BIN *pNewCert )
{
    OSSL_CRMF_MSGS  *pMsgs = (OSSL_CRMF_MSGS *)pBody;
    int nNum  = sk_OSSL_CRMF_MSG_num( pMsgs );
    for( int i = 0; i < nNum; i++ )
    {
        OSSL_CRMF_MSG *pMsg = sk_OSSL_CRMF_MSG_value( pMsgs, i );
        OSSL_CRMF_CERTTEMPLATE *pTmpl = OSSL_CRMF_MSG_get0_tmpl( pMsg );
        X509_PUBKEY *pPubKey = OSSL_CRMF_CERTTEMPLATE_get0_publicKey( pTmpl );
    }

    return 0;
}

int procCertConf( OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, JDB_Cert *pDBCert, void *pBody )
{
    STACK_OF(OSSL_CMP_CERTSTATUS) *pCertStatus = pBody;

    return 0;
}

int procCMP( sqlite3* db, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    char    *pHex = NULL;

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
    char            *pHexKID = NULL;
    JDB_Cert        sDBCert;
    JDB_User        sDBUser;

    memset( &sDBCert, 0x00, sizeof(sDBCert));
    memset( &sDBUser, 0x00, sizeof(sDBUser));

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

    JS_BIN_set( &binKID, pASenderKID->data, pASenderKID->length );
    JS_BIN_encodeHex( &binKID, &pHexKID );

    ret = JS_DB_getUserByRefCode( db, pHexKID, &sDBUser );
    if( ret >= 0 && strlen( sDBUser.pSecretNum ) > 0 )
    {
        BIN binSecret = {0,0};
        JS_BIN_decodeHex( sDBUser.pSecretNum, &binSecret );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
        JS_BIN_reset( &binSecret );
    }
    else
    {
        JCertInfo sCACertInfo;

        JDB_Cert    sDBCACert;
        JDB_Cert    sDBCert;

        BIN         binCert;
        unsigned char   *pPosCert = NULL;

        memset( &sCACertInfo, 0x00, sizeof(sCACertInfo));

        JS_PKI_getCertInfo( &g_binCACert, &sCACertInfo, NULL );
        JS_DB_getCertByDNHash( db, sCACertInfo.pDNHash, &sDBCACert );
        JS_DB_getCertBySerial( db, sDBCACert.nNum, pHexKID, &sDBCert );
        JS_BIN_decodeHex( sDBCert.pCert, &binCert );

        pPosCert = binCert.pVal;
        pXSignCert = d2i_X509( NULL, &pPosCert, binCert.nLen );
        sk_X509_push( pXCerts, pXSignCert );
        OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );

        JS_BIN_reset( &binCert );
        JS_PKI_resetCertInfo( &sCACertInfo );
        JS_DB_resetCert( &sDBCert );
        JS_DB_resetCert( &sDBCACert );
    }

    if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR )
    {
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;
        procIR( pCTX, pBody, &sDBUser, &binNewCert );

        pPosNewCert = binNewCert.pVal;
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXNewCert );
        JS_BIN_reset( &binNewCert );
        if( pXNewCert ) X509_free( pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_KUR )
    {
        BIN binNewCert = {0,0};
        X509 *pXNewCert = NULL;
        const unsigned char *pPosNewCert = NULL;

        pPosNewCert = binNewCert.pVal;
        procKUR( pCTX, &sDBCert, pBody, &binNewCert );
        pXNewCert = d2i_X509( NULL, &pPosNewCert, binNewCert.nLen );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXNewCert );

        JS_BIN_reset( &binNewCert );
        if( pXNewCert ) X509_free( pXNewCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_RR )
    {
        procRR( pCTX, &sDBCert, pBody );
        OSSL_CMP_SRV_CTX_set1_certOut( pSrvCTX, pXSignCert );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        procGENM( pCTX, pBody );
    }
    else if( nReqType == OSSL_CMP_PKIBODY_CERTCONF )
    {
        procCertConf( pCTX, &sDBUser, &sDBCert, pBody );
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

    s_nPrevType = nReqType;


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

int procCMP_mock( const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    char    *pHex = NULL;

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

    if( nReqType == OSSL_CMP_PKIBODY_IR || nReqType == OSSL_CMP_PKIBODY_CR || nReqType == OSSL_CMP_PKIBODY_GENM )
    {
        BIN binSecret = {0,0};

        JS_BIN_set( &binSecret, (unsigned char *)"0123456789ABCDEF", 16 );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );

        /* Update Genm용은 아래 인증서를 셋팅해야 함 */

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

        if( s_nPrevType == OSSL_CMP_PKIBODY_KUR )
        {
            sk_X509_push( pXCerts, pXSignCert );
            OSSL_CMP_CTX_set1_untrusted_certs( pCTX, pXCerts );
        }
        else
        {
            BIN binSecret = {0,0};
            JS_BIN_set( &binSecret, (unsigned char *)"0123456789ABCDEF", 16 );
            OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
        }

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

    s_nPrevType = nReqType;


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

