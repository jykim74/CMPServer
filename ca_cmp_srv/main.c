#include <stdio.h>

#include "openssl/evp.h"
#include "openssl/cmp.h"

#include "js_process.h"
#include "js_http.h"
#include "js_cmp.h"


BIN     binRef = {0,0};
BIN     binMsg = {0,0};
BIN     binSecret = {0,0};
BIN     binSignCert = {0,0};
BIN     binSignPri= {0,0};

#ifndef OPENSSL_V3

void testInit()
{
    JS_BIN_set( &binRef, (const unsigned char *)"12345678", 8 );
    JS_BIN_set( &binSecret, (const unsigned char *)"0123456789ABCDEF", 16 );
    JS_BIN_fileRead( "/Users/jykim/work/PKITester/data/user_cert.der", &binSignCert );
    JS_BIN_fileRead( "/Users/jykim/work/PKITester/data/user_prikey.der", &binSignPri );
}




int testReqCMP( int nType )
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

    OSSL_CMP_ITAV   *pITAV = NULL;

    OSSL_CMP_CTX    *pCTX = NULL;
    pCTX = OSSL_CMP_CTX_new();
    if( pCTX == NULL )
    {
        fprintf( stderr, "CMP CTX is null\n" );
        return -1;
    }

    pPosSignCert = binSignCert.pVal;
    pPosSignPri = binSignPri.pVal;

    pXSignCert = d2i_X509( NULL, &pPosSignCert, binSignCert.nLen );
    pESignPri = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosSignPri, binSignPri.nLen );

    if( nType == OSSL_CMP_PKIBODY_IR || nType == OSSL_CMP_PKIBODY_CR  )
    {
        OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );
        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );

        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
        OSSL_CMP_CTX_set1_newPkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_KUR )
    {
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
        // OSSL_CMP_CTX_set1_newPkey( pCTX, pESignPri );
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
//        OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );
//        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_CERTCONF )
    {
//        OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );
//        OSSL_CMP_CTX_set1_secretValue( pCTX, binSecret.pVal, binSecret.nLen );
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );

        CMP_CTX_set1_newClCert( pCTX, pXSignCert );
    }

    OSSL_CMP_MSG    *pMsg = NULL;

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
        return -1;
    }

    nOutLen = i2d_OSSL_CMP_MSG( pMsg, &pOut );
    printf( "OutLen: %d\n", nOutLen );

    JS_BIN_set( &binMsg, pOut, nOutLen );
    JS_BIN_encodeHex( &binMsg, &pHex );
    if( pHex ) printf( "%s\n", pHex );
    printf( "%d Type done\n", nType );

    OSSL_CMP_CTX_free( pCTX );
    if( pXSignCert ) X509_free( pXSignCert );
    if( pESignPri ) EVP_PKEY_free( pESignPri );

    return 0;
}

int testReqParse()
{
    int         ret = 0;
    unsigned char       *pPosCMP = NULL;
    OSSL_CMP_MSG        *pMsg = NULL;
    OSSL_CMP_PKIHEADER  *pHeader = NULL;
    int         nType = -1;
    OSSL_CMP_CTX        *pCTX = NULL;

    pPosCMP = binMsg.pVal;

    pMsg = d2i_OSSL_CMP_MSG( NULL, &pPosCMP, binMsg.nLen );
    if( pMsg == NULL )
    {
        fprintf( stderr, "Invalid CMP MSG\n" );
        return -1;
    }

    nType = OSSL_CMP_MSG_get_bodytype( pMsg );
    pHeader = OSSL_CMP_MSG_get0_header( pMsg );

    pCTX = OSSL_CMP_CTX_new();
    OSSL_CMP_MSG_check_received( pCTX, pMsg, NULL, 0 );





    return 0;
}

int testRspCMP( int nType )
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

    int nCertReqId = -1;
    OSSL_CMP_PKISI  *pXSI = NULL;
    STACK_OF(X509)  *pXChain = NULL;
    STACK_OF(X509)  *pXCaPubs = NULL;
    int             nEncrypted = 0;
    int             nUnprotectedError = -1;

    OSSL_CRMF_CERTID    *pXCertID = NULL;

    OSSL_CMP_ITAV   *pITAV = NULL;

    OSSL_CMP_CTX    *pCTX = NULL;
    pCTX = OSSL_CMP_CTX_new();
    if( pCTX == NULL )
    {
        fprintf( stderr, "CMP CTX is null\n" );
        return -1;
    }

    pPosSignCert = binSignCert.pVal;
    pPosSignPri = binSignPri.pVal;

    pXSignCert = d2i_X509( NULL, &pPosSignCert, binSignCert.nLen );
    pESignPri = d2i_PrivateKey( EVP_PKEY_RSA, NULL, &pPosSignPri, binSignPri.nLen );


    if( nType == OSSL_CMP_PKIBODY_CP || nType == OSSL_CMP_PKIBODY_IP )
    {
        int nStatus = OSSL_CMP_PKISTATUS_accepted;
        int nFailInfo = 0;

        pXSI = OSSL_CMP_statusInfo_new( nStatus, nFailInfo, "accepted" );

        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
        OSSL_CMP_CTX_set1_newPkey( pCTX, pESignPri );
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
    }
    else if( nType == OSSL_CMP_PKIBODY_KUP )
    {
        int nStatus = OSSL_CMP_PKISTATUS_accepted;
        int nFailInfo = 0;

        pXSI = OSSL_CMP_statusInfo_new( nStatus, nFailInfo, "accepted" );
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_RP )
    {
        int nStatus = OSSL_CMP_PKISTATUS_accepted;
        int nFailInfo = 0;

        pXCertID = OSSL_CRMF_CERTID_gen( X509_get_subject_name( pXSignCert), X509_get_serialNumber(pXSignCert));

        pXSI = OSSL_CMP_statusInfo_new( nStatus, nFailInfo, "accepted" );

        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
    }
    else if( nType == OSSL_CMP_PKIBODY_GENP )
    {
        OSSL_CMP_CTX_set1_clCert( pCTX, pXSignCert );
        OSSL_CMP_CTX_set1_pkey( pCTX, pESignPri );
    }
    else
    {
        fprintf( stderr, "Invalid Rsp Type(%d)\n", nType );
        return -1;
    }

    OSSL_CMP_MSG    *pMsg = NULL;

    if( nType == OSSL_CMP_PKIBODY_IP
            || nType == OSSL_CMP_PKIBODY_CP
            || nType == OSSL_CMP_PKIBODY_KUP )
    {
        pMsg = OSSL_CMP_certrep_new( pCTX, nType, nCertReqId, pXSI, pXSignCert, pXChain, pXCaPubs, nEncrypted, nUnprotectedError );
    }
    else if( nType == OSSL_CMP_PKIBODY_RP )
    {
        pMsg = OSSL_CMP_rp_new( pCTX, pXSI, pXCertID, nUnprotectedError );
    }
    else if( nType == OSSL_CMP_PKIBODY_GENP )
    {
        pMsg = OSSL_CMP_genp_new( pCTX );
    }


    if( pMsg == NULL )
    {
        fprintf( stderr, "fail to get CMP_MSG\n" );
        return -1;
    }

    nOutLen = i2d_OSSL_CMP_MSG( pMsg, &pOut );
    printf( "OutLen: %d\n", nOutLen );

    JS_BIN_set( &binMsg, pOut, nOutLen );
    JS_BIN_encodeHex( &binMsg, &pHex );
    if( pHex ) printf( "%s\n", pHex );
    printf( "%d Type done\n", nType );

    OSSL_CMP_CTX_free( pCTX );
    if( pXSignCert ) X509_free( pXSignCert );
    if( pESignPri ) EVP_PKEY_free( pESignPri );

    return 0;
}

int test_main()
{
    int ret = 0;
//    int     nType = OSSL_CMP_PKIBODY_IR;
//    int     nType = OSSL_CMP_PKIBODY_CR;
//    int     nType = OSSL_CMP_PKIBODY_RR;
//    int     nType = OSSL_CMP_PKIBODY_KUR;
//    int     nType = OSSL_CMP_PKIBODY_GENM;
    int     nType = OSSL_CMP_PKIBODY_CERTCONF;

    testInit();

#if 1
    ret = testReqCMP( nType );
    printf( "Req Ret : %d\n", ret );
    ret = testReqParse();
    printf( "Req Parse Ret : %d\n", ret );
#endif

//    int     nRspType = OSSL_CMP_PKIBODY_CP;
//    int     nRspType = OSSL_CMP_PKIBODY_IP;
    int     nRspType = OSSL_CMP_PKIBODY_RP;
//    int     nRspType = OSSL_CMP_PKIBODY_KUP;
//    int     nRspType = OSSL_CMP_PKIBODY_GENP;
#if 0
    ret = testRspCMP( nRspType );
    printf( "Rsp Ret: %d\n", ret );
#endif

    return 0;
}

#endif
