#include <stdio.h>

#include "js_process.h"
#include "js_http.h"
#include "js_cmp.h"

int testCMP( int nType )
{
    int     ret = 0;
    BIN     binRef = {0,0};
    BIN     binMsg = {0,0};

    int     nOutLen = 0;
    unsigned char       *pOut = NULL;
    char        *pHex = NULL;

    OSSL_CMP_ITAV   *pITAV = NULL;

    OSSL_CMP_CTX    *pCTX = NULL;
    pCTX = OSSL_CMP_CTX_new();
    if( pCTX == NULL )
    {
        fprintf( stderr, "CMP CTX is null\n" );
        return -1;
    }

    JS_BIN_set( &binRef, (const unsigned char *)"12345678", 8 );

    OSSL_CMP_CTX_set1_referenceValue( pCTX, binRef.pVal, binRef.nLen );

    OSSL_CMP_MSG    *pMsg = NULL;
    pMsg = OSSL_CMP_MSG_create( pCTX, nType );
    if( pMsg == NULL )
    {
        fprintf( stderr, "CMP Msg is null\n" );
        return -1;
    }

    ret = OSSL_CMP_MSG_protect( pCTX, pMsg );
    if( ret != 1 )
    {
        fprintf( stderr, "fail to protect msg(%d)\n", ret );
    }
    else
    {
        printf( "Success to make protect\n" );
    }

    nOutLen = i2d_OSSL_CMP_MSG( pMsg, &pOut );
    printf( "OutLen: %d\n", nOutLen );

    JS_BIN_set( &binMsg, pOut, nOutLen );
    JS_BIN_encodeHex( &binMsg, &pHex );
    if( pHex ) printf( "%s\n", pHex );

    return 0;
}

int main()
{
    int ret = 0;
    int     nType = OSSL_CMP_PKIBODY_IR;

    ret = testCMP( nType );

    printf( "Ret: %d\n", ret );
    return 0;
}
