#ifndef CMP_SRV_H
#define CMP_SRV_H

#include "openssl/cmp.h"
#include "js_bin.h"

int procCMP( const BIN *pReq, BIN *pRsp );
OSSL_CMP_SRV_CTX* setupServerCTX();

#endif // CMP_SRV_H
