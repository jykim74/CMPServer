#ifndef CMP_SRV_H
#define CMP_SRV_H

#include "openssl/cmp.h"
#include "js_db.h"
#include "js_bin.h"

#define     JS_CMP_SRV_VERSION          "0.9.1"

const char *getBuildInfo();
int procCMP( sqlite3* db, const BIN *pReq, BIN *pRsp );
OSSL_CMP_SRV_CTX* setupServerCTX();

#endif // CMP_SRV_H
