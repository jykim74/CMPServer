#ifndef CMP_SRV_H
#define CMP_SRV_H

#include "openssl/cmp.h"
#include "js_db.h"
#include "js_bin.h"

int procCMP( sqlite3* db, const BIN *pReq, BIN *pRsp );
OSSL_CMP_SRV_CTX* setupServerCTX();

#endif // CMP_SRV_H
