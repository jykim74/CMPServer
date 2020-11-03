#ifndef CMP_SRV_H
#define CMP_SRV_H

#include "openssl/cmp.h"
#include "js_db.h"
#include "js_bin.h"
#include "js_pki_x509.h"

#define     JS_CMP_SRV_VERSION          "0.9.2"

const char *getBuildInfo();
int procCMP( sqlite3* db, const BIN *pReq, BIN *pRsp );
int procSCEP( sqlite3* db, const JNameValList *pParamList, const BIN *pReq,  BIN *pRsp );
int makeCert( JDB_CertPolicy *pDBCertPolicy, JDB_PolicyExtList *pDBPolicyExtList, JIssueCertInfo *pIssueCertInfo, int nKeyType, BIN *pCert );
OSSL_CMP_SRV_CTX* setupServerCTX();

#endif // CMP_SRV_H
