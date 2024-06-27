#ifndef CMP_SRV_H
#define CMP_SRV_H

#include "openssl/cmp.h"
#include "js_db.h"
#include "js_bin.h"
#include "js_pki_x509.h"

#define     JS_CMP_SRV_VERSION          "0.9.2"

const char *getBuildInfo();
int procGENM( sqlite3 *db, OSSL_CMP_CTX *pCTX, void *pBody );
int procIR( sqlite3* db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, void *pBody, BIN *pNewCert );
int procP10CR( sqlite3* db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, void *pBody, BIN *pNewCert );
int procRR( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody );
int procKUR( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_Cert *pDBCert, void *pBody, BIN *pNewCert );
int procCertConf( sqlite3 *db, OSSL_CMP_CTX *pCTX, JDB_User *pDBUser, JDB_Cert *pDBCert, void *pBody, BIN *pCert );

int procCMP( sqlite3* db, const BIN *pReq, BIN *pRsp );
int procSCEP( sqlite3* db, const JNameValList *pParamList, const BIN *pReq,  BIN *pRsp );
int makeCert( JDB_CertProfile *pDBCertProfile, JDB_ProfileExtList *pDBProfileExtList, JIssueCertInfo *pIssueCertInfo, BIN *pCert );
OSSL_CMP_SRV_CTX* setupServerCTX();

#endif // CMP_SRV_H
