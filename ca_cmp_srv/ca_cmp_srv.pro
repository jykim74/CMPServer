TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

DEFINES += USE_CMP
DEFINES += USE_SCEP

SOURCES += \
        cmp_mock_srv.c \
        cmp_proc.c \
        cmp_srv.c \
        work_scep.c

INCLUDEPATH += "../../PKILib"


mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/openssl3/include"
    INCLUDEPATH += "/usr/local/include"
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/openssl3/lib" -lcrypto -lssl
    LIBS += -L"/usr/local/lib" -lltdl
    LIBS += -lsqlite3
}

win32 {
    contains(QT_ARCH, i386) {
        message( "ca_cmp_srv 32bit" )

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win32/debug/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug" -lPKILib -lws2_32
            LIBS += -L"../../lib/win32/debug/openssl3/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win32/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release" -lPKILib -lws2_32
            LIBS += -L"../../lib/win32/openssl3/lib" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw32\include"
        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lsqlite3
    } else {
        message( "ca_cmp_srv 64bit" )

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win64/debug/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug" -lPKILib -lws2_32
            LIBS += -L"../../lib/win64/debug/openssl3/lib64" -lcrypto -lssl
            LIBS += -L"../../win64"
        } else {
            INCLUDEPATH += "../../PKILib/lib/win64/"$${OPENSSL_NAME}"/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release" -lPKILib -lws2_32
            LIBS += -L"../../lib/win64/openssl3/lib64" -lcrypto -lssl
            LIBS += -L"../../win64"
        }

        INCLUDEPATH += "C:\msys64\mingw64\include"
        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lsqlite3
    }
}

HEADERS += \
    cmp_mock_srv.h \
    cmp_srv.h

DISTFILES += \
    ../ca_cmp.cfg
