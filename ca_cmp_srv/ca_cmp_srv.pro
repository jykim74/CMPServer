TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cmp_proc.c \
        cmp_srv.c \
        main.c \
        work_scep.c

INCLUDEPATH += "../../PKILib"

mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/cmpossl/include"
    INCLUDEPATH += "/usr/local/include"
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/cmpossl/lib" -lcrypto -lssl
    LIBS += -L"/usr/local/lib" -lltdl
    LIBS += -lsqlite3
}

win32 {
    contains(QT_ARCH, i386) {
        message( "ca_cmp_srv 32bit" )

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win32/debug/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/debug/cmpossl/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win32/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/cmpossl/lib" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw32\include"
        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lsqlite3
    } else {
        message( "ca_cmp_srv 64bit" )

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win64/debug/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/debug/cmpossl/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win64/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/cmpossl/lib" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw64\include"
        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lsqlite3
    }
}

HEADERS += \
    cmp_srv.h

DISTFILES += \
    ../ca_cmp.cfg
