TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    src/Server.cpp \
    src/PerMessageDeflate.cpp \
    src/Socket.cpp

LIBS += -lssl -lcrypto -lz -luv -lpthread

HEADERS += \
    src/uWS.h \
    src/PerMessageDeflate.h \
    src/Parser.h \
    src/SocketData.h \
    src/Platform.h

QMAKE_CXXFLAGS_RELEASE -= -O1
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE *= -O3 -g

INCLUDEPATH += src
