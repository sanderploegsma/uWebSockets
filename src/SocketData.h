#ifndef SOCKETDATA_H
#define SOCKETDATA_H

#include <string>
#include <openssl/ssl.h>

#include "uWS.h"

struct PerMessageDeflate;

namespace uWS {

enum SendFlags {
    SND_CONTINUATION = 1,
    SND_NO_FIN = 2
};

enum SocketState : int {
    READ_HEAD,
    READ_MESSAGE,
    CLOSING
};

enum SocketSendState : int {
    FRAGMENT_START,
    FRAGMENT_MID
};

struct Message {
    char *data;
    size_t length;
    Message *nextMessage = nullptr;
    void (*callback)(void *s) = nullptr;
};

struct Queue {
    Message *head = nullptr, *tail = nullptr;
    void pop()
    {
        Message *nextMessage;
        if ((nextMessage = head->nextMessage)) {
            delete [] (char *) head;
            head = nextMessage;
        } else {
            delete [] (char *) head;
            head = tail = nullptr;
        }
    }

    bool empty() {return head == nullptr;}
    Message *front() {return head;}
    void push(Message *message)
    {
        if (tail) {
            tail->nextMessage = message;
            tail = message;
        } else {
            head = message;
            tail = message;
        }
    }
};

struct SocketData {
    unsigned char state = READ_HEAD;
    unsigned char sendState = FRAGMENT_START;
    unsigned char fin = true;
    char opStack = -1;
    char spill[16]; // can be 14 in size
    unsigned char spillLength = 0;
    OpCode opCode[2];
    unsigned int remainingBytes = 0;
    char mask[4];
    Server *server;
    Queue messageQueue;
    // points to uv_poll_t
    void *next = nullptr, *prev = nullptr, *data = nullptr;
    SSL *ssl = nullptr;
    PerMessageDeflate *pmd = nullptr;
    std::string buffer, controlBuffer; // turns out these are very lightweight (in GCC)
};

}

#endif // SOCKETDATA_H
