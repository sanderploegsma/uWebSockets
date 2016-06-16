#include "uWS.h"
using namespace uWS;

#include "Parser.h"

#include <iostream>
#include <queue>
#include <algorithm>
using namespace std;

//#define VALIDATION

#ifdef VALIDATION
#include <set>
std::set<void *> validPolls;
#endif

#include "Platform.h"

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>

#include <uv.h>
#include <zlib.h>

#include "PerMessageDeflate.h"

void base64(unsigned char *src, char *dst)
{
    static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 18; i += 3) {
        *dst++ = b64[(src[i] >> 2) & 63];
        *dst++ = b64[((src[i] & 3) << 4) | ((src[i + 1] & 240) >> 4)];
        *dst++ = b64[((src[i + 1] & 15) << 2) | ((src[i + 2] & 192) >> 6)];
        *dst++ = b64[src[i + 2] & 63];
    }
    *dst++ = b64[(src[18] >> 2) & 63];
    *dst++ = b64[((src[18] & 3) << 4) | ((src[19] & 240) >> 4)];
    *dst++ = b64[((src[19] & 15) << 2)];
    *dst++ = '=';
}

tuple<unsigned short, char *, size_t> parseCloseFrame(string &payload)
{
    unsigned short code = 0;
    char *message = nullptr;
    size_t length = 0;

    if (payload.length() >= 2) {
        code = ntohs(*(uint16_t *) payload.data());

        // correct bad codes
        if (code < 1000 || code > 1011 || (code >= 1004 && code <= 1006)) {
            code = 0;
        }
    }

    if (payload.length() > 2) {
        message = (char *) payload.data() + 2;
        length = payload.length() - 2;

        // check utf-8
        if (!Server::isValidUtf8((unsigned char *) message, length)) {
            code = length = 0;
        }
    }

    return make_tuple(code, message, length);
}


Server::Server(int port, bool master, int options, int maxPayload, string path) : port(port), master(master), options(options), maxPayload(maxPayload), path(path)
{
    // lowercase the path
    if (!path.length() || path[0] != '/') {
        path = '/' + path;
    }
    transform(path.begin(), path.end(), path.begin(), ::tolower);

    onConnection([](Socket socket) {});
    onDisconnection([](Socket socket, int code, char *message, size_t length) {});
    onMessage([](Socket socket, const char *data, size_t length, OpCode opCode) {});

    // we need 24 bytes over to not read invalidly outside

    // we need 4 bytes (or 3 at least) outside for unmasking
    receiveBuffer = (char *) new uint32_t[BUFFER_SIZE / 4 + 6];

    sendBuffer = new char[SHORT_SEND];
    inflateBuffer = new char[INFLATE_BUFFER_SIZE];
    upgradeResponse = new char[2048];

    // set default fragment handler
    fragmentCallback = internalFragment;

    listenAddr = new sockaddr_in;
    ((sockaddr_in *) listenAddr)->sin_family = AF_INET;
    ((sockaddr_in *) listenAddr)->sin_addr.s_addr = INADDR_ANY;
    ((sockaddr_in *) listenAddr)->sin_port = htons(port);

    loop = master ? uv_default_loop() : uv_loop_new();

    if (port) {
        FD listenFd = socket(AF_INET, SOCK_STREAM, 0);
        if (::bind(listenFd, (sockaddr *) listenAddr, sizeof(sockaddr_in)) | listen(listenFd, 10)) {
            throw nullptr; // ERR_LISTEN
        }

        //SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);

        this->server = new uv_poll_t;
        uv_poll_init_socket((uv_loop_t *) loop, (uv_poll_t *) this->server, listenFd);
        uv_poll_start((uv_poll_t *) this->server, UV_READABLE, (uv_poll_cb) onAcceptable);
        ((uv_poll_t *) this->server)->data = this;
    }

    if (!master) {
        upgradeAsync = new uv_async_t;
        closeAsync = new uv_async_t;
        ((uv_async_t *) upgradeAsync)->data = this;
        ((uv_async_t *) closeAsync)->data = this;

        uv_async_init((uv_loop_t *) loop, (uv_async_t *) closeAsync, [](uv_async_t *a) {
            Server::closeHandler((Server *) a->data);
        });

        uv_async_init((uv_loop_t *) loop, (uv_async_t *) upgradeAsync, [](uv_async_t *a) {
            Server::upgradeHandler((Server *) a->data);
        });
    }
}

Server::~Server()
{
    delete [] (uint32_t *) receiveBuffer;
    delete [] sendBuffer;
    delete [] inflateBuffer;
    delete [] upgradeResponse;
    delete (sockaddr_in *) listenAddr;

    if (!master) {
        uv_loop_delete((uv_loop_t *) loop);
    }
}

void Server::run()
{
    uv_run((uv_loop_t *) loop, UV_RUN_DEFAULT);
}

void Server::close(bool force)
{
    forceClose = force;
    if (master) {
        Server::closeHandler(this);
    } else {
        uv_async_send((uv_async_t *) closeAsync);
    }
}

// unoptimized!
void Server::broadcast(char *data, size_t length, OpCode opCode)
{
    // use same doubly linked list as the server uses to track its clients
    // prepare the buffer, send multiple times

    // todo: this should be optimized to send the same message for every client!
    for (void *p = clients; p; p = ((SocketData *) ((uv_poll_t *) p)->data)->next) {
        Socket(p).send(data, length, opCode);
    }
}

void Server::upgradeHandler(Server *server)
{
    server->upgradeQueueMutex.lock();

    // todo: parallel upgrade, just move the queue here
    while (!server->upgradeQueue.empty()) {
        auto upgradeRequest = server->upgradeQueue.front();
        server->upgradeQueue.pop();

        // upgrade the connection
        unsigned char shaInput[] = "XXXXXXXXXXXXXXXXXXXXXXXX258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        memcpy(shaInput, get<1>(upgradeRequest).c_str(), 24);
        unsigned char shaDigest[SHA_DIGEST_LENGTH];
        SHA1(shaInput, sizeof(shaInput) - 1, shaDigest);

        memcpy(server->upgradeResponse, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ", 97);
        base64(shaDigest, server->upgradeResponse + 97);
        memcpy(server->upgradeResponse + 125, "\r\n", 2);
        size_t upgradeResponseLength = 127;

        uv_poll_t *clientPoll = new uv_poll_t;
        uv_poll_init_socket((uv_loop_t *) server->loop, clientPoll, get<0>(upgradeRequest));
        SocketData *socketData = new SocketData;
        socketData->server = server;

        PerMessageDeflate::NegotiationOffer offer(get<3>(upgradeRequest).c_str());
        if ((server->options & PERMESSAGE_DEFLATE) && offer.perMessageDeflate) {
            string response;
            socketData->pmd = new PerMessageDeflate(offer, server->options, response);
            response.append("\r\n\r\n");
            memcpy(server->upgradeResponse + 127, response.data(), response.length());
            upgradeResponseLength += response.length();
        } else {
            memcpy(server->upgradeResponse + 127, "\r\n", 2);
            upgradeResponseLength += 2;
        }

        socketData->ssl = (SSL *) get<2>(upgradeRequest);
        if (socketData->ssl) {
            SSL_set_fd(socketData->ssl, get<0>(upgradeRequest));
            SSL_set_mode(socketData->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
        }

        clientPoll->data = socketData;
        uv_poll_start(clientPoll, UV_READABLE, (uv_poll_cb) onReadable);

#ifdef VALIDATION
        if (!validPolls.insert(clientPoll).second) {
            cout << "ERROR: Already opened: " << clientPoll << endl;
            exit(-1);
        } else {
            cout << "INFO: Open: " << clientPoll << endl;
        }
#endif

        // add this poll to the list
        if (!server->clients) {
            server->clients = clientPoll;
        } else {
            SocketData *tailData = (SocketData *) ((uv_poll_t *) server->clients)->data;
            tailData->prev = clientPoll;
            socketData->next = server->clients;
            server->clients = clientPoll;
        }

        //cout << "[" << string(server->upgradeResponse, upgradeResponseLength) << "]" << endl;

        Socket(clientPoll).write(server->upgradeResponse, upgradeResponseLength, false);
        server->connectionCallback(clientPoll);
    }

    server->upgradeQueueMutex.unlock();
}

void Server::closeHandler(Server *server)
{
    if (!server->master) {
        uv_close((uv_handle_t *) server->upgradeAsync, [](uv_handle_t *a) {
            delete (uv_async_t *) a;
        });

        uv_close((uv_handle_t *) server->closeAsync, [](uv_handle_t *a) {
            delete (uv_async_t *) a;
        });
    }

    if (server->server) {
        FD listenFd;
        uv_fileno((uv_handle_t *) server->server, (uv_os_fd_t *) &listenFd);
        ::close(listenFd);
        uv_poll_stop((uv_poll_t *) server->server);
        uv_close((uv_handle_t *) server->server, [](uv_handle_t *handle) {
            delete (uv_poll_t *) handle;
        });
    }

    for (void *p = server->clients; p; p = ((SocketData *) ((uv_poll_t *) p)->data)->next) {
        Socket(p).close(server->forceClose);
    }
}

// move this into Server.cpp
void Server::upgrade(FD fd, const char *secKey, void *ssl, const char *extensions, size_t extensionsLength)
{
    // add upgrade request to the queue
    upgradeQueueMutex.lock();
    upgradeQueue.push(make_tuple(fd, string(secKey, 24), ssl, string(extensions, extensionsLength)));
    upgradeQueueMutex.unlock();

    if (master) {
        Server::upgradeHandler(this);
    } else {
        uv_async_send((uv_async_t *) upgradeAsync);
    }
}

void Server::onAcceptable(void *vp, int status, int events)
{
    if (status < 0) {
        // error accept
        return;
    }

    uv_poll_t *p = (uv_poll_t *) vp;

    socklen_t listenAddrLength = sizeof(sockaddr_in);
    FD serverFd;
    uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &serverFd);
    FD clientFd = accept(serverFd, (sockaddr *) ((Server *) p->data)->listenAddr, &listenAddrLength);

    // if accept fails, we just ignore the connection
    if (clientFd == -1) {
        return;
    }

#ifdef __APPLE__
    int noSigpipe = 1;
    setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, sizeof(int));
#endif

    // start async reading of http headers
    uv_poll_t *http = new uv_poll_t;
    http->data = new HTTPData{(Server *) p->data};
    uv_poll_init_socket((uv_loop_t *) ((Server *) p->data)->loop, http, clientFd);
    uv_poll_start(http, UV_READABLE, [](uv_poll_t *p, int status, int events) {

        if (status < 0) {
            // error read
        }

        FD fd;
        uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);
        HTTPData *httpData = (HTTPData *) p->data;
        int length = recv(fd, httpData->server->receiveBuffer, BUFFER_SIZE, 0);
        httpData->headerBuffer.append(httpData->server->receiveBuffer, length);

        // did we read the complete header?
        if (httpData->headerBuffer.find("\r\n\r\n") != string::npos) {

            // our part is done here
            uv_poll_stop(p);
            uv_close((uv_handle_t *) p, [](uv_handle_t *handle) {
                delete (HTTPData *) handle->data;
                delete (uv_poll_t *) handle;
            });

            Request h = (char *) httpData->headerBuffer.data();

            // strip away any ? from the GET request
            h.value.first[h.value.second] = 0;
            for (size_t i = 0; i < h.value.second; i++) {
                if (h.value.first[i] == '?') {
                    h.value.first[i] = 0;
                    break;
                } else {
                    // lowercase the request path
                    h.value.first[i] = tolower(h.value.first[i]);
                }
            }

            pair<char *, size_t> secKey = {}, extensions = {};

            // only accept requests with our path
            //if (!strcmp(h.value.first, httpData->server->path.c_str())) {
                for (h++; h.key.second; h++) {
                    if (h.key.second == 17 || h.key.second == 24) {
                        // lowercase the key
                        for (size_t i = 0; i < h.key.second; i++) {
                            h.key.first[i] = tolower(h.key.first[i]);
                        }
                        if (!strncmp(h.key.first, "sec-websocket-key", h.key.second)) {
                            secKey = h.value;
                        } else if (!strncmp(h.key.first, "sec-websocket-extensions", h.key.second)) {
                            extensions = h.value;
                        }
                    }
                }

                // this is an upgrade
                if (secKey.first && secKey.second == 24) {
                    if (httpData->server->upgradeCallback) {
                        httpData->server->upgradeCallback(fd, secKey.first, nullptr, extensions.first, extensions.second);
                    } else {
                        httpData->server->upgrade(fd, secKey.first, nullptr, extensions.first, extensions.second);
                    }
                    return;
                }
            //}

            // for now, we just close HTTP traffic
            ::close(fd);
        } else {
            // todo: start timer to time out the connection!

        }
    });
    //SSL *SSL_new(SSL_CTX *ctx);
    //int SSL_set_fd(SSL *ssl, int fd);
}

// default HTTP handler
void Server::internalHTTP(Request &request)
{
    cout << "Got some HTTP action!" << endl;
}

#define STRICT

// 0.17% CPU time
void Server::onReadable(void *vp, int status, int events)
{
#ifdef VALIDATION
    if (validPolls.find(vp) == validPolls.end()) {
        cout << "ERROR: Woke up closed poll(UV_READABLE): " << vp << endl;
        exit(-1);
    } else {
        cout << "INFO: Woke up poll(UV_READABLE): " << vp << endl;
    }
#endif

    uv_poll_t *p = (uv_poll_t *) vp;
    SocketData *socketData = (SocketData *) p->data;

    // this one is not needed, read will do this!
    if (status < 0) {
        Socket(p).close(true, 1006);
        return;
    }

    char *src = socketData->server->receiveBuffer;
    memcpy(src, socketData->spill, socketData->spillLength);
    FD fd;
    uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);

    ssize_t received;
    if (socketData->ssl) {
        received = SSL_read(socketData->ssl, src + socketData->spillLength, BUFFER_SIZE - socketData->spillLength);
    } else {
        received = recv(fd, src + socketData->spillLength, BUFFER_SIZE - socketData->spillLength, 0);
    }

    if (received == -1 || received == 0) {
        // do we have a close frame in our buffer, and did we already set the state as CLOSING?
        if (socketData->state == CLOSING && socketData->controlBuffer.length()) {
            tuple<unsigned short, char *, size_t> closeFrame = parseCloseFrame(socketData->controlBuffer);
            if (!get<0>(closeFrame)) {
                get<0>(closeFrame) = 1006;
            }
            Socket(p).close(true, get<0>(closeFrame), get<1>(closeFrame), get<2>(closeFrame));
        } else {
            Socket(p).close(true, 1006);
        }
        return;
    }

    // do not parse any data once in closing state
    if (socketData->state == CLOSING) {
        return;
    }

    // cork sends into one large package
#ifdef __linux
    int cork = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(int));
#endif

    int length = socketData->spillLength + received;

    parseNext:
    if (socketData->state == READ_HEAD) {

        while (length >= (int) sizeof(frameFormat)) {
            frameFormat frame = *(frameFormat *) src;

            int lastFin = socketData->fin;
            socketData->fin = fin(frame);

            if (socketData->pmd && opCode(frame) != 0) {
                socketData->pmd->compressedFrame = rsv1(frame);
            }

#ifdef STRICT
            // invalid reserved bits
            if ((rsv1(frame) && !socketData->pmd) || rsv2(frame) || rsv3(frame)) {
                Socket(p).close(true, 1006);
                return;
            }

            // invalid opcodes
            if ((opCode(frame) > 2 && opCode(frame) < 8) || opCode(frame) > 10) {
                Socket(p).close(true, 1006);
                return;
            }
#endif

            // do not store opCode continuation!
            if (opCode(frame)) {

                // if empty stack or a new op-code, push on stack!
                if (socketData->opStack == -1 || socketData->opCode[(unsigned char) socketData->opStack] != (OpCode) opCode(frame)) {
                    socketData->opCode[(unsigned char) ++socketData->opStack] = (OpCode) opCode(frame);
                }

#ifdef STRICT
                // Case 5.18
                if (socketData->opStack == 0 && !lastFin && fin(frame)) {
                    Socket(p).close(true, 1006);
                    return;
                }

                // control frames cannot be fragmented or long
                if (opCode(frame) > 2 && (!fin(frame) || payloadLength(frame) > 125)) {
                    Socket(p).close(true, 1006);
                    return;
                }

            } else {
                // continuation frame must have a opcode prior!
                if (socketData->opStack == -1) {
                    Socket(p).close(true, 1006);
                    return;
                }
#endif
            }

            if (payloadLength(frame) > 125) {
                if (payloadLength(frame) == 126) {
                    const int MEDIUM_MESSAGE_HEADER = 8;
                    // we need to have enough length to read the long length
                    if (length < 2 + (int) sizeof(uint16_t)) {
                        break;
                    }
                    if (ntohs(*(uint16_t *) &src[2]) <= length - MEDIUM_MESSAGE_HEADER) {
                        if (Parser::consumeCompleteMessage(length, MEDIUM_MESSAGE_HEADER, ntohs(*(uint16_t *) &src[2]), socketData, &src, frame, p)) {
                            return;
                        }
                    } else {
                        if (length < MEDIUM_MESSAGE_HEADER + 1) {
                            break;
                        }
                        Parser::consumeIncompleteMessage(length, MEDIUM_MESSAGE_HEADER, ntohs(*(uint16_t *) &src[2]), socketData, src, p);
                        return;
                    }
                } else {
                    const int LONG_MESSAGE_HEADER = 14;
                    // we need to have enough length to read the long length
                    if (length < 2 + (int) sizeof(uint64_t)) {
                        break;
                    }
                    if (be64toh(*(uint64_t *) &src[2]) <= (uint64_t) length - LONG_MESSAGE_HEADER) {
                        if (Parser::consumeCompleteMessage(length, LONG_MESSAGE_HEADER, be64toh(*(uint64_t *) &src[2]), socketData, &src, frame, p)) {
                            return;
                        }
                    } else {
                        if (length < LONG_MESSAGE_HEADER + 1) {
                            break;
                        }
                        Parser::consumeIncompleteMessage(length, LONG_MESSAGE_HEADER, be64toh(*(uint64_t *) &src[2]), socketData, src, p);
                        return;
                    }
                }
            } else {
                const int SHORT_MESSAGE_HEADER = 6;
                if (payloadLength(frame) <= length - SHORT_MESSAGE_HEADER) {
                    if (Parser::consumeCompleteMessage(length, SHORT_MESSAGE_HEADER, payloadLength(frame), socketData, &src, frame, p)) {
                        return;
                    }
                } else {
                    if (length < SHORT_MESSAGE_HEADER + 1) {
                        break;
                    }
                    Parser::consumeIncompleteMessage(length, SHORT_MESSAGE_HEADER, payloadLength(frame), socketData, src, p);
                    return;
                }
            }
        }

        if (length) {
            memcpy(socketData->spill, src, length);
            socketData->spillLength = length;
        }
    } else {
        if (socketData->remainingBytes < (unsigned int) length) {
            if (Parser::consumeCompleteTail(&src, length, socketData, p)) {
                return;
            }
            goto parseNext;
        } else {
            Parser::consumeEntireBuffer(src, length, socketData, p);
        }
    }

#ifdef __linux
    cork = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(int));
#endif
}

void Server::onFragment(void (*fragmentCallback)(Socket, const char *, size_t, OpCode, bool, size_t, bool))
{
    this->fragmentCallback = fragmentCallback;
}

void Server::onUpgrade(function<void(FD, const char *, void *, const char *, size_t)> upgradeCallback)
{
    this->upgradeCallback = upgradeCallback;
}

void Server::onConnection(function<void(Socket)> connectionCallback)
{
    this->connectionCallback = connectionCallback;
}

void Server::onDisconnection(function<void(Socket, int code, char *message, size_t length)> disconnectionCallback)
{
    this->disconnectionCallback = disconnectionCallback;
}

void Server::onMessage(function<void(Socket, const char *, size_t, OpCode)> messageCallback)
{
    this->messageCallback = messageCallback;
}

// default fragment handler
void Server::internalFragment(Socket socket, const char *fragment, size_t length, OpCode opCode, bool fin, size_t remainingBytes, bool compressed)
{
    uv_poll_t *p = (uv_poll_t *) socket.socket;
    SocketData *socketData = (SocketData *) p->data;

    // Text or binary
    if (opCode < 3) {

        // permessage-deflate
        if (compressed) {
            socketData->pmd->setInput((char *) fragment, length);
            size_t bufferSpace;
            try {
                while (!(bufferSpace = socketData->pmd->inflate(socketData->server->inflateBuffer, INFLATE_BUFFER_SIZE))) {
                    socketData->buffer.append(socketData->server->inflateBuffer, INFLATE_BUFFER_SIZE);
                }

                if (!remainingBytes && fin) {
                    unsigned char tail[4] = {0, 0, 255, 255};
                    socketData->pmd->setInput((char *) tail, 4);
                    if (!socketData->pmd->inflate(socketData->server->inflateBuffer + INFLATE_BUFFER_SIZE - bufferSpace, bufferSpace)) {
                        socketData->buffer.append(socketData->server->inflateBuffer + INFLATE_BUFFER_SIZE - bufferSpace, bufferSpace);
                        while (!(bufferSpace = socketData->pmd->inflate(socketData->server->inflateBuffer, INFLATE_BUFFER_SIZE))) {
                            socketData->buffer.append(socketData->server->inflateBuffer, INFLATE_BUFFER_SIZE);
                        }
                    }
                }
            } catch (...) {
                socket.close(true, 1006);
                return;
            }

            fragment = socketData->server->inflateBuffer;
            length = INFLATE_BUFFER_SIZE - bufferSpace;
        }

        if (!remainingBytes && fin && !socketData->buffer.length()) {
            if (opCode == 1 && !Server::isValidUtf8((unsigned char *) fragment, length)) {
                socket.close(true, 1006);
                return;
            }

            socketData->server->messageCallback(socket, (char *) fragment, length, opCode);
        } else {
            socketData->buffer.append(fragment, socketData->server->maxPayload ? min(length, socketData->server->maxPayload - socketData->buffer.length()) : length);
            if (!remainingBytes && fin) {

                // Chapter 6
                if (opCode == 1 && !Server::isValidUtf8((unsigned char *) socketData->buffer.c_str(), socketData->buffer.length())) {
                    socket.close(true, 1006);
                    return;
                }

                socketData->server->messageCallback(socket, (char *) socketData->buffer.c_str(), socketData->buffer.length(), opCode);
                socketData->buffer.clear();
            }
        }


    } else {
        socketData->controlBuffer.append(fragment, length);
        if (!remainingBytes && fin) {
            if (opCode == CLOSE) {
                tuple<unsigned short, char *, size_t> closeFrame = parseCloseFrame(socketData->controlBuffer);
                Socket(p).close(false, get<0>(closeFrame), get<1>(closeFrame), get<2>(closeFrame));
                // leave the controlBuffer with the close frame intact
                return;
            } else {
                if (opCode == PING) {
                    opCode = PONG;
                } else if (opCode == PONG) {
                    opCode = PING;
                }

                socket.send((char *) socketData->controlBuffer.c_str(), socketData->controlBuffer.length(), opCode);
            }
            socketData->controlBuffer.clear();
        }
    }
}

bool Server::isValidUtf8(unsigned char *str, size_t length)
{
    /*
    Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
    OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    */
    static uint8_t utf8d[] = {
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
      1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
      7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
      8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
      0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
      0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
      0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
      1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
      1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
      1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
      1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
    };

    // Modified (c) 2016 Alex Hultman
    uint8_t *utf8d_256 = utf8d + 256, state = 0;
    for (int i = 0; i < (int) length; i++) {
        state = utf8d_256[(state << 4) + utf8d[str[i]]];
    }
    return !state;
}
