#include <iostream>
using namespace std;

#include "SocketData.h"
#include "Platform.h"
#include <uv.h>

namespace uWS {
class Server;

inline size_t formatMessage(char *dst, char *src, size_t length, OpCode opCode, size_t reportedLength)
{
    size_t messageLength;
    if (reportedLength < 126) {
        messageLength = length + 2;
        memcpy(dst + 2, src, length);
        dst[1] = reportedLength;
    } else if (reportedLength <= UINT16_MAX) {
        messageLength = length + 4;
        memcpy(dst + 4, src, length);
        dst[1] = 126;
        *((uint16_t *) &dst[2]) = htons(reportedLength);
    } else {
        messageLength = length + 10;
        memcpy(dst + 10, src, length);
        dst[1] = 127;
        *((uint64_t *) &dst[2]) = htobe64(reportedLength);
    }

    int flags = 0;
    dst[0] = (flags & SND_NO_FIN ? 0 : 128);
    if (!(flags & SND_CONTINUATION)) {
        dst[0] |= opCode;
    }
    return messageLength;
}

void Socket::close(bool force, unsigned short code, char *data, size_t length)
{
#ifdef VALIDATION
    if (force) {
        cout << "INFO: Close: " << socket << endl;
        if (!validPolls.erase(socket)) {
            cout << "ERROR: Already closed: " << socket << endl;
            exit(-1);
        }
    } else {
        cout << "INFO: Graceful close: " << socket << endl;
        if (validPolls.find(socket) == validPolls.end()) {
            cout << "ERROR: Already closed: " << socket << endl;
            exit(-1);
        }
    }
#endif

    uv_poll_t *p = (uv_poll_t *) socket;
    FD fd;
    uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);
    SocketData *socketData = (SocketData *) p->data;

    if (socketData->state != CLOSING) {
        socketData->state = CLOSING;
        if (socketData->prev == socketData->next) {
            socketData->server->clients = nullptr;
        } else {
            if (socketData->prev) {
                ((SocketData *) ((uv_poll_t *) socketData->prev)->data)->next = socketData->next;
            } else {
                socketData->server->clients = socketData->next;
            }
            if (socketData->next) {
                ((SocketData *) ((uv_poll_t *) socketData->next)->data)->prev = socketData->prev;
            }
        }

        // reuse prev as timer, mark no timer set
        socketData->prev = nullptr;

        // call disconnection callback on first close (graceful or force)
        socketData->server->disconnectionCallback(socket, code, data, length);
    } else if (!force) {
        cout << "WARNING: Already gracefully closed: " << socket << endl;
        return;
    }

    if (force) {
        // delete all messages in queue
        while (!socketData->messageQueue.empty()) {
            socketData->messageQueue.pop();
        }

        uv_poll_stop(p);
        uv_close((uv_handle_t *) p, [](uv_handle_t *handle) {
            delete (uv_poll_t *) handle;
        });

        ::close(fd);
        SSL_free(socketData->ssl);
        socketData->controlBuffer.clear();

        // cancel force close timer
        if (socketData->prev) {
            uv_timer_stop((uv_timer_t *) socketData->prev);
            uv_close((uv_handle_t *) socketData->prev, [](uv_handle_t *handle) {
                delete (uv_timer_t *) handle;
            });
        }

        delete socketData->pmd;
        delete socketData;
    } else {
        // force close after 15 seconds
        socketData->prev = new uv_timer_t;
        uv_timer_init((uv_loop_t *) socketData->server->loop, (uv_timer_t *) socketData->prev);
        ((uv_timer_t *) socketData->prev)->data = socket;
        uv_timer_start((uv_timer_t *) socketData->prev, [](uv_timer_t *timer) {
            Socket(timer->data).close(true, 1006);
        }, 15000, 0);

        char *sendBuffer = socketData->server->sendBuffer;
        if (code) {
            length = min<size_t>(1024, length) + 2;
            *((uint16_t *) &sendBuffer[length + 2]) = htons(code);
            memcpy(&sendBuffer[length + 4], data, length - 2);
        }
        write((char *) sendBuffer, formatMessage(sendBuffer, &sendBuffer[length + 2], length, CLOSE, length), false, [](void *s) {
            uv_poll_t *p = (uv_poll_t *) s;
            FD fd;
            uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);
            SocketData *socketData = (SocketData *) p->data;
            if (socketData->ssl) {
                SSL_shutdown(socketData->ssl);
            }
            shutdown(fd, SHUT_WR);
        });
    }
}

void Socket::send(char *data, size_t length, OpCode opCode, size_t fakedLength)
{
    size_t reportedLength = length;
    if (fakedLength) {
        reportedLength = fakedLength;
    }

    if (length <= Server::SHORT_SEND - 10) {
        SocketData *socketData = (SocketData *) ((uv_poll_t *) socket)->data;
        char *sendBuffer = socketData->server->sendBuffer;
        write(sendBuffer, formatMessage(sendBuffer, data, length, opCode, reportedLength), false);
    } else {
        char *buffer = new char[sizeof(Message) + length + 10] + sizeof(Message);
        write(buffer, formatMessage(buffer, data, length, opCode, reportedLength), true);
    }
}

void Socket::sendFragment(char *data, size_t length, OpCode opCode, size_t remainingBytes)
{
    SocketData *socketData = (SocketData *) ((uv_poll_t *) socket)->data;
    if (remainingBytes) {
        if (socketData->sendState == FRAGMENT_START) {
            send(data, length, opCode, length + remainingBytes);
            socketData->sendState = FRAGMENT_MID;
        } else {
            write(data, length, false);
        }
    } else {
        if (socketData->sendState == FRAGMENT_START) {
            send(data, length, opCode);
        } else {
            write(data, length, false);
            socketData->sendState = FRAGMENT_START;
        }
    }
}

void *Socket::getData()
{
    return ((SocketData *) ((uv_poll_t *) socket)->data)->data;
}

void Socket::setData(void *data)
{
    ((SocketData *) ((uv_poll_t *) socket)->data)->data = data;
}

// async Unix send (has a Message struct in the start if transferOwnership)
void Socket::write(char *data, size_t length, bool transferOwnership, void(*callback)(void *s))
{
    uv_poll_t *p = (uv_poll_t *) socket;
    FD fd;
    uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);

    ssize_t sent = 0;
    SocketData *socketData = (SocketData *) p->data;
    if (!socketData->messageQueue.empty()) {
        goto queueIt;
    }

    if (socketData->ssl) {
        sent = SSL_write(socketData->ssl, data, length);
    } else {
        sent = ::send(fd, data, length, MSG_NOSIGNAL);
    }

    if (sent == (int) length) {
        // everything was sent in one go!
        if (transferOwnership) {
            delete [] (data - sizeof(Message));
        }

        if (callback) {
            callback(socket);
        }

    } else {
        // not everything was sent
        if (sent == -1) {
            // check to see if any error occurred
            if (socketData->ssl) {
                int error = SSL_get_error(socketData->ssl, sent);
                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                    goto queueIt;
                }
            } else {
#ifdef _WIN32
                if (WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
#endif
                    goto queueIt;
                }
            }

            // error sending!
            if (transferOwnership) {
                delete [] (data - sizeof(Message));
            }
            return;
        } else {

            queueIt:
            sent = max<ssize_t>(sent, 0);

            // queue the rest of the message!
            Message *messagePtr;
            if (transferOwnership) {
                messagePtr = (Message *) (data - sizeof(Message));
                messagePtr->data = data + sent;
                messagePtr->length = length - sent;
                messagePtr->nextMessage = nullptr;
            } else {
                // we need to copy the buffer
                messagePtr = (Message *) new char[sizeof(Message) + length - sent];
                messagePtr->length = length - sent;
                messagePtr->data = ((char *) messagePtr) + sizeof(Message);
                messagePtr->nextMessage = nullptr;
                memcpy(messagePtr->data, data + sent, messagePtr->length);
            }

            messagePtr->callback = callback;
            ((SocketData *) p->data)->messageQueue.push(messagePtr);

            // only start this if we just broke the 0 queue size!
            uv_poll_start(p, UV_WRITABLE | UV_READABLE, [](uv_poll_t *handle, int status, int events) {

#ifdef VALIDATION
                if (validPolls.find(handle) == validPolls.end()) {
                    cout << "ERROR: Woke up closed poll(UV_WRITABLE | UV_READABLE): " << handle << endl;
                    exit(-1);
                } else {
                    cout << "INFO: Woke up poll(UV_WRITABLE | UV_READABLE): " << handle << endl;
                }
#endif

                // handle all poll errors with forced disconnection
                if (status < 0) {
                    Socket(handle).close(true, 1006);
                    return;
                }

                // handle reads if available
                if (events & UV_READABLE) {
                    Server::onReadable(handle, status, events);
                    if (!(events & UV_WRITABLE)) {
                        return;
                    }
                }

                SocketData *socketData = (SocketData *) handle->data;

                if (socketData->state == CLOSING) {
                    cout << "CLOSING state, Socket::write" << endl;
                    return;
                }

                FD fd;
                uv_fileno((uv_handle_t *) handle, (uv_os_fd_t *) &fd);

                do {
                    Message *messagePtr = socketData->messageQueue.front();

                    ssize_t sent;
                    if (socketData->ssl) {
                        sent = SSL_write(socketData->ssl, messagePtr->data, messagePtr->length);
                    } else {
                        sent = ::send(fd, messagePtr->data, messagePtr->length, MSG_NOSIGNAL);
                    }

                    if (sent == (int) messagePtr->length) {

                        if (messagePtr->callback) {
                            messagePtr->callback(handle);
                        }

                        socketData->messageQueue.pop();
                    } else {
                        if (sent == -1) {
                            // check to see if any error occurred
                            if (socketData->ssl) {
                                int error = SSL_get_error(socketData->ssl, sent);
                                if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                                    return;
                                }
                            } else {
                #ifdef _WIN32
                                if (WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEWOULDBLOCK) {
                #else
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                #endif
                                    return;
                                }
                            }

                            // error sending!
                            uv_poll_start(handle, UV_READABLE, (uv_poll_cb) Server::onReadable);
                            return;
                        } else {
                            // update the Message
                            messagePtr->data += sent;
                            messagePtr->length -= sent;
                            return;
                        }
                    }
                } while (!socketData->messageQueue.empty());

                // only receive when we have fully sent everything
                uv_poll_start(handle, UV_READABLE, (uv_poll_cb) Server::onReadable);
            });
        }
    }
}

Socket::Address Socket::getAddress()
{
    uv_poll_t *p = (uv_poll_t *) socket;
    FD fd;
    uv_fileno((uv_handle_t *) p, (uv_os_fd_t *) &fd);

    sockaddr_storage addr;
    socklen_t addrLength = sizeof(addr);
    getpeername(fd, (sockaddr *) &addr, &addrLength);

    static __thread char buf[INET6_ADDRSTRLEN];

    if (addr.ss_family == AF_INET) {
        sockaddr_in *ipv4 = (sockaddr_in *) &addr;
        inet_ntop(AF_INET, &ipv4->sin_addr, buf, sizeof(buf));
        return {ntohs(ipv4->sin_port), buf, "IPv4"};
    } else {
        sockaddr_in6 *ipv6 = (sockaddr_in6 *) &addr;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, buf, sizeof(buf));
        return {ntohs(ipv6->sin6_port), buf, "IPv6"};
    }
}

}
