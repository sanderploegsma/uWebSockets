#ifndef PARSER_H
#define PARSER_H

#include "SocketData.h"
#include "PerMessageDeflate.h"

#include <uv.h>

#include <string>
#include <vector>
#include <utility>
#include <cstddef>

namespace uWS {
class Server;

struct HTTPData {
    Server *server;
    std::string headerBuffer;
    std::vector<std::pair<char *, size_t>> headers;
};

struct Request {
    char *cursor;
    std::pair<char *, size_t> key, value;
    Request(char *cursor) : cursor(cursor)
    {
        size_t length;
        for (; isspace(*cursor); cursor++);
        for (length = 0; !isspace(cursor[length]) && cursor[length] != '\r'; length++);
        key = {cursor, length};
        cursor += length + 1;
        for (length = 0; !isspace(cursor[length]) && cursor[length] != '\r'; length++);
        value = {cursor, length};
    }

    Request &operator++(int)
    {
        size_t length = 0;
        for (; !(cursor[0] == '\r' && cursor[1] == '\n'); cursor++);
        cursor += 2;
        if (cursor[0] == '\r' && cursor[1] == '\n') {
            key = value = {0, 0};
        } else {
            for (; cursor[length] != ':' && cursor[length] != '\r'; length++);
            key = {cursor, length};
            if (cursor[length] != '\r') {
                cursor += length;
                length = 0;
                while (isspace(*(++cursor)));
                for (; cursor[length] != '\r'; length++);
                value = {cursor, length};
            } else {
                value = {0, 0};
            }
        }
        return *this;
    }
};

typedef uint16_t frameFormat;
inline bool fin(frameFormat &frame) {return frame & 128;}
inline unsigned char opCode(frameFormat &frame) {return frame & 15;}
inline unsigned char payloadLength(frameFormat &frame) {return (frame >> 8) & 127;}
inline bool rsv3(frameFormat &frame) {return frame & 16;}
inline bool rsv2(frameFormat &frame) {return frame & 32;}
inline bool rsv1(frameFormat &frame) {return frame & 64;}
inline bool mask(frameFormat &frame) {return frame & 32768;}

struct Parser {
    static inline void unmask_imprecise(char *dst, char *src, char *mask, unsigned int length)
    {
        for (unsigned int n = (length >> 2) + 1; n; n--) {
            *(dst++) = *(src++) ^ mask[0];
            *(dst++) = *(src++) ^ mask[1];
            *(dst++) = *(src++) ^ mask[2];
            *(dst++) = *(src++) ^ mask[3];
        }
    }

    static inline void unmask_imprecise_copy_mask(char *dst, char *src, char *maskPtr, unsigned int length)
    {
        char mask[4] = {maskPtr[0], maskPtr[1], maskPtr[2], maskPtr[3]};
        unmask_imprecise(dst, src, mask, length);
    }

    static inline void rotate_mask(unsigned int offset, char *mask)
    {
        char originalMask[4] = {mask[0], mask[1], mask[2], mask[3]};
        mask[(0 + offset) % 4] = originalMask[0];
        mask[(1 + offset) % 4] = originalMask[1];
        mask[(2 + offset) % 4] = originalMask[2];
        mask[(3 + offset) % 4] = originalMask[3];
    }

    static inline void unmask_inplace(char *data, char *stop, char *mask)
    {
        while (data < stop) {
            *(data++) ^= mask[0];
            *(data++) ^= mask[1];
            *(data++) ^= mask[2];
            *(data++) ^= mask[3];
        }
    }

    template <typename T>
    static inline void consumeIncompleteMessage(int length, const int headerLength, T fullPayloadLength, SocketData *socketData, char *src, void *socket)
    {
        socketData->spillLength = 0;
        socketData->state = READ_MESSAGE;
        socketData->remainingBytes = fullPayloadLength - length + headerLength;

        memcpy(socketData->mask, src + headerLength - 4, 4);
        unmask_imprecise(src, src + headerLength, socketData->mask, length);
        rotate_mask(4 - (length - headerLength) % 4, socketData->mask);

        socketData->server->fragmentCallback(socket, src, length - headerLength,
                                             socketData->opCode[(unsigned char) socketData->opStack], socketData->fin, socketData->remainingBytes, socketData->pmd && socketData->pmd->compressedFrame);
    }

    template <typename T>
    static inline int consumeCompleteMessage(int &length, const int headerLength, T fullPayloadLength, SocketData *socketData, char **src, frameFormat &frame, void *socket)
    {
        unmask_imprecise_copy_mask(*src, *src + headerLength, *src + headerLength - 4, fullPayloadLength);
        socketData->server->fragmentCallback(socket, *src, fullPayloadLength, socketData->opCode[(unsigned char) socketData->opStack], socketData->fin, 0, socketData->pmd && socketData->pmd->compressedFrame);

        if (uv_is_closing((uv_handle_t *) socket) || socketData->state == CLOSING) {
            return 1;
        }

        if (fin(frame)) {
            socketData->opStack--;
        }

        *src += fullPayloadLength + headerLength;
        length -= fullPayloadLength + headerLength;
        socketData->spillLength = 0;
        return 0;
    }

    static inline void consumeEntireBuffer(char *src, int length, SocketData *socketData, void *p)
    {
        int n = (length >> 2) + bool(length % 4); // this should always overwrite!

        unmask_inplace(src, src + n * 4, socketData->mask);
        socketData->remainingBytes -= length;
        socketData->server->fragmentCallback(p, (const char *) src, length,
                                             socketData->opCode[(unsigned char) socketData->opStack], socketData->fin, socketData->remainingBytes, socketData->pmd && socketData->pmd->compressedFrame);

        if (uv_is_closing((uv_handle_t *) p) || socketData->state == CLOSING) {
            return;
        }

        // if we perfectly read the last of the message, change state!
        if (!socketData->remainingBytes) {
            socketData->state = READ_HEAD;

            if (socketData->fin) {
                socketData->opStack--;
            }
        } else if (length % 4) {
            rotate_mask(4 - (length % 4), socketData->mask);
        }
    }

    static inline int consumeCompleteTail(char **src, int &length, SocketData *socketData, void *p)
    {
        int n = (socketData->remainingBytes >> 2);
        unmask_inplace(*src, *src + n * 4, socketData->mask);
        for (int i = 0, s = socketData->remainingBytes % 4; i < s; i++) {
            (*src)[n * 4 + i] ^= socketData->mask[i];
        }

        socketData->server->fragmentCallback(p, (const char *) *src, socketData->remainingBytes,
                                             socketData->opCode[(unsigned char) socketData->opStack], socketData->fin, 0, socketData->pmd && socketData->pmd->compressedFrame);

        if (uv_is_closing((uv_handle_t *) p) || socketData->state == CLOSING) {
            return 1;
        }

        if (socketData->fin) {
            socketData->opStack--;
        }

        (*src) += socketData->remainingBytes;
        length -= socketData->remainingBytes;

        socketData->state = READ_HEAD;
        return 0;
    }
};

}

#endif // PARSER_H
