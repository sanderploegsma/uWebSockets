#ifndef PERMESSAGEDEFLATE_H
#define PERMESSAGEDEFLATE_H

#include <zlib.h>
#include <string>
#include <cstddef>

struct PerMessageDeflate {
    z_stream readStream, writeStream;
    bool compressedFrame;
    bool serverNoContextTakeover = false;
    bool clientNoContextTakeover = false;

    struct NegotiationOffer {
        enum tokens {
            PERMESSAGE_DEFLATE = 1838,
            SERVER_NO_CONTEXT_TAKEOVER = 2807,
            CLIENT_NO_CONTEXT_TAKEOVER = 2783,
            SERVER_MAX_WINDOW_BITS = 2372,
            CLIENT_MAX_WINDOW_BITS = 2348
        };

        int *lastInteger = nullptr;
        bool perMessageDeflate = false;
        bool serverNoContextTakeover = false;
        bool clientNoContextTakeover = false;
        int serverMaxWindowBits = 0;
        int clientMaxWindowBits = 0;

        NegotiationOffer(const char *in);
        int getToken(const char **in);
    };

    PerMessageDeflate(NegotiationOffer &offer, int options, std::string &response);
    ~PerMessageDeflate();
    void setInput(char *src, size_t srcLength);
    size_t inflate(char *dst, size_t dstLength);
};

#endif // PERMESSAGEDEFLATE_H
