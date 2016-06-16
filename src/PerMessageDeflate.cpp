#include "PerMessageDeflate.h"
using namespace std;

int PerMessageDeflate::NegotiationOffer::getToken(const char **in)
{
    while (!isalnum(**in) && **in != '\0') {
        (*in)++;
    }

    int hashedToken = 0;
    while (isalnum(**in) || **in == '-' || **in == '_') {
        if (isdigit(**in)) {
            hashedToken = hashedToken * 10 - (**in - '0');
        } else {
            hashedToken += **in;
        }
        (*in)++;
    }
    return hashedToken;
}

PerMessageDeflate::NegotiationOffer::NegotiationOffer(const char *in)
{
    int token = 1;
    for (; token && token != PERMESSAGE_DEFLATE; token = getToken(&in));

    perMessageDeflate = (token == PERMESSAGE_DEFLATE);
    while ((token = getToken(&in))) {
        switch (token) {
        case PERMESSAGE_DEFLATE:
            return;
        case SERVER_NO_CONTEXT_TAKEOVER:
            serverNoContextTakeover = true;
            break;
        case CLIENT_NO_CONTEXT_TAKEOVER:
            clientNoContextTakeover = true;
            break;
        case SERVER_MAX_WINDOW_BITS:
            serverMaxWindowBits = 1;
            lastInteger = &serverMaxWindowBits;
            break;
        case CLIENT_MAX_WINDOW_BITS:
            clientMaxWindowBits = 1;
            lastInteger = &clientMaxWindowBits;
            break;
        default:
            if (token < 0 && lastInteger) {
                *lastInteger = -token;
            } else {
                // cout << "UNKNOWN TOKEN: " << token << endl;
            }
            break;
        }
    }
}

PerMessageDeflate::PerMessageDeflate(NegotiationOffer &offer, int options, string &response) : readStream({}), writeStream({})
{
    response = "Sec-WebSocket-Extensions: permessage-deflate";
    if ((options & NegotiationOffer::SERVER_NO_CONTEXT_TAKEOVER) || offer.serverNoContextTakeover) {
        response += "; server_no_context_takeover";
        serverNoContextTakeover = true;
    }
    if ((options & NegotiationOffer::CLIENT_NO_CONTEXT_TAKEOVER) || offer.clientNoContextTakeover) {
        response += "; client_no_context_takeover";
        clientNoContextTakeover = true;
    }

    inflateInit2(&readStream, -15);
}

PerMessageDeflate::~PerMessageDeflate()
{
    inflateEnd(&readStream);
}

void PerMessageDeflate::setInput(char *src, size_t srcLength) {
    readStream.next_in = (unsigned char *) src;
    readStream.avail_in = srcLength;
}

size_t PerMessageDeflate::inflate(char *dst, size_t dstLength) {
    if (!readStream.avail_in) {
        return dstLength;
    }
    readStream.next_out = (unsigned char *) dst;
    readStream.avail_out = dstLength;
    int err = ::inflate(&readStream, Z_NO_FLUSH);
    if (err != Z_STREAM_END && err != Z_OK) {
        throw err;
    }
    return readStream.avail_out;
}
