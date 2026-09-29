#ifndef AX_TCP_SACK_STATE_H
#define AX_TCP_SACK_STATE_H

#include "tcp_options.h"

namespace ax_tcp
{
struct SackOptions
{
    bool malformed = false;
    bool permitted = false;
    bool sack = false;
};

inline SackOptions sack_options(const std::uint8_t* bytes, std::size_t size, bool syn)
{
    if (invalid_options(bytes, size, syn))
        return {true, false, false};
    SackOptions result;
    for (std::size_t offset = 0; offset < size && bytes[offset] != 0;)
    {
        const auto kind = bytes[offset];
        result.permitted |= kind == 4;
        result.sack |= kind == 5;
        offset += kind == 1 ? 1 : bytes[offset + 1];
    }
    return result;
}

class SackNegotiation
{
public:
    void observe(unsigned side, std::uint32_t sequence, bool permitted, bool forwarded)
    {
        if (!forwarded || side > 1)
            return;
        auto& offer = offers[side];
        if (!offer.seen)
            offer = {true, permitted, sequence};
        else
            // Conflicting retransmissions cannot expand permissions. This
            // conservative ambiguity policy is separate from wire grammar.
            offer.permitted &= offer.sequence == sequence && permitted;
    }

    bool permits(unsigned sender) const
    {
        return sender < 2 && offers[sender].seen && offers[1 - sender].seen &&
            offers[1 - sender].permitted;
    }

private:
    struct Offer
    {
        bool seen = false;
        bool permitted = false;
        std::uint32_t sequence = 0;
    };
    Offer offers[2];
};
}
#endif
