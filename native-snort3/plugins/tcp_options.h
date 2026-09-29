#ifndef AX_TCP_OPTIONS_H
#define AX_TCP_OPTIONS_H

#include <cstddef>
#include <cstdint>

namespace ax_tcp
{
// RFC 9293: a bounded TLV list followed by zero padding. RFC 2018 SACK
// blocks occupy eight bytes each; SACK-Permitted, like MSS, is SYN-only.
// Unknown well-framed options remain opaque. Negotiation, authentication,
// SACK sequence windows and other endpoint state require separate checks.
inline bool invalid_options(const std::uint8_t* bytes, std::size_t size, bool syn)
{
    if (size > 40 || size % 4 || (!bytes && size))
        return true;
    std::size_t position = 0;
    while (position < size)
    {
        const auto kind = bytes[position];
        if (kind == 0)
        {
            for (++position; position < size; ++position)
                if (bytes[position] != 0)
                    return true;
            return false;
        }
        if (kind == 1)
        {
            ++position;
            continue;
        }
        if (size - position < 2)
            return true;
        const auto length = bytes[position + 1];
        if (length < 2 || length > size - position)
            return true;
        if ((kind == 2 && (length != 4 || !syn)) ||
            (kind == 3 && length != 3) ||
            (kind == 4 && (length != 2 || !syn)) ||
            (kind == 5 && (length < 10 || (length - 2) % 8)) ||
            (kind == 8 && length != 10))
            return true;
        position += length;
    }
    return false;
}
}
#endif
