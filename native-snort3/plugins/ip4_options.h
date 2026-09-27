#ifndef AX_IP4_OPTIONS_H
#define AX_IP4_OPTIONS_H

#include <cstddef>
#include <cstdint>

namespace ax_ip4
{
// The caller supplies exactly the original IPv4 options and padding span,
// excluding the fixed header and payload: 0..40 bytes in four-byte units.
// RFC 791 section 3.1 defines option framing, minimum pointers, single RR/TS
// instances and zero padding. RFC 1122 section 3.2.1.8(c) forbids sending more
// than one source-route option, including a mixed LSRR/SSRR pair. RFC 2113
// section 2.1 fixes Router Alert at four bytes; unknown values remain opaque.
// Enforcing sender formats at this IPS is a strict local policy where an
// endpoint is permitted not to process the option. No routing, address,
// timestamp, Security-option or obsolete Stream Identifier semantics are
// inferred; well-framed unknown options remain accepted (RFC 1122 3.2.1.8).
inline bool invalid_options(const std::uint8_t* options, std::size_t size)
{
    if (size > 40 || size % 4 != 0 || (!options && size))
        return true;
    bool record_route = false;
    bool source_route = false;
    bool timestamp = false;
    std::size_t offset = 0;
    while (offset < size)
    {
        const auto type = options[offset];
        if (type == 0) // End of Option List: the rest is zero padding.
        {
            while (++offset < size)
                if (options[offset] != 0)
                    return true;
            return false;
        }
        if (type == 1) // NOP is a single byte, with no length field.
        {
            ++offset;
            continue;
        }
        const auto remaining = size - offset;
        if (remaining < 2)
            return true;
        const std::size_t length = options[offset + 1];
        if (length < 2 || length > remaining)
            return true;
        switch (type)
        {
        case 7:   // Record Route
        case 131: // Loose Source and Record Route
        case 137: // Strict Source and Record Route
            if (length < 3 || options[offset + 2] < 4)
                return true;
            if (type == 7)
            {
                if (record_route)
                    return true;
                record_route = true;
            }
            else
            {
                if (source_route)
                    return true;
                source_route = true;
            }
            break;
        case 68: // Internet Timestamp
            if (length < 4 || options[offset + 2] < 5 || timestamp)
                return true;
            timestamp = true;
            break;
        case 148: // Router Alert: value fields are intentionally unrestricted.
            if (length != 4)
                return true;
            break;
        default:
            break;
        }
        // A pointer beyond its option's length denotes a full/completed
        // RR, source route or timestamp area, not a malformed pointer.
        offset += length;
    }
    return false;
}
}

#endif
