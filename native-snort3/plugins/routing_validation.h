#ifndef AX_ROUTING_VALIDATION_H
#define AX_ROUTING_VALIDATION_H

#include "ip_validation.h"

#include <cstddef>
#include <cstdint>

namespace ax_ip
{
// This is a necessary-address check, not a complete routing or assignment
// test. RFC 6275 sections 3.1, 4.6, 6.4, and 11.3.3 require a routable unicast
// home address. Reject the statelessly identifiable multicast, unspecified,
// loopback and link-local cases, while retaining ULA/global addresses.
// Ownership, actual routability and comparison with the care-of address scope
// need independent endpoint state; no prefix allowlist is inferred here.
inline bool invalid_type2_home_address(const std::uint8_t* address)
{
    if (!address || address[0] == 0xff ||
        (address[0] == 0xfe && (address[1] & 0xc0) == 0x80))
        return true;
    bool first_fifteen_zero = true;
    for (unsigned i = 0; i < 15; ++i)
        first_fifteen_zero = first_fifteen_zero && address[i] == 0;
    return first_fifteen_zero && address[15] <= 1;
}

// One exact Routing extension as it appeared on the wire. RFC 6275 sections
// 6.4.1 and 11.3.3 fix Type 2 to 24 octets with Segments Left equal to one.
// Zero can occur AFTER local mobile-node processing, so this helper must not
// be applied to that transformed representation. Reserved octets are ignored.
// Other routing types retain their own endpoint-specific interpretation.
inline bool invalid_type2_header(const std::uint8_t* header, std::size_t size)
{
    if (!header || size < 8 ||
        size != (static_cast<std::size_t>(header[1]) + 1) * 8)
        return true;
    if (header[2] != 2)
        return false;
    return size != 24 || header[1] != 2 || header[3] != 1 ||
        invalid_type2_home_address(header + 8);
}

// The caller supplies the selected IPv6 packet's captured, declared-length-
// bounded original payload. Follow only known extension framing, at most eight
// extensions (the native profile's explicit resource policy). This reaches
// Type 2 headers after an offset-zero Fragment header before reassembly removes
// that header; a noninitial fragment is continuation data and stops the walk.
//
// Repeated valid Type 2 headers are preserved, as are other Routing Types,
// including an unknown type with Segments Left zero. This does not assert that
// an unknown nonzero-segment route is supported by the eventual endpoint.
inline bool invalid_type2_chain(std::uint8_t next_header,
    const std::uint8_t* payload, std::size_t size)
{
    if (!payload && size)
        return true;
    std::size_t offset = 0;
    unsigned extensions = 0;
    while (true)
    {
        const std::size_t remaining = size - offset;
        switch (next_header)
        {
        case 0: // Hop-by-Hop.
        case 60: // Destination Options.
        case 43: // Routing.
        case 51: // Authentication Header.
        {
            if (extensions++ == 8 || remaining < 2)
                return true;
            const std::size_t length = next_header == 51 ?
                (static_cast<std::size_t>(payload[offset + 1]) + 2) * 4 :
                (static_cast<std::size_t>(payload[offset + 1]) + 1) * 8;
            if (length > remaining)
                return true;
            if (next_header == 51 && invalid_ah_header(payload + offset, length, true))
                return true;
            if (next_header == 43 && invalid_type2_header(payload + offset, length))
                return true;
            next_header = payload[offset];
            offset += length;
            break;
        }
        case 44: // Fragment.
        {
            if (extensions++ == 8 || remaining < 8)
                return true;
            const auto field = (static_cast<unsigned>(payload[offset + 2]) << 8)
                | payload[offset + 3];
            next_header = payload[offset];
            offset += 8;
            if ((field & 0xfff8) != 0)
                return false;
            break;
        }
        default:
            return false;
        }
    }
}
}

#endif
