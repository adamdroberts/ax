#ifndef AX_ESP_VALIDATION_H
#define AX_ESP_VALIDATION_H

#include "ip_validation.h"

#include <cstddef>
#include <cstdint>

namespace ax_esp
{
// Inspect only visible ESP framing in one selected IP payload. RFC 4303
// sections 2/2.1 require the eight-byte SPI/sequence header and prohibit SPI
// zero. A complete ESP packet also needs its mandatory Pad Length and Next
// Header octets (sections 2.5/2.6). Their encrypted values, the ICV and the SA
// are deliberately not interpreted here. RFC 7112's first-fragment header
// chain ends at the ESP fixed header, so a first nonfinal fragment needs only
// those eight bytes. IPv4 does not impose that header-chain requirement: an
// incomplete initial AH/ESP header waits for reassembly (RFC 4302 section
// 3.3.4). A visible zero SPI is invalid even when its sequence bytes arrive
// later. Noninitial fragments cannot be parsed as fresh headers.
//
// Payload bounds exclude link padding and the selected IP header. The IPv4
// offset argument is zero for the first fragment, nonzero for any later one;
// its units do not matter. IPv6 fragmentation comes from the on-wire header.
// Unknown upper protocols stop this ESP-specific check. A malformed known
// extension chain fails closed. The eight-extension bound is local policy.
inline bool invalid_visible_framing(std::uint8_t next_header,
    const std::uint8_t* payload, std::size_t size, bool ipv6,
    std::uint16_t ipv4_fragment_offset = 0, bool ipv4_more_fragments = false)
{
    if (!ipv6 && ipv4_fragment_offset)
        return false;
    if (!payload && size)
        return true;
    bool first_nonfinal = !ipv6 && ipv4_more_fragments;
    std::size_t offset = 0;
    unsigned extensions = 0;
    while (true)
    {
        const std::size_t remaining = size - offset;
        if (next_header == 50)
        {
            if (remaining >= 4 && payload[offset] == 0 && payload[offset + 1] == 0 &&
                payload[offset + 2] == 0 && payload[offset + 3] == 0)
                return true;
            if (!ipv6 && first_nonfinal && remaining < 8)
                return false;
            if (remaining < (first_nonfinal ? 8u : 10u))
                return true;
            return false;
        }
        const bool options = ipv6 &&
            (next_header == 0 || next_header == 43 || next_header == 60);
        const bool fragment = ipv6 && next_header == 44;
        if (!options && !fragment && next_header != 51)
            return false;
        if (extensions++ == 8)
            return true;
        if (fragment)
        {
            if (remaining < 8)
                return true;
            if (payload[offset + 2] != 0 || (payload[offset + 3] & 0xf8) != 0)
                return false;
            first_nonfinal = first_nonfinal || (payload[offset + 3] & 1) != 0;
            next_header = payload[offset];
            offset += 8;
            continue;
        }
        if (remaining < 2)
            return ipv6 || !first_nonfinal;
        const std::size_t length = options ?
            (static_cast<std::size_t>(payload[offset + 1]) + 1) * 8 :
            (static_cast<std::size_t>(payload[offset + 1]) + 2) * 4;
        if (length > remaining)
            // Only IPv4's initial nonfinal fragment may defer an incomplete
            // AH. A declared AH shorter than its mandatory fields is already
            // invalid, regardless of how many of those bytes have arrived.
            return ipv6 || !first_nonfinal || length < 12;
        if (!options && ax_ip::invalid_ah_header(payload + offset, length, ipv6))
            return true;
        next_header = payload[offset];
        offset += length;
    }
}
}

#endif
