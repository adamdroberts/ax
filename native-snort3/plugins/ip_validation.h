#ifndef AX_IP_VALIDATION_H
#define AX_IP_VALIDATION_H

#include <cstddef>
#include <cstdint>

namespace ax_ip
{
// The caller supplies exactly one decoded AH layer, excluding its payload.
// RFC 4302 sections 2 and 2.2 require all three fixed 32-bit fields and,
// for IPv6, a total AH length divisible by eight. This checks framing only;
// the selected SA, integrity algorithm, ICV and replay window are not known.
inline bool invalid_ah_header(const std::uint8_t* header, std::size_t size, bool ipv6)
{
    if (!header || size < 12)
        return true;
    const std::size_t declared = (static_cast<std::size_t>(header[1]) + 2) * 4;
    return size != declared || (ipv6 && size % 8 != 0);
}

enum class FirstFragmentError
{
    none,
    truncated,
    malformed,
    // These three outcomes are conservative local inspection policies, not
    // assertions that every such packet is forbidden by an RFC.
    unsupported_protocol,
    nested_fragment,
    extension_limit,
};

// RFC 7112 / RFC 8200 require the first fragment to contain the complete IPv6
// header chain. The supplied span begins immediately AFTER the offset-zero
// Fragment header and ends at the decoded IPv6 packet boundary. No reassembly,
// security-association processing or payload interpretation happens here.
inline FirstFragmentError first_fragment_error(std::uint8_t next_header,
    const std::uint8_t* data, std::size_t size)
{
    if (!data && size)
        return FirstFragmentError::malformed;
    std::size_t offset = 0;
    unsigned extensions = 0;
    while (true)
    {
        const std::size_t remaining = size - offset;
        switch (next_header)
        {
        case 0: // Hop-by-Hop cannot follow a Fragment header.
            return FirstFragmentError::malformed;
        case 44:
            return FirstFragmentError::nested_fragment;
        case 43: // Routing and Destination Options use eight-octet units.
        case 60:
        case 51: // AH uses four-octet units and a different length bias.
        {
            if (extensions++ == 8)
                return FirstFragmentError::extension_limit;
            if (remaining < 2)
                return FirstFragmentError::truncated;
            const std::size_t length = next_header == 51 ?
                (static_cast<std::size_t>(data[offset + 1]) + 2) * 4 :
                (static_cast<std::size_t>(data[offset + 1]) + 1) * 8;
            if (length > remaining)
                return FirstFragmentError::truncated;
            if (next_header == 51 && invalid_ah_header(data + offset, length, true))
                return FirstFragmentError::malformed;
            next_header = data[offset];
            offset += length;
            break;
        }
        case 6: // TCP's data offset includes any TCP options.
        {
            if (remaining < 20)
                return FirstFragmentError::truncated;
            const std::size_t length = (data[offset + 12] >> 4) * 4;
            if (length < 20)
                return FirstFragmentError::malformed;
            return length > remaining ? FirstFragmentError::truncated : FirstFragmentError::none;
        }
        case 17: // UDP's fixed header.
        case 50: // ESP SPI and sequence number; encrypted contents stay opaque.
            return remaining < 8 ? FirstFragmentError::truncated : FirstFragmentError::none;
        case 58: // The four common ICMPv6 header octets; type-specific data follows.
            return remaining < 4 ? FirstFragmentError::truncated : FirstFragmentError::none;
        case 4: // Encapsulated IPv4: include its complete IHL, including options.
        {
            if (remaining < 20)
                return FirstFragmentError::truncated;
            const std::size_t length = (data[offset] & 0x0f) * 4;
            if ((data[offset] >> 4) != 4 || length < 20)
                return FirstFragmentError::malformed;
            return length > remaining ? FirstFragmentError::truncated : FirstFragmentError::none;
        }
        case 41: // The encapsulated IPv6 base header; no tunnel admission here.
            if (remaining < 40)
                return FirstFragmentError::truncated;
            return (data[offset] >> 4) != 6 ? FirstFragmentError::malformed : FirstFragmentError::none;
        case 59: // No Next Header imposes no additional header requirement.
            return FirstFragmentError::none;
        default:
            return FirstFragmentError::unsupported_protocol;
        }
    }
}

inline bool invalid_first_fragment(std::uint8_t next_header,
    const std::uint8_t* data, std::size_t size)
{
    return first_fragment_error(next_header, data, size) != FirstFragmentError::none;
}
}

#endif
