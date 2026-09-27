// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_IPV6_FRAGMENT_PREFIX_H
#define AX_IPV6_FRAGMENT_PREFIX_H
#include <cstddef>
#include <cstdint>

namespace ax_fragment
{
struct Ip6Prefix
{
    bool valid = false;
    std::size_t length = 0;       // Base IPv6 header plus headers before Fragment.
    std::size_t next_offset = 0;  // Byte that currently names Fragment.
    std::uint16_t fragment_offset = 0;
    std::uint8_t next = 0;        // Offset-zero Fragment header's Next Header.
    std::uint8_t ecn = 0;
    unsigned extensions = 0;
};

// Capture-bounded walk of the selected IPv6 layer, never of fragment payload.
// Header semantics and endpoint processing remain separate responsibilities.
inline Ip6Prefix ip6_prefix(const std::uint8_t* ip, std::size_t size,
    unsigned max_extensions = 255)
{
    Ip6Prefix result;
    if (!ip || size < 40 || ip[0] >> 4 != 6)
        return result;
    const std::size_t declared = (static_cast<unsigned>(ip[4]) << 8) | ip[5];
    if (!declared || declared > size - 40)
        return result; // Fragmented jumbograms are not permitted.
    const auto end = 40 + declared;
    std::size_t offset = 40, next_offset = 6;
    auto next = ip[6];
    for (unsigned extensions = 0; extensions < max_extensions; ++extensions)
    {
        if (end - offset < 8)
            return result;
        if (next == 44)
        {
            result.valid = true;
            result.length = offset;
            result.next_offset = next_offset;
            result.next = ip[offset];
            result.fragment_offset = ((static_cast<unsigned>(ip[offset + 2]) << 8) |
                ip[offset + 3]) & 0xfff8;
            result.ecn = (ip[1] >> 4) & 3;
            result.extensions = extensions + 1;
            return result;
        }
        if (next != 0 && next != 43 && next != 60 && next != 51)
            return result;
        const std::size_t length = next == 51 ?
            (static_cast<std::size_t>(ip[offset + 1]) + 2) * 4 :
            (static_cast<std::size_t>(ip[offset + 1]) + 1) * 8;
        if (length > end - offset || (next == 51 && (length < 16 || length % 8)))
            return result;
        next = ip[offset];
        next_offset = offset;
        offset += length;
    }
    return result;
}

// Subtraction-based bounds also handle adversarial size_t metadata safely.
inline bool ip6_rebuilt_fits(std::size_t prefix, std::size_t payload,
    std::size_t outer, std::size_t capacity)
{
    return prefix >= 40 && prefix - 40 <= 65535 && payload <= 65535 - (prefix - 40) &&
        outer <= capacity && prefix <= capacity - outer && payload <= capacity - outer - prefix;
}

// RFC 3168 section 5.3: preserve CE, but never combine CE with Not-ECT.
// For the unspecified mixtures without CE, retain offset-zero's codepoint.
inline std::uint8_t ip6_rebuilt_ecn(std::uint8_t seen, std::uint8_t first)
{
    if (!seen || seen > 15 || first > 3 || !(seen & (1u << first)) || (seen & 9) == 9)
        return 0xff;
    return seen & 8 ? 3 : first;
}
}
#endif
