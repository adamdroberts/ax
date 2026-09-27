// Local Snort 3.12.2.0 decoder repair. SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_IPV4_CHECKSUM_DESTINATION_H
#define AX_IPV4_CHECKSUM_DESTINATION_H

#include <cstddef>
#include <cstdint>

namespace ax_checksum
{
// Read only the original IPv4 options span, never transport payload. The route
// slots contain four-byte addresses. An active pointer selects a remaining
// slot; its final slot is the ultimate destination. When the pointer exceeds
// the option length, the route is complete and the base destination applies.
// RFC 791 section 3.1; RFC 1122 section 3.2.1.8(c); RFC 9293 section 3.9.2.1.
// False means malformed/ambiguous framing, not an absent route. The caller
// must not silently use the base address after that result.
inline bool ipv4_route_destination(const std::uint8_t* options, std::size_t size,
    const std::uint8_t*& final)
{
    final = nullptr;
    if (size > 40 || size % 4 || (!options && size))
        return false;
    bool route_seen = false;
    std::size_t offset = 0;
    while (offset < size)
    {
        const auto type = options[offset];
        if (type == 0) // EOL; original padding validation is a separate rule.
            return true;
        if (type == 1)
        {
            ++offset;
            continue;
        }
        if (size - offset < 2)
            return false;
        const std::size_t length = options[offset + 1];
        if (length < 2 || length > size - offset)
            return false;
        if (type == 131 || type == 137) // LSRR or SSRR, never both.
        {
            if (route_seen || length < 3 || (length - 3) % 4)
                return false;
            route_seen = true;
            const auto pointer = options[offset + 2];
            if (pointer < 4)
                return false;
            if (pointer <= length)
            {
                if ((pointer - 4) % 4 || length - pointer + 1 < 4)
                    return false;
                final = options + offset + length - 4;
            }
        }
        offset += length;
    }
    return true;
}

// Snort's selected IPv4 header and current transport layer must belong to the
// SAME packet buffer. Decode and encode_update supply that invariant. These
// checks bound the original IHL span; they do not establish buffer ownership.
// Intervening headers (e.g. AH) are not searched for route-like bytes.
// nullptr means invalid; a valid result always points at four address bytes.
inline const std::uint8_t* ipv4_destination(const std::uint8_t* ip4,
    const std::uint8_t* upper)
{
    if (!ip4 || !upper)
        return nullptr;
    const auto begin = reinterpret_cast<std::uintptr_t>(ip4);
    const auto end = reinterpret_cast<std::uintptr_t>(upper);
    if (end < begin || end - begin < 20 || end - begin > 65535)
        return nullptr;
    const auto length = static_cast<std::size_t>(ip4[0] & 15) * 4;
    const auto declared = (static_cast<unsigned>(ip4[2]) << 8) | ip4[3];
    if ((ip4[0] >> 4) != 4 || length < 20 || length > end - begin || declared < end - begin)
        return nullptr;
    const std::uint8_t* final;
    if (!ipv4_route_destination(ip4 + 20, length - 20, final))
        return nullptr;
    return final ? final : ip4 + 16;
}
}
#endif
