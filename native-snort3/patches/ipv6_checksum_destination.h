// Local Snort 3.12.2.0 decoder repair. SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_IPV6_CHECKSUM_DESTINATION_H
#define AX_IPV6_CHECKSUM_DESTINATION_H

#include <cstddef>
#include <cstdint>

namespace ax_checksum
{
// The span ends exactly where the current upper-layer decoder starts. Never
// search transport data for extension-like bytes. This is address selection,
// not a substitute for structural rules, endpoint bindings, or IPsec checks.
// Eight extensions is the accompanying profile's explicit resource bound.
inline const std::uint8_t* type2_destination(std::uint8_t next,
    const std::uint8_t* prefix, std::size_t size, std::uint8_t upper_protocol)
{
    if (!prefix && size)
        return nullptr;
    std::size_t offset = 0;
    const std::uint8_t* destination = nullptr;
    unsigned extensions = 0;
    while (offset < size)
    {
        if (extensions++ == 8 || size - offset < 8)
            return nullptr;
        const auto* header = prefix + offset;
        std::size_t length;
        switch (next)
        {
        case 0: // Hop-by-Hop.
        case 60: // Destination Options; Home Address source handling is separate.
        case 43: // Routing.
            length = (static_cast<std::size_t>(header[1]) + 1) * 8;
            break;
        case 51: // Authentication Header, IPv6 8-octet alignment.
            length = (static_cast<std::size_t>(header[1]) + 2) * 4;
            if (length < 16 || length % 8)
                return nullptr;
            break;
        case 44: // A real fragment cannot yet have a complete checksum.
            length = 8;
            if (header[2] || (header[3] & 0xf9))
                return nullptr;
            break;
        default: // Includes ESP, another IP layer, and unknown extensions.
            return nullptr;
        }
        if (length > size - offset)
            return nullptr;
        if (next == 43)
        {
            if (header[2] == 2)
            {
                // RFC 6275 sections 6.4.1/11.3.3: one on-wire segment.
                // Zero is an internal post-processing representation; ignore
                // it here. Original-wire structural rejection is separate.
                if (length != 24 || header[3] > 1)
                    return nullptr;
                if (header[3] == 1)
                    destination = header + 8;
            }
            else if (header[3])
            {
                // An active later route has type-specific semantics. A later
                // valid Type 2 may again supply the final nested destination.
                destination = nullptr;
            }
        }
        next = header[0];
        offset += length;
    }
    return next == upper_protocol ? destination : nullptr;
}

// Call only with Snort's selected IPv6 header and current decoded/updated
// layer in the SAME packet buffer. Decode and PacketManager::encode_update
// provide this invariant; callers must not pass the separate response buffer.
// Integer comparisons avoid subtraction of unrelated pointers on a failed
// invariant, but cannot themselves establish allocation ownership.
inline const std::uint8_t* destination(const std::uint8_t* ip6,
    const std::uint8_t* upper, std::uint8_t upper_protocol)
{
    if (!ip6 || !upper)
        return nullptr;
    const auto base = reinterpret_cast<std::uintptr_t>(ip6);
    const auto end = reinterpret_cast<std::uintptr_t>(upper);
    if (end < base || end - base < 40 || end - base > 40 + 65535)
        return nullptr;
    const auto size = static_cast<std::size_t>(end - base - 40);
    // The existing payload length can be stale during a resize. It must still
    // contain the extension prefix, but need not equal the new transport size.
    const auto declared = (static_cast<unsigned>(ip6[4]) << 8) | ip6[5];
    if ((ip6[0] >> 4) != 6 || size > declared)
        return nullptr;
    return type2_destination(ip6[6], ip6 + 40, size, upper_protocol);
}
}
#endif
