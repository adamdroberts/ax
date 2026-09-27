// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_IPV4_FRAGMENT_PREFIX_H
#define AX_IPV4_FRAGMENT_PREFIX_H

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ax_fragment
{
// Trivial state: the native FragTracker is cleared with memset. Options remain
// owned by its existing offset-zero option buffer, validated independently.
struct Ip4Prefix
{
    uint8_t first[20];
    uint32_t largest_end;
    uint8_t ecn_seen;
    bool first_seen;
};

enum class Ip4PrefixResult : uint8_t { okay, invalid_header_or_size, conflicting_ecn };

inline bool ip4_rebuilt_fits(size_t header, size_t payload, size_t outer, size_t capacity)
{
    return header >= 20 && header <= 60 && !(header % 4) &&
        payload <= 65535 - header && outer <= capacity &&
        header <= capacity - outer && payload <= capacity - outer - header;
}

inline Ip4PrefixResult observe_ip4_prefix(Ip4Prefix& state, const uint8_t* ip,
    size_t captured, uint16_t fragment_offset, size_t payload)
{
    if (!ip || captured < 20 || (ip[0] >> 4) != 4)
        return Ip4PrefixResult::invalid_header_or_size;
    const size_t header = (ip[0] & 15) * 4;
    const size_t total = (static_cast<unsigned>(ip[2]) << 8) | ip[3];
    const unsigned flags_offset = (static_cast<unsigned>(ip[6]) << 8) | ip[7];
    if (header < 20 || header > captured || total > captured || total <= header ||
        total - header != payload || ((flags_offset & 8191) * 8) != fragment_offset ||
        !(flags_offset & 0x3fff))
        return Ip4PrefixResult::invalid_header_or_size;
    // total bounds payload before addition, so this cannot wrap even on 32-bit.
    const uint32_t end = fragment_offset + static_cast<uint32_t>(payload);
    const uint32_t largest = end > state.largest_end ? end : state.largest_end;
    const size_t first_header = state.first_seen ? (state.first[0] & 15) * 4 :
        fragment_offset ? 20 : header;
    if (!ip4_rebuilt_fits(first_header, largest, 0, 65535))
        return Ip4PrefixResult::invalid_header_or_size;
    const uint8_t codes = state.ecn_seen | (1u << (ip[1] & 3));
    if ((codes & 9) == 9)
        return Ip4PrefixResult::conflicting_ecn;
    state.largest_end = largest;
    state.ecn_seen = codes;
    if (!fragment_offset && !state.first_seen)
    {
        std::memcpy(state.first, ip, sizeof(state.first));
        state.first_seen = true;
    }
    return Ip4PrefixResult::okay;
}
}
#endif
