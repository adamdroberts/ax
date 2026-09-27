// Bounded IPv4 copied-option consistency state for the reviewed Snort repair.
// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_IPV4_FRAGMENT_OPTIONS_H
#define AX_IPV4_FRAGMENT_OPTIONS_H

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ax_fragment
{
// POD: Snort initializes its containing FragTracker with memset.
struct CopiedOptions
{
    uint8_t bytes[40];
    uint8_t destination[4];
    uint8_t length;
    bool seen;
    bool rejected;
};

// Inspect original IHL bytes, not a decoder-shortened option list. The caller
// supplies the validated ultimate destination, or nullptr for an invalid route.
// NOP/EOL padding and non-copied offset-zero options do not form part of the key.
// Unknown data and source-route records can be mutable; compare their type and
// length only. Router Alert's value is preserved. This is a bounded strict
// reassembly policy, not authentication or a definition of unknown options.
inline bool observe(CopiedOptions& state, const uint8_t* options, size_t length,
    bool continuation, const uint8_t* destination)
{
    if (state.rejected)
        return false;
    uint8_t key[40] = {};
    size_t used = 0;
    bool valid = length <= sizeof(key) && (!length || options) && destination;
    for (size_t pos = 0; valid && pos < length; )
    {
        const uint8_t kind = options[pos];
        if (!kind)
        {
            // RFC 791 header padding is zero, including after EOL.
            for (; pos < length; ++pos)
                valid = valid && options[pos] == 0;
            break;
        }
        if (kind == 1)
        {
            ++pos;
            continue;
        }
        if (length - pos < 2 || options[pos + 1] < 2 ||
            options[pos + 1] > length - pos)
        {
            valid = false;
            break;
        }
        const size_t size = options[pos + 1];
        if (kind & 0x80)
        {
            key[used] = kind;
            key[used + 1] = static_cast<uint8_t>(size);
            if (kind == 148) // RFC 2113 Router Alert
            {
                if (size != 4)
                {
                    valid = false;
                    break;
                }
                key[used + 2] = options[pos + 2];
                key[used + 3] = options[pos + 3];
            }
            used += size; // Sum of disjoint option lengths cannot exceed 40.
        }
        else if (continuation)
        {
            valid = false;
            break;
        }
        pos += size;
    }
    if (valid && state.seen)
        valid = state.length == used && !std::memcmp(state.bytes, key, used) &&
            !std::memcmp(state.destination, destination, 4);
    if (!valid)
    {
        state.rejected = true;
        return false;
    }
    if (!state.seen)
    {
        std::memcpy(state.bytes, key, used);
        std::memcpy(state.destination, destination, 4);
        state.length = static_cast<uint8_t>(used);
        state.seen = true; // An empty option list is a real observation.
    }
    return true;
}
}
#endif
