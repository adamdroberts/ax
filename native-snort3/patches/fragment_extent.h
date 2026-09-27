// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_FRAGMENT_EXTENT_H
#define AX_FRAGMENT_EXTENT_H

#include <cstdint>

namespace ax_fragment
{
// Trivial storage: the native tracker is initialized and released with memset.
struct Extent
{
    uint32_t more_end;
    uint32_t final_end;
    bool final_seen;
};

// A final fragment fixes the length. Every non-final fragment must end before
// that length. Reject contradictory declarations without mutating saved state.
// Offset alignment and version-specific header/size checks are separate gates.
inline bool observe_extent(Extent& state, uint16_t offset, uint16_t length, bool more)
{
    const uint32_t end = static_cast<uint32_t>(offset) + length;
    if (!length || end > 65535 ||
        (state.final_seen && (more ? end >= state.final_end : end != state.final_end)) ||
        (!more && state.more_end >= end))
        return false;
    if (more)
    {
        if (end > state.more_end)
            state.more_end = end;
    }
    else
    {
        state.final_end = end;
        state.final_seen = true;
    }
    return true;
}

// Byte totals cannot establish coverage: bytes beyond the final boundary can
// compensate for a hole. Require the ordered native list to cover every byte
// exactly once. A cycle or zero-length node cannot make this scan unbounded.
template <typename Fragment>
inline bool complete_ranges(const Fragment* fragment, uint32_t end)
{
    if (!fragment || !end || end > 65535)
        return false;
    uint32_t position = 0;
    for (; fragment; fragment = fragment->next)
    {
        const uint32_t size = fragment->size;
        if (fragment->offset != position || !size || size > end - position)
            return false;
        position += size;
    }
    return position == end;
}
}
#endif
