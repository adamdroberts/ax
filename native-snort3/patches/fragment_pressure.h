// Bounded loss-of-state quarantine for the reviewed Snort engine repair.
// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_FRAGMENT_PRESSURE_H
#define AX_FRAGMENT_PRESSURE_H
#include <atomic>
#include <cstdint>
#include <limits>

namespace ax_fragment
{
inline std::atomic<uint64_t>& lost_state_deadline(bool ipv6)
{
    static std::atomic<uint64_t> v4{0};
    static std::atomic<uint64_t> v6{0};
    return ipv6 ? v6 : v4;
}

// Nonnegative int64 seconds plus uint32 retention cannot overflow uint64.
// Invalid local clock metadata produces a fail-closed sentinel.
inline uint64_t loss_deadline(int64_t last_seen, uint32_t retention)
{
    if (last_seen < 0)
        return std::numeric_limits<uint64_t>::max();
    return static_cast<uint64_t>(last_seen) + retention;
}

inline bool remember_state_loss(bool ipv6, int64_t last_seen, int64_t now, uint32_t retention)
{
    const uint64_t until = loss_deadline(last_seen, retention);
    if (now >= 0 && static_cast<uint64_t>(now) >= until)
        return false;
    auto& deadline = lost_state_deadline(ipv6);
    uint64_t previous = deadline.load(std::memory_order_relaxed);
    while (previous < until && !deadline.compare_exchange_weak(previous, until,
            std::memory_order_relaxed, std::memory_order_relaxed))
    { }
    return true;
}

inline bool state_loss_quarantine(bool ipv6, int64_t now)
{
    return now < 0 || static_cast<uint64_t>(now) <
        lost_state_deadline(ipv6).load(std::memory_order_relaxed);
}
}
#endif
