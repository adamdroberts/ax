// SPDX-License-Identifier: GPL-2.0-only
#include "fragment_pressure.h"
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

static size_t assertions = 0;
static void check(bool value)
{
    ++assertions;
    if (!value)
        std::abort();
}
int main()
{
    using namespace ax_fragment;
    check(!state_loss_quarantine(false, 0));
    check(!state_loss_quarantine(true, 0));
    check(remember_state_loss(false, 100, 101, 121));
    check(state_loss_quarantine(false, 220));
    check(!state_loss_quarantine(false, 221));
    check(!state_loss_quarantine(true, 100));
    check(!remember_state_loss(false, 0, 121, 121));
    check(lost_state_deadline(false).load() == 221);
    check(remember_state_loss(false, 20, 21, 121));
    check(lost_state_deadline(false).load() == 221); // Cannot shorten a prior loss.
    check(state_loss_quarantine(false, -1));
    check(loss_deadline(-1, 1) == std::numeric_limits<uint64_t>::max());
    check(loss_deadline(std::numeric_limits<int64_t>::max(), 4294967295U) ==
        uint64_t(std::numeric_limits<int64_t>::max()) + 4294967295ULL);
    uint64_t seed = 0x7143feab;
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed; };
    for (unsigned i = 0; i < 100000; ++i)
    {
        const int64_t last = random() & 0x7fffffffffffffffULL;
        const uint32_t retention = random();
        const unsigned __int128 expected = static_cast<unsigned __int128>(last) + retention;
        check(loss_deadline(last, retention) == expected);
    }
    lost_state_deadline(false).store(0);
    lost_state_deadline(true).store(0);
    std::vector<std::thread> threads;
    for (unsigned thread = 0; thread < 8; ++thread)
        threads.emplace_back([thread]() {
            for (unsigned i = 0; i < 25000; ++i)
                remember_state_loss(thread & 1, thread * 25000 + i, 0, 121);
        });
    for (auto& thread : threads)
        thread.join();
    check(lost_state_deadline(false).load() == 6 * 25000 + 24999 + 121);
    check(lost_state_deadline(true).load() == 7 * 25000 + 24999 + 121);
    check(!state_loss_quarantine(false, lost_state_deadline(false).load()));
    check(!state_loss_quarantine(true, lost_state_deadline(true).load()));
    std::printf("{\"assertions\":%zu,\"random_deadlines\":100000,\"concurrent_publishers\":8,\"concurrent_updates\":200000}\n", assertions);
}
