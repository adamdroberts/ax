// SPDX-License-Identifier: GPL-2.0-only
#include "fragment_lifetime.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

static size_t assertions = 0;
static void check(bool value)
{
    ++assertions;
    if (!value)
    {
        std::fprintf(stderr, "assertion %zu failed\n", assertions);
        std::abort();
    }
}
static bool oracle(int64_t ns, int64_t nu, int64_t fs, int64_t fu, uint32_t budget)
{
    if (ns < 0 || fs < 0 || nu < 0 || nu >= 1000000 || fu < 0 || fu >= 1000000)
        return true;
    const __int128 delta = (__int128(ns) * 1000000 + nu) - (__int128(fs) * 1000000 + fu);
    return delta < 0 || delta >= __int128(budget) * 1000000;
}
int main()
{
    for (uint32_t budget : {0U, 1U, 30U, 60U, 120U, 2147483647U, 4294967295U})
    {
        check(ax_fragment::reassembly_seconds(false, budget) == budget);
        check(ax_fragment::reassembly_seconds(true, budget) == (budget < 60 ? budget : 60));
        for (bool ipv6 : {false, true})
        {
            uint64_t expected = budget;
            if (expected < (ipv6 ? 60U : 120U))
                expected = ipv6 ? 60 : 120;
            if (expected < 4294967295ULL)
                ++expected;
            check(ax_fragment::retention_seconds(ipv6, budget) == expected);
        }
        for (int64_t fs : {int64_t(0), int64_t(1700000000), int64_t(4294967295),
                          std::numeric_limits<int64_t>::max() - 4294967296LL})
        {
            for (int64_t fu : {0, 1, 250000, 999999})
            {
                for (int64_t delta : {int64_t(-1), int64_t(0), int64_t(1),
                                      int64_t(budget) * 1000000 - 1, int64_t(budget) * 1000000,
                                      int64_t(budget) * 1000000 + 1})
                {
                    const __int128 now = __int128(fs) * 1000000 + fu + delta;
                    const int64_t ns = now / 1000000, nu = now % 1000000;
                    check(ax_fragment::lifetime_expired(ns, nu, fs, fu, budget) == oracle(ns, nu, fs, fu, budget));
                }
            }
        }
    }
    for (int64_t ns : {-1, 0, 1})
        for (int64_t nu : {-1, 0, 999999, 1000000})
            for (int64_t fs : {-1, 0, 1})
                for (int64_t fu : {-1, 0, 999999, 1000000})
                    check(ax_fragment::lifetime_expired(ns, nu, fs, fu, 60) == oracle(ns, nu, fs, fu, 60));
    uint64_t seed = 0x712efa51;
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed; };
    for (unsigned i = 0; i < 100000; ++i)
    {
        const int64_t fs = random() & 0x3fffffffffffffffULL;
        const int64_t ns = fs + int64_t(random() % 8589934592ULL) - 100;
        const int64_t fu = int64_t(random() % 1000002) - 1, nu = int64_t(random() % 1000002) - 1;
        const uint32_t budget = random();
        check(ax_fragment::lifetime_expired(ns, nu, fs, fu, budget) == oracle(ns, nu, fs, fu, budget));
    }
    std::printf("{\"assertions\":%zu,\"random_timestamps\":100000}\n", assertions);
}
