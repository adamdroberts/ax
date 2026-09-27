// SPDX-License-Identifier: GPL-2.0-only
#include "ipv4_fragment_options.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <vector>

using Bytes = std::vector<uint8_t>;
using ax_fragment::CopiedOptions;
static size_t assertions = 0;
static const uint8_t destination[] = {192, 0, 2, 1};
static void check(bool value)
{
    ++assertions;
    if (!value)
    {
        std::fprintf(stderr, "assertion %zu failed\n", assertions);
        std::abort();
    }
}
static bool see(CopiedOptions& state, const Bytes& bytes, bool continuation = false)
{ return ax_fragment::observe(state, bytes.data(), bytes.size(), continuation, destination); }
static void pair(const Bytes& first, const Bytes& second, bool expected, bool later = true)
{
    CopiedOptions state{};
    check(see(state, first));
    check(see(state, second, later) == expected);
    check(state.rejected == !expected);
    // A retry of previously accepted bytes cannot clear a rejection.
    check(see(state, first) == expected);
}
int main()
{
    static_assert(std::is_trivial<CopiedOptions>::value, "tracker uses memset");
    static_assert(sizeof(CopiedOptions) <= 48, "bounded per-tracker overhead");
    const Bytes ra{148, 4, 0, 0};
    pair({}, {}, true);
    pair({}, {1, 1, 1, 1}, true);
    pair({1, 1, 0, 0}, {}, true);
    pair(ra, {1, 148, 4, 0, 0, 0, 0, 0}, true);
    pair({7, 3, 4, 0}, {}, true); // non-copied option only at offset zero
    pair({}, {7, 3, 4, 0}, false);
    pair(ra, {}, false);
    pair({}, ra, false);
    pair(ra, {148, 4, 0, 1}, false);
    pair(ra, {158, 4, 0, 0}, false);
    pair({158, 4, 0, 0}, {158, 4, 0xff, 0xff}, true); // opaque mutable data
    pair({158, 2, 159, 2}, {159, 2, 158, 2}, false);
    pair({158, 2}, {158, 2, 158, 2}, false);
    pair({}, {0, 0, 1, 0}, false);
    pair({}, {158}, false);
    pair({}, {158, 0}, false);
    pair({}, {158, 1}, false);
    pair({}, {158, 3}, false);
    pair({}, Bytes(41, 1), false);
    for (unsigned kind = 2; kind < 256; ++kind)
    {
        for (unsigned length = 2; length <= 40; ++length)
        {
            if (kind == 148 && length != 4)
                continue;
            Bytes original(length, 0xa5);
            original[0] = kind;
            original[1] = length;
            CopiedOptions state{};
            check(see(state, original));
            check(see(state, original));
            check(see(state, original, true) == bool(kind & 128));
            for (size_t pos = 2; pos < length; ++pos)
            {
                auto changed = original;
                changed[pos] ^= 0x55;
                pair(original, changed, kind != 148, false);
            }
            if (kind & 128)
            {
                for (size_t count = 0; count <= 40 - length; ++count)
                {
                    auto padded = original;
                    padded.insert(padded.begin(), count, 1);
                    pair(original, padded, true);
                }
            }
            else
                pair(original, {}, true);
        }
    }
    Bytes maximum;
    for (int i = 0; i < 20; ++i)
        maximum.insert(maximum.end(), {158, 2});
    pair(maximum, maximum, true);
    for (unsigned i = 0; i < 4; ++i)
    {
        CopiedOptions state{};
        uint8_t changed[4];
        std::memcpy(changed, destination, 4);
        changed[i] ^= 1;
        check(see(state, ra));
        check(!ax_fragment::observe(state, ra.data(), ra.size(), true, changed));
        check(!see(state, ra));
    }
    {
        CopiedOptions state{};
        check(!ax_fragment::observe(state, nullptr, 1, false, destination));
        state = {};
        check(!ax_fragment::observe(state, nullptr, 0, false, nullptr));
        state = {};
        check(ax_fragment::observe(state, nullptr, 0, false, destination));
    }
    uint32_t seed = 0x73946a21;
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; };
    for (size_t i = 0; i < 100000; ++i)
    {
        // Exact allocations expose reads beyond the supplied span to ASan.
        Bytes bytes(random() % 65);
        for (auto& value : bytes)
            value = random();
        CopiedOptions state{};
        const bool continuation = random() & 1;
        const bool accepted = see(state, bytes, continuation);
        check(see(state, bytes, continuation) == accepted);
        if (!accepted)
            check(!see(state, {}));
    }
    std::printf("{\"assertions\":%zu,\"random_spans\":100000,\"state_bytes\":%zu}\n", assertions, sizeof(CopiedOptions));
}
