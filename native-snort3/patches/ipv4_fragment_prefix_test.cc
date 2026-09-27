// SPDX-License-Identifier: GPL-2.0-only
#include "ipv4_fragment_prefix.h"
#include "ipv6_fragment_prefix.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <type_traits>
#include <vector>

using Bytes = std::vector<uint8_t>;
using State = ax_fragment::Ip4Prefix;
using Result = ax_fragment::Ip4PrefixResult;
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
static Bytes packet(unsigned header, unsigned payload, unsigned offset, unsigned ecn, bool more = true)
{
    Bytes bytes(header + payload, 0);
    bytes[0] = 0x40 | (header / 4);
    bytes[1] = 0x28 | ecn;
    bytes[2] = bytes.size() >> 8;
    bytes[3] = bytes.size();
    bytes[6] = (offset / 8) >> 8 | (more ? 32 : 0);
    bytes[7] = offset / 8;
    bytes[8] = 41;
    bytes[9] = 17;
    return bytes;
}
int main()
{
    static_assert(std::is_trivial<State>::value, "Native tracker requires trivial storage");
    for (unsigned header = 20; header <= 60; header += 4)
    {
        const auto bytes = packet(header, 24, 0, 2);
        for (size_t captured = 0; captured < bytes.size(); ++captured)
        {
            // Exactly sized allocation makes any boundary overread observable.
            const Bytes truncated(bytes.begin(), bytes.begin() + captured);
            State state{};
            check(ax_fragment::observe_ip4_prefix(state, truncated.data(), captured, 0, 24) == Result::invalid_header_or_size);
            check(!state.first_seen && state.ecn_seen == 0 && state.largest_end == 0);
        }
        for (unsigned offset = 0; offset <= 65528; offset += 8)
        {
            const auto wire = packet(header, 24, offset, 2, offset == 0);
            State state{};
            const bool valid = offset + 24u + (offset ? 20u : header) <= 65535;
            check((ax_fragment::observe_ip4_prefix(state, wire.data(), wire.size(), offset, 24) == Result::okay) == valid);
            if (valid)
            {
                check(state.first_seen == (offset == 0));
                check(state.largest_end == offset + 24 && state.ecn_seen == 4);
            }
        }
        // Exact total length boundaries include offset-zero options even when
        // the last fragment arrived first and its own header was only 20 bytes.
        for (int delta = -1; delta <= 1; ++delta)
            for (bool reverse : {false, true})
            {
                const unsigned payload = 65535 - header + delta;
                auto first = packet(header, 24, 0, 2);
                auto last = packet(20, payload - 24, 24, 2, false);
                const std::array<Bytes, 2> wires{first, last};
                State state{};
                for (unsigned n = 0; n < 2; ++n)
                {
                    const unsigned i = reverse ? 1 - n : n;
                    const bool valid = delta <= 0 || (n == 0 && (i == 0 || header != 20));
                    check((ax_fragment::observe_ip4_prefix(state, wires[i].data(), wires[i].size(),
                        i ? 24 : 0, i ? payload - 24 : 24) == Result::okay) == valid);
                    if (!valid)
                        break;
                }
            }
        for (size_t payload = 0; payload <= 65536; ++payload)
        {
            const bool fits = header + payload <= 65535;
            check(ax_fragment::ip4_rebuilt_fits(header, payload, 14, 67053) == fits);
            check(ax_fragment::ip4_rebuilt_fits(header, payload, 14, 14 + header + payload) == fits);
            check(!ax_fragment::ip4_rebuilt_fits(header, payload, 14, 13 + header + payload));
        }
    }
    for (unsigned a = 0; a < 4; ++a)
        for (unsigned b = 0; b < 4; ++b)
            for (unsigned c = 0; c < 4; ++c)
            {
                const std::array<unsigned, 3> codes{a, b, c};
                std::array<unsigned, 3> order{0, 1, 2};
                do
                {
                    State state{};
                    bool ce = false, not_ect = false, rejected = false;
                    for (auto i : order)
                    {
                        auto wire = packet(20 + i * 4, 24, i * 24, codes[i], i != 2);
                        ce |= codes[i] == 3;
                        not_ect |= codes[i] == 0;
                        const auto result = ax_fragment::observe_ip4_prefix(state, wire.data(), wire.size(), i * 24, 24);
                        check(result == (ce && not_ect ? Result::conflicting_ecn : Result::okay));
                        if (result != Result::okay)
                        {
                            rejected = true;
                            break; // Native rejection is sticky and bypasses this helper thereafter.
                        }
                    }
                    if (!rejected)
                    {
                        check(state.first_seen && state.first[8] == 41 && state.first[0] == 0x45);
                        check(ax_fragment::ip6_rebuilt_ecn(state.ecn_seen, state.first[1] & 3) == (ce ? 3 : a));
                    }
                } while (std::next_permutation(order.begin(), order.end()));
            }
    auto first = packet(60, 24, 0, 2);
    State state{};
    check(ax_fragment::observe_ip4_prefix(state, first.data(), first.size(), 0, 24) == Result::okay);
    auto duplicate = packet(20, 24, 0, 3);
    duplicate[8] = 99;
    check(ax_fragment::observe_ip4_prefix(state, duplicate.data(), duplicate.size(), 0, 24) == Result::okay);
    check(state.first[0] == 0x4f && state.first[8] == 41 && state.ecn_seen == 12);
    check(ax_fragment::observe_ip4_prefix(state, nullptr, 100, 0, 24) == Result::invalid_header_or_size);
    for (unsigned value = 0; value < 256; ++value)
    {
        auto bad = packet(20, 24, 0, 2);
        bad[0] = value;
        State empty{};
        check((ax_fragment::observe_ip4_prefix(empty, bad.data(), bad.size(), 0, 24) == Result::okay) == (value == 0x45));
    }
    const auto maximum = std::numeric_limits<size_t>::max();
    check(!ax_fragment::ip4_rebuilt_fits(maximum, maximum, maximum, maximum));
    check(!ax_fragment::ip4_rebuilt_fits(20, 1, maximum, maximum));
    check(!ax_fragment::ip4_rebuilt_fits(19, 0, 0, maximum));
    check(!ax_fragment::ip4_rebuilt_fits(61, 0, 0, maximum));
    uint32_t seed = 0x8921ad39;
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; };
    for (unsigned i = 0; i < 100000; ++i)
    {
        Bytes bytes(random() % 257);
        for (auto& byte : bytes)
            byte = random();
        State empty{};
        const auto offset = random() % 65536, payload = random() % 65536;
        const auto result = ax_fragment::observe_ip4_prefix(empty, bytes.data(), bytes.size(), offset, payload);
        check(result != Result::okay || (empty.largest_end <= 65515 && empty.ecn_seen));
        const size_t header = random() % 128, body = random(), outer = random(), capacity = random();
        const bool expected = header >= 20 && header <= 60 && header % 4 == 0 &&
            header + static_cast<uint64_t>(body) <= 65535 && static_cast<uint64_t>(outer) + header + body <= capacity;
        check(ax_fragment::ip4_rebuilt_fits(header, body, outer, capacity) == expected);
    }
    std::printf("{\"assertions\":%zu,\"random_spans\":100000,\"random_geometry\":100000}\n", assertions);
}
