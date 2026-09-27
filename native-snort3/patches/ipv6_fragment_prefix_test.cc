// SPDX-License-Identifier: GPL-2.0-only
#include "ipv6_fragment_prefix.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <vector>

using Bytes = std::vector<std::uint8_t>;
static std::size_t assertions = 0;
static void check(bool value)
{
    ++assertions;
    if (!value)
    {
        std::fprintf(stderr, "assertion %zu failed\n", assertions);
        std::abort();
    }
}
static Bytes packet(unsigned length, unsigned kind = 60)
{
    Bytes bytes(40 + length + 8 + 24, 0);
    bytes[0] = 0x60;
    bytes[4] = (bytes.size() - 40) >> 8;
    bytes[5] = bytes.size() - 40;
    bytes[6] = length ? kind : 44;
    if (length)
    {
        bytes[40] = 44;
        bytes[41] = kind == 51 ? length / 4 - 2 : length / 8 - 1;
    }
    bytes[40 + length] = 17;
    bytes[40 + length + 3] = 1;
    return bytes;
}
int main()
{
    for (unsigned length = 0; length <= 2048; length += 8)
    {
        auto bytes = packet(length);
        const auto parsed = ax_fragment::ip6_prefix(bytes.data(), bytes.size());
        check(parsed.valid && parsed.length == 40 + length && parsed.next == 17);
        check(parsed.next_offset == (length ? 40u : 6u));
        check(parsed.fragment_offset == 0 && parsed.extensions == (length ? 2u : 1u));
        check(!ax_fragment::ip6_prefix(bytes.data(), bytes.size(), length ? 1 : 0).valid);
        for (std::size_t size = 0; size < bytes.size(); ++size)
            check(!ax_fragment::ip6_prefix(bytes.data(), size).valid);
        bytes.push_back(0xa5); // Link padding is not part of the selected IP length.
        check(ax_fragment::ip6_prefix(bytes.data(), bytes.size()).valid);
        for (unsigned offset = 0; offset <= 65528; offset += 8)
        {
            bytes[42 + length] = offset >> 8;
            bytes[43 + length] = offset | 7; // Reserved bits do not alter offset.
            check(ax_fragment::ip6_prefix(bytes.data(), bytes.size()).fragment_offset == offset);
        }
    }
    for (unsigned kind = 0; kind < 256; ++kind)
    {
        auto bytes = packet(16, kind);
        bool known = kind == 0 || kind == 43 || kind == 60 || kind == 51 || kind == 44;
        check(ax_fragment::ip6_prefix(bytes.data(), bytes.size()).valid == known);
    }
    for (unsigned length = 8; length <= 1028; length += 4)
    {
        auto bytes = packet(length, 51);
        check(ax_fragment::ip6_prefix(bytes.data(), bytes.size()).valid == (length >= 16 && length % 8 == 0));
    }
    for (unsigned a = 0; a < 4; ++a)
        for (unsigned b = 0; b < 4; ++b)
            for (unsigned c = 0; c < 4; ++c)
            {
                const auto seen = (1 << a) | (1 << b) | (1 << c);
                const bool ce = a == 3 || b == 3 || c == 3;
                const bool not_ect = a == 0 || b == 0 || c == 0;
                check(ax_fragment::ip6_rebuilt_ecn(seen, a) == (ce && not_ect ? 255 : ce ? 3 : a));
            }
    for (unsigned seen = 0; seen <= 255; ++seen)
        for (unsigned first = 0; first <= 255; ++first)
        {
            const bool invalid = !seen || seen > 15 || first > 3 ||
                !(seen & (1u << (first & 3))) || (seen & 9) == 9;
            check((ax_fragment::ip6_rebuilt_ecn(seen, first) == 255) == invalid);
        }
    for (std::size_t prefix = 40; prefix <= 65575; ++prefix)
    {
        const auto payload = 65575 - prefix;
        check(ax_fragment::ip6_rebuilt_fits(prefix, payload, 14, 67053));
        check(!ax_fragment::ip6_rebuilt_fits(prefix, payload + 1, 14, 67053));
        check(ax_fragment::ip6_rebuilt_fits(prefix, payload, 14, prefix + payload + 14));
        check(!ax_fragment::ip6_rebuilt_fits(prefix, payload, 14, prefix + payload + 13));
    }
    const auto maximum = std::numeric_limits<std::size_t>::max();
    check(!ax_fragment::ip6_rebuilt_fits(maximum, maximum, maximum, maximum));
    check(!ax_fragment::ip6_rebuilt_fits(39, 0, 0, maximum));
    check(!ax_fragment::ip6_rebuilt_fits(40, 1, maximum, maximum));
    std::uint32_t seed = 0x6711ab22;
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; };
    for (unsigned i = 0; i < 100000; ++i)
    {
        Bytes bytes(random() % 4097);
        for (auto& b : bytes)
            b = random();
        const auto parsed = ax_fragment::ip6_prefix(bytes.data(), bytes.size(), random() % 256);
        check(!parsed.valid || (parsed.length >= 40 && parsed.length + 8 <= bytes.size() && parsed.next_offset < parsed.length));
        const std::size_t prefix = random(), payload = random(), outer = random(), capacity = random();
        const bool expected = prefix >= 40 && prefix + payload <= 65575 && outer + prefix + payload <= capacity;
        check(ax_fragment::ip6_rebuilt_fits(prefix, payload, outer, capacity) == expected);
    }
    std::printf("{\"assertions\":%zu,\"random_spans\":100000,\"random_geometry\":100000}\n", assertions);
}
