// SPDX-License-Identifier: GPL-2.0-only
#include "home_address.h"
#include "ip6_options.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

using Bytes = std::vector<std::uint8_t>;
using Error = ax_home::Error;
static unsigned checks = 0;
static void check(bool value)
{
    ++checks;
    if (!value)
        std::abort();
}

static Bytes option(std::size_t position = 6, unsigned length = 16)
{
    Bytes data((position + 2 + length + 7) / 8 * 8, 0);
    data[0] = 17;
    data[1] = data.size() / 8 - 1;
    data[position] = 0xc9;
    data[position + 1] = length;
    if (length >= 2)
    {
        data[position + 2] = 0x20;
        data[position + 3] = 1;
    }
    return data;
}

static void expect(const Bytes& data, Error error, std::uint8_t next = 60)
{
    const auto result = ax_home::chain(next, data.data(), data.size());
    check(result.error == error);
    if (ax_home::malformed_home(error))
        check(ax_ip::invalid_ip6_option_chain(next, data.data(), data.size(), data.size()));
}

static Bytes joined(Bytes first, std::uint8_t next, const Bytes& second)
{
    first[0] = next;
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

static Bytes ipv6(const Bytes& prefix, std::uint8_t next = 60)
{
    Bytes packet(40, 0);
    packet[0] = 0x60;
    packet[4] = prefix.size() >> 8;
    packet[5] = prefix.size();
    packet[6] = next;
    packet.insert(packet.end(), prefix.begin(), prefix.end());
    return packet;
}

int main()
{
    const auto hao = option();
    expect(hao, Error::none);
    expect(hao, Error::placement, 0);
    check(ax_home::chain(60, nullptr, 1).error == Error::framing);
    check(ax_home::chain(60, nullptr, 0).error == Error::framing);
    for (std::size_t size = 0; size < hao.size(); ++size)
    {
        Bytes truncated(hao.begin(), hao.begin() + size);
        expect(truncated, Error::framing);
    }
    for (unsigned length = 0; length <= 255; ++length)
        expect(option(6, length), length == 16 ? Error::none : Error::length);
    for (std::size_t position = 2; position <= 2030; ++position)
    {
        auto data = option(position);
        expect(data, position % 8 == 6 ? Error::none : Error::alignment);
        auto packet = ipv6(data);
        const auto* source = ax_home::source(packet.data(), packet.data() + packet.size(), 17);
        check(source == (position % 8 == 6 ? packet.data() + 40 + position + 2 : nullptr));
    }
    // Recognition uses the full type byte; action bits do not alias 0xc9.
    for (unsigned type = 0; type <= 255; ++type)
    {
        auto data = hao;
        data[6] = type;
        if (type == 0)
            data[7] = 0; // Remaining address bytes become valid zero-length TLVs.
        const auto result = ax_home::chain(60, data.data(), data.size());
        check(result.error == Error::none);
        check((result.source != nullptr) == (type == 0xc9));
    }
    auto overrun = hao;
    overrun[7] = 17;
    expect(overrun, Error::length);
    auto duplicate = hao;
    duplicate.resize(48, 0);
    duplicate[1] = 5;
    std::copy(hao.begin() + 6, hao.end(), duplicate.begin() + 30);
    expect(duplicate, Error::duplicate);
    expect(joined(hao, 60, hao), Error::duplicate);
    for (const auto address : {std::array<unsigned, 3>{0, 0, 0}, {0, 0, 1},
                              {0xfe, 0x80, 0}, {0xfe, 0xbf, 0}, {0xff, 2, 1},
                              {0xfc, 0, 0}, {0x20, 1, 0}})
    {
        auto data = hao;
        std::fill(data.begin() + 8, data.end(), 0);
        data[8] = address[0]; data[9] = address[1]; data[23] = address[2];
        const bool bad = address[0] == 0 || address[0] >= 0xfe;
        expect(data, bad ? Error::address : Error::none);
    }
    const Bytes route = {17, 0, 253, 0, 0, 0, 0, 0};
    expect(joined(route, 60, hao), Error::none, 43);
    expect(joined(hao, 43, route), Error::placement);
    Bytes ah(16, 0);
    ah[0] = 17; ah[1] = 2;
    expect(joined(ah, 60, hao), Error::placement, 51);
    expect(joined(hao, 51, ah), Error::none);
    for (unsigned field : {0u, 1u, 8u, 9u, 65528u})
    {
        Bytes fragment = {17, 0, static_cast<std::uint8_t>(field >> 8),
            static_cast<std::uint8_t>(field), 0, 0, 0, 1};
        auto before = joined(hao, 44, fragment);
        expect(before, Error::none);
        auto packet = ipv6(before);
        check((ax_home::source(packet.data(), packet.data() + packet.size(), 17) != nullptr) == (field == 0));
        expect(joined(fragment, 60, hao), (field & 0xfff8) ? Error::none : Error::placement, 44);
    }
    Bytes padding(8, 0);
    padding[0] = 17;
    auto limit = hao;
    for (unsigned i = 1; i < 8; ++i)
        limit = joined(padding, 60, limit);
    expect(limit, Error::none);
    expect(joined(padding, 60, limit), Error::budget);
    // Stop at transport, unknown headers, encapsulation and opaque ESP.
    for (unsigned next : {6u, 17u, 41u, 50u, 58u, 59u, 253u})
    {
        const auto result = ax_home::chain(next, hao.data(), hao.size());
        check(result.error == Error::none && result.source == nullptr && result.consumed == 0);
    }
    auto packet = ipv6(hao);
    check(ax_home::source(nullptr, packet.data(), 17) == nullptr);
    check(ax_home::source(packet.data(), nullptr, 17) == nullptr);
    check(ax_home::source(packet.data(), packet.data() + 39, 17) == nullptr);
    check(ax_home::source(packet.data() + 1, packet.data(), 17) == nullptr);
    check(ax_home::source(packet.data(), packet.data() + packet.size(), 6) == nullptr);
    packet[5] = 23;
    check(ax_home::source(packet.data(), packet.data() + packet.size(), 17) == nullptr);
    packet[5] = 25; // A resize may leave payload length larger than the prefix.
    check(ax_home::source(packet.data(), packet.data() + packet.size(), 17) == packet.data() + 48);
    packet[0] = 0x40;
    check(ax_home::source(packet.data(), packet.data() + packet.size(), 17) == nullptr);

    std::mt19937 random(0x62750820);
    for (unsigned trial = 0; trial < 100000; ++trial)
    {
        // Independent single-option oracle: a length of 16 at 8n+6 in a
        // Destination header selects its exact address and no other bytes.
        const unsigned position = 2 + random() % 2010;
        const unsigned length = random() % 20;
        const bool hop = random() % 2;
        auto data = option(position, length);
        const auto result = ax_home::chain(hop ? 0 : 60, data.data(), data.size());
        const auto expected = length != 16 ? Error::length : hop ? Error::placement :
            position % 8 != 6 ? Error::alignment : Error::none;
        check(result.error == expected);
        check(result.source == (expected == Error::none ? data.data() + position + 2 : nullptr));

        // Exact-sized arbitrary spans run under ASan/UBSan, including unknown
        // framing. This is memory-safety coverage, not a semantic fuzz oracle.
        Bytes fuzz(random() % 4100);
        for (auto& byte : fuzz)
            byte = random();
        const std::uint8_t protocols[] = {0, 60, 43, 51, 44, 17, 253};
        const auto parsed = ax_home::chain(protocols[random() % 7], fuzz.data(), fuzz.size());
        check(parsed.consumed <= fuzz.size());
        if (parsed.source)
            check(parsed.source >= fuzz.data() && parsed.source + 16 <= fuzz.data() + fuzz.size());
    }
    std::printf("%u Home Address assertions, 100000 semantic cases and 100000 arbitrary spans passed\n", checks);
}
