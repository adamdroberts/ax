#include "routing_validation.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

#ifdef NDEBUG
#error "validation requires assertions; do not compile with NDEBUG"
#endif

namespace
{
unsigned checks = 0;

std::vector<std::uint8_t> type2()
{
    std::vector<std::uint8_t> header(24, 0);
    header[0] = 59;
    header[1] = 2;
    header[2] = 2;
    header[3] = 1;
    header[8] = 0x20;
    header[9] = 0x01;
    header[10] = 0x0d;
    header[11] = 0xb8;
    header[23] = 3;
    return header;
}

void expect(const std::vector<std::uint8_t>& header, bool invalid)
{
    assert(ax_ip::invalid_type2_header(header.data(), header.size()) == invalid);
    assert(ax_ip::invalid_type2_chain(43, header.data(), header.size()) == invalid);
    checks += 2;
}

void chain(const std::vector<std::uint8_t>& payload, bool invalid, std::uint8_t next)
{
    assert(ax_ip::invalid_type2_chain(next, payload.data(), payload.size()) == invalid);
    ++checks;
}

std::vector<std::uint8_t> prepend(std::vector<std::uint8_t> prefix,
    const std::vector<std::uint8_t>& tail)
{
    prefix.insert(prefix.end(), tail.begin(), tail.end());
    return prefix;
}
}

int main()
{
    assert(ax_ip::invalid_type2_header(nullptr, 0));
    assert(ax_ip::invalid_type2_header(nullptr, 24));
    assert(ax_ip::invalid_type2_home_address(nullptr));
    assert(ax_ip::invalid_type2_chain(59, nullptr, 24));
    checks += 4;
    const auto valid = type2();
    expect(valid, false);
    for (std::size_t length = 0; length < valid.size(); ++length)
        expect(std::vector<std::uint8_t>(valid.begin(), valid.begin() + length), true);
    auto oversized = valid;
    oversized.push_back(0);
    // An exact-header caller rejects an extra byte, while chain framing leaves
    // No Next Header payload alone. Assert these different spans explicitly.
    assert(ax_ip::invalid_type2_header(oversized.data(), oversized.size()));
    chain(oversized, false, 43);
    ++checks;
    for (unsigned length = 0; length <= 255; ++length)
    {
        auto header = valid;
        header.resize((length + 1) * 8, 0);
        header[1] = static_cast<std::uint8_t>(length);
        expect(header, length != 2);
    }
    for (unsigned segments = 0; segments <= 255; ++segments)
    {
        auto header = valid;
        header[3] = static_cast<std::uint8_t>(segments);
        expect(header, segments != 1);
    }
    // All four reserved bytes are receiver-ignored, including nonzero values.
    for (unsigned offset = 4; offset < 8; ++offset)
        for (unsigned value = 0; value <= 255; ++value)
        {
            auto header = valid;
            header[offset] = static_cast<std::uint8_t>(value);
            expect(header, false);
        }
    for (const auto& address : std::vector<std::array<std::uint8_t, 16>>{
             {}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
             {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
             {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
             {0xfe, 0xbf, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}})
    {
        auto header = valid;
        for (unsigned i = 0; i < address.size(); ++i)
            header[8 + i] = address[i];
        expect(header, true);
    }
    for (unsigned prefix : {0xfcu, 0xfdu, 0x20u, 0x30u})
    {
        auto header = valid;
        header[8] = static_cast<std::uint8_t>(prefix);
        expect(header, false);
    }
    // Other routing types, their reserved bits, segment counts and address
    // contents are outside this Type 2 check. Type 0 is separately denied by
    // the native builtin policy, not accidentally treated as Type 2 here.
    for (unsigned kind : {0u, 1u, 3u, 4u, 253u, 254u, 255u})
        for (unsigned segments : {0u, 1u, 255u})
        {
            std::vector<std::uint8_t> header = {59, 0,
                static_cast<std::uint8_t>(kind), static_cast<std::uint8_t>(segments),
                0xff, 0xff, 0xff, 0xff};
            expect(header, false);
        }

    auto bad = valid;
    bad[3] = 2;
    for (unsigned next : {0u, 60u})
    {
        const std::vector<std::uint8_t> options = {43, 0, 0, 0, 0, 0, 0, 0};
        chain(prepend(options, valid), false, static_cast<std::uint8_t>(next));
        chain(prepend(options, bad), true, static_cast<std::uint8_t>(next));
    }
    std::vector<std::uint8_t> ah(16, 0);
    ah[0] = 43;
    ah[1] = 2;
    chain(prepend(ah, valid), false, 51);
    chain(prepend(ah, bad), true, 51);
    ah[1] = 1;
    chain(prepend(ah, valid), true, 51);
    for (unsigned field : {0u, 1u, 9u, 0xfff8u})
    {
        const std::vector<std::uint8_t> fragment = {43, 0,
            static_cast<std::uint8_t>(field >> 8), static_cast<std::uint8_t>(field),
            0, 0, 0, 1};
        chain(prepend(fragment, valid), false, 44);
        chain(prepend(fragment, bad), (field & 0xfff8) == 0, 44);
    }
    // Repeated valid Type 2 and mixed routing types are inspected separately.
    auto first = valid;
    first[0] = 43;
    chain(prepend(first, valid), false, 43);
    chain(prepend(first, bad), true, 43);
    const std::vector<std::uint8_t> unknown = {43, 0, 253, 0, 0, 0, 0, 0};
    chain(prepend(unknown, valid), false, 43);
    chain(prepend(unknown, bad), true, 43);
    chain(prepend(first, {59, 0, 253, 0, 0, 0, 0, 0}), false, 43);

    chain({}, false, 59);
    chain(bad, false, 17);
    chain(bad, false, 253);
    for (std::size_t size = 0; size < 8; ++size)
    {
        std::vector<std::uint8_t> truncated(size, 0);
        for (unsigned next : {0u, 60u, 43u, 44u, 51u})
            chain(truncated, true, static_cast<std::uint8_t>(next));
    }
    std::vector<std::uint8_t> limit;
    for (unsigned i = 0; i < 8; ++i)
        limit = prepend(first, limit);
    limit[7 * 24] = 59;
    chain(limit, false, 43);
    chain(prepend(first, limit), true, 43); // Explicit local extension budget.

    std::mt19937 random(0x62751133);
    for (unsigned trial = 0; trial < 100000; ++trial)
    {
        const std::size_t size = random() % 2057;
        std::vector<std::uint8_t> bytes(size);
        for (auto& byte : bytes)
            byte = static_cast<std::uint8_t>(random());
        if (size >= 8 && size <= 2048 && size % 8 == 0 && trial % 2 == 0)
            bytes[1] = size / 8 - 1;
        (void)ax_ip::invalid_type2_header(bytes.data(), bytes.size());
        const std::uint8_t next[] = {0, 60, 43, 51, 44, 17, 253};
        (void)ax_ip::invalid_type2_chain(next[random() % 7], bytes.data(), bytes.size());
    }
    std::cout << checks << " Routing Type 2 assertions and 100000 randomized cases passed\n";
}
