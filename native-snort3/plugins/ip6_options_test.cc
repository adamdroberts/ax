#include "ip6_options.h"

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
using Error = ax_ip::IP6OptionError;
unsigned checks = 0;

std::vector<std::uint8_t> extension(std::initializer_list<std::uint8_t> options)
{
    std::vector<std::uint8_t> header = {59, 0};
    header.insert(header.end(), options);
    while (header.size() % 8)
        header.push_back(0);
    header[1] = header.size() / 8 - 1;
    return header;
}

void expect(const std::vector<std::uint8_t>& header, Error wanted,
    bool hop_by_hop = true, std::uint16_t payload_length = 64,
    bool fragment_present = false)
{
    assert(ax_ip::ip6_options_error(header.data(), header.size(), hop_by_hop,
        payload_length, fragment_present) == wanted);
    assert(ax_ip::invalid_ip6_options(header.data(), header.size(), hop_by_hop,
        payload_length, fragment_present) == (wanted != Error::none));
    checks += 2;
}

void chain(const std::vector<std::uint8_t>& payload, bool invalid,
    std::uint8_t next = 0, std::uint16_t payload_length = 64)
{
    assert(ax_ip::invalid_ip6_option_chain(next, payload.data(), payload.size(),
        payload_length) == invalid);
    ++checks;
}
}

int main()
{
    assert(ax_ip::ip6_options_error(nullptr, 0, true, 0, false) == Error::header_length);
    assert(ax_ip::ip6_options_error(nullptr, 8, true, 64, false) == Error::header_length);
    checks += 2;
    const auto padding = extension({0, 0, 0, 0, 0, 0});
    expect(padding, Error::none);
    expect(padding, Error::none, false);
    expect(padding, Error::missing_jumbo, true, 0);
    for (std::size_t size = 0; size < padding.size(); ++size)
    {
        assert(ax_ip::ip6_options_error(padding.data(), size, true, 64, false)
            == Error::header_length);
        ++checks;
    }
    auto wrong_length = padding;
    wrong_length[1] = 1;
    expect(wrong_length, Error::header_length);
    wrong_length = padding;
    wrong_length.push_back(0);
    expect(wrong_length, Error::header_length);

    // Every non-Pad1 type needs its length octet within this exact extension.
    for (unsigned type = 1; type <= 255; ++type)
    {
        auto trailing = padding;
        trailing.back() = static_cast<std::uint8_t>(type);
        expect(trailing, Error::truncated_option);
    }
    for (unsigned length = 5; length <= 255; ++length)
        expect(extension({0x1e, static_cast<std::uint8_t>(length), 0, 0, 0, 0}),
            Error::option_overrun);

    // Preserve opaque option types regardless of action/change bits. These
    // bits do not make a type malformed or identify receiver support.
    for (unsigned type = 1; type <= 255; ++type)
    {
        if (type == 5 || type == 0xc2)
            continue;
        for (bool hop : {false, true})
            expect(extension({static_cast<std::uint8_t>(type), 0, 0, 0, 0, 0}),
                Error::none, hop);
    }
    expect(extension({1, 4, 1, 2, 3, 4}), Error::none); // Opaque PadN data.
    expect(extension({0x1e, 0, 0x01, 0xff, 0, 0}), Error::option_overrun);

    const auto router_alert = extension({5, 2, 0, 0});
    expect(router_alert, Error::none);
    expect(router_alert, Error::router_alert_placement, false);
    expect(extension({5, 2, 0xff, 0xff}), Error::none); // Unknown value ignored.
    expect(extension({5, 0}), Error::router_alert_length);
    expect(extension({5, 1, 0}), Error::router_alert_length);
    expect(extension({5, 3, 0, 0, 0}), Error::router_alert_length);
    expect(extension({0, 5, 2, 0, 0}), Error::router_alert_alignment);
    expect(extension({5, 2, 0, 0, 5, 2, 0, 0}), Error::duplicate_router_alert);
    expect(extension({0x1e, 0, 5, 2, 0, 0}), Error::none);
    expect(extension({0x1e, 0, 5, 0}), Error::router_alert_length);
    expect(extension({0x45, 2, 0, 0, 5, 2, 0, 0}), Error::none);

    const auto jumbo = extension({0xc2, 4, 0, 1, 0, 0});
    expect(jumbo, Error::none, true, 0);
    expect(jumbo, Error::jumbo_placement, false, 0);
    expect(jumbo, Error::jumbo_base_length, true, 64);
    expect(jumbo, Error::jumbo_fragment, true, 0, true);
    expect(extension({0xc2, 0}), Error::jumbo_length, true, 0);
    expect(extension({0xc2, 3, 0, 1, 0}), Error::jumbo_length, true, 0);
    expect(extension({0xc2, 5, 0, 1, 0, 0, 0}), Error::jumbo_length, true, 0);
    expect(extension({0, 0, 0xc2, 4, 0, 1, 0, 0}), Error::jumbo_alignment, true, 0);
    expect(extension({0xc2, 4, 0, 0, 0xff, 0xff}), Error::jumbo_small_payload, true, 0);
    expect(extension({0xc2, 4, 0, 0, 0, 0}), Error::jumbo_small_payload, true, 0);
    expect(extension({0xc2, 4, 0xff, 0xff, 0xff, 0xff}), Error::none, true, 0);
    expect(extension({0xc2, 4, 0, 1, 0, 0, 0, 0, 0xc2, 4, 0, 1, 0, 0}),
        Error::duplicate_jumbo, true, 0);
    expect(extension({0x1e, 0, 0, 0, 0xc2, 4, 0, 1, 0, 0}), Error::none, true, 0);
    expect(extension({0xc2, 4, 0, 1, 0, 0, 0x1e, 255}), Error::option_overrun, true, 0);

    // The largest representable extension has 2048 octets. Traversal must
    // retain a trailing error after thousands of well-formed opaque options.
    std::vector<std::uint8_t> maximum(2048, 0);
    maximum[0] = 59;
    maximum[1] = 255;
    for (std::size_t offset = 2; offset < maximum.size(); offset += 2)
        maximum[offset] = 0x1e;
    expect(maximum, Error::none);
    maximum.back() = 1;
    expect(maximum, Error::option_overrun);

    chain({}, false, 59);
    chain({}, true, 0);
    chain({}, true, 44);
    assert(ax_ip::invalid_ip6_option_chain(59, nullptr, 1, 1));
    ++checks;
    chain(padding, false);
    chain(router_alert, false);
    chain(router_alert, true, 60);
    chain(jumbo, true, 0, 64);
    chain(jumbo, false, 0, 0);
    chain(extension({5, 0}), true);

    // Offset-zero fragments must expose their following Destination Options;
    // noninitial fragments contain continuation bytes and must not be parsed.
    for (bool first : {false, true})
    {
        std::vector<std::uint8_t> fragment = {60, 0, 0,
            static_cast<std::uint8_t>(first ? 1 : 9), 0, 0, 0, 1};
        auto valid = fragment;
        valid.insert(valid.end(), padding.begin(), padding.end());
        chain(valid, false, 44);
        auto malformed = fragment;
        malformed.insert(malformed.end(), router_alert.begin(), router_alert.end());
        chain(malformed, first, 44);
        fragment.resize(7);
        chain(fragment, true, 44);
    }
    // A Fragment header anywhere in the traversed chain conflicts with Jumbo,
    // including noninitial fragments at which the rest of the walk must stop.
    for (unsigned field : {0u, 1u, 9u})
    {
        auto jumbofrag = jumbo;
        jumbofrag[0] = 44;
        jumbofrag.insert(jumbofrag.end(), {59, 0, 0,
            static_cast<std::uint8_t>(field), 0, 0, 0, 1});
        chain(jumbofrag, true, 0, 0);
    }
    // Traverse AH and Routing by their differing length units. Do not inspect
    // opaque upper-layer data that happens to resemble a forbidden option.
    std::vector<std::uint8_t> ah(16, 0);
    ah[0] = 60;
    ah[1] = 2;
    ah.insert(ah.end(), padding.begin(), padding.end());
    chain(ah, false, 51);
    ah[1] = 1; // Twelve-byte AH cannot align an IPv6 extension to eight bytes.
    chain(ah, true, 51);
    std::vector<std::uint8_t> routing = {60, 0, 253, 0, 0, 0, 0, 0};
    routing.insert(routing.end(), router_alert.begin(), router_alert.end());
    chain(routing, true, 43);
    chain(routing, false, 17);
    chain(routing, false, 253);
    for (std::size_t size = 0; size < 8; ++size)
    {
        const std::vector<std::uint8_t> short_header(padding.begin(), padding.begin() + size);
        for (unsigned next : {0u, 60u, 43u, 51u, 44u})
            chain(short_header, true, static_cast<std::uint8_t>(next));
    }
    std::vector<std::uint8_t> limit;
    for (unsigned i = 0; i < 8; ++i)
    {
        auto option = padding;
        option[0] = i == 7 ? 59 : 60;
        limit.insert(limit.end(), option.begin(), option.end());
    }
    chain(limit, false, 60);
    limit[56] = 60;
    limit.insert(limit.end(), padding.begin(), padding.end());
    chain(limit, true, 60); // Explicit local eight-extension policy.

    // Independent bounded arbitrary-input memory-safety coverage. Exact-sized
    // buffers let ASan detect a read past either the header or TLV span.
    std::mt19937 random(0x82002711);
    for (unsigned trial = 0; trial < 100000; ++trial)
    {
        const std::size_t size = random() % 2057;
        std::vector<std::uint8_t> bytes(size);
        for (auto& byte : bytes)
            byte = static_cast<std::uint8_t>(random());
        if (size >= 8 && size <= 2048 && size % 8 == 0 && trial % 2 == 0)
            bytes[1] = size / 8 - 1;
        (void)ax_ip::ip6_options_error(bytes.data(), bytes.size(), random() % 2,
            static_cast<std::uint16_t>(random()), random() % 2);
        const std::uint8_t next[] = {0, 60, 43, 51, 44, 17, 253};
        (void)ax_ip::invalid_ip6_option_chain(next[random() % 7], bytes.data(),
            bytes.size(), static_cast<std::uint16_t>(random()));
    }
    std::cout << checks << " IPv6 option assertions and 100000 randomized cases passed\n";
}
