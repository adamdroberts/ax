#include "ip4_options.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <random>
#include <vector>

#ifdef NDEBUG
#error "IPv4 option validation tests require assertions"
#endif

int main()
{
    std::size_t checks = 0;
    auto expect = [&](const std::vector<std::uint8_t>& data, bool invalid)
    {
        assert(ax_ip4::invalid_options(data.data(), data.size()) == invalid);
        ++checks;
    };
    auto padded = [](std::vector<std::uint8_t> data)
    {
        data.resize((data.size() + 3) / 4 * 4);
        return data;
    };

    assert(!ax_ip4::invalid_options(nullptr, 0)); ++checks;
    for (std::size_t size = 1; size <= 64; ++size)
    {
        assert(ax_ip4::invalid_options(nullptr, size)); ++checks;
        expect(std::vector<std::uint8_t>(size, 0), size > 40 || size % 4 != 0);
    }
    std::uint8_t one = 1;
    assert(!ax_ip4::invalid_options(&one, 0)); ++checks;
    assert(ax_ip4::invalid_options(&one, std::numeric_limits<std::size_t>::max())); ++checks;
    expect({}, false);
    for (std::size_t size = 0; size <= 40; size += 4)
        expect(std::vector<std::uint8_t>(size, 1), false);

    // Every EOL location and every possible following octet. Padding after
    // EOL is zero, even if a nonzero octet looks like NOP or another option.
    for (unsigned end = 0; end < 40; ++end)
    {
        std::vector<std::uint8_t> bytes(40, 0);
        std::fill(bytes.begin(), bytes.begin() + end, 1);
        expect(bytes, false);
        for (unsigned position = end + 1; position < 40; ++position)
            for (unsigned value = 1; value <= 255; ++value)
            {
                bytes[position] = value;
                expect(bytes, true);
                bytes[position] = 0;
            }
    }

    // Exhaust all TLV type/length bytes over every legal span size. Known
    // pointer fields use 255 (full/completed), avoiding unrelated semantics.
    for (unsigned type = 2; type <= 255; ++type)
        for (unsigned length = 0; length <= 255; ++length)
            for (unsigned span = 4; span <= 40; span += 4)
            {
                std::vector<std::uint8_t> bytes(span, 0);
                bytes[0] = type; bytes[1] = length;
                // Bytes outside a short option are padding, not its pointer.
                if (length >= 3)
                    bytes[2] = 255;
                bool valid = length >= 2 && length <= span;
                if (type == 7 || type == 131 || type == 137)
                    valid = valid && length >= 3;
                else if (type == 68)
                    valid = valid && length >= 4;
                else if (type == 148)
                    valid = valid && length == 4;
                expect(bytes, !valid);
            }

    // Every pointer byte, including values far past the declared length.
    // No unsupported pointer-alignment assumption is imposed.
    for (unsigned type : {7u, 131u, 137u, 68u})
        for (unsigned length = 0; length <= 255; ++length)
            for (unsigned pointer = 0; pointer <= 255; ++pointer)
            {
                std::vector<std::uint8_t> bytes(40, 0);
                bytes[0] = type; bytes[1] = length;
                if (length >= 3)
                    bytes[2] = pointer;
                const unsigned minimum_length = type == 68 ? 4 : 3;
                const unsigned minimum_pointer = type == 68 ? 5 : 4;
                const bool valid = length >= minimum_length && length <= 40 &&
                    pointer >= minimum_pointer;
                expect(bytes, !valid);
            }

    // Router Alert values are not a validity allowlist (RFC 2113 section 2.2).
    for (unsigned value = 0; value <= 65535; ++value)
        expect({148, 4, static_cast<std::uint8_t>(value >> 8),
                static_cast<std::uint8_t>(value)}, false);

    // Multiple independent options, unknowns, obsolete opaque options, and
    // exact-boundary versus missing-length/truncated TLVs after NOP prefixes.
    expect({7, 3, 255, 68, 4, 255, 0, 0}, false);
    expect({7, 3, 4, 131, 3, 255, 1, 0}, false);
    expect({7, 3, 4, 7, 3, 255, 1, 0}, true);
    expect({68, 4, 5, 0, 68, 4, 255, 0}, true);
    for (unsigned left : {131u, 137u})
        for (unsigned right : {131u, 137u})
            expect({static_cast<std::uint8_t>(left), 3, 255,
                    static_cast<std::uint8_t>(right), 3, 255, 1, 0}, true);
    expect({130, 2, 136, 2}, false); // Security and Stream Identifier stay opaque.
    expect({148, 4, 0, 0, 148, 4, 255, 255}, false); // No invented uniqueness rule.
    expect({30, 4, 0, 255, 30, 4, 0, 1}, false); // Unknown value octets are not TLVs.
    for (unsigned prefix = 0; prefix < 40; ++prefix)
    {
        std::vector<std::uint8_t> bytes(prefix, 1);
        bytes.push_back(30);
        // A length octet may not be borrowed from beyond the supplied span.
        if (bytes.size() % 4 == 0)
            expect(bytes, true);
        for (unsigned length : {0u, 1u, 2u, 3u, 4u, 40u, 255u})
        {
            auto option = bytes;
            option.push_back(length);
            option = padded(option);
            const bool invalid = option.size() > 40 || length < 2 ||
                length > option.size() - prefix;
            expect(option, invalid);
        }
    }

    // Guard-adjacent allocations plus ASan/UBSan exercise arbitrary short
    // spans; mutation beyond the supplied span must never affect the result.
    std::mt19937 random(7911122);
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        const std::size_t size = random() % 65;
        std::vector<std::uint8_t> bytes(size);
        for (auto& byte : bytes)
            byte = random();
        const bool invalid = ax_ip4::invalid_options(bytes.data(), bytes.size());
        auto extra = bytes;
        extra.resize(size + 32, 0xff);
        assert(ax_ip4::invalid_options(extra.data(), size) == invalid);
        if (size > 40 || size % 4 != 0)
            assert(invalid);
    }
    std::cout << checks << " assertions and 100000 deterministic randomized cases passed\n";
}
