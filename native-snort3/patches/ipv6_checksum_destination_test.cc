#include "ipv6_checksum_destination.h"

#include <algorithm>
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
using Bytes = std::vector<std::uint8_t>;
std::size_t checks = 0;
constexpr std::size_t absent = static_cast<std::size_t>(-1);

Bytes type2(std::uint8_t next = 17, std::uint8_t segments = 1)
{
    Bytes header(24, 0);
    header[0] = next;
    header[1] = 2;
    header[2] = 2;
    header[3] = segments;
    header[8] = 0x20;
    header[9] = 0x01;
    header[10] = 0x0d;
    header[11] = 0xb8;
    header[23] = 3;
    return header;
}

Bytes extension(std::uint8_t next)
{
    Bytes header(8, 0);
    header[0] = next;
    return header;
}

Bytes route(std::uint8_t next, std::uint8_t segments)
{
    auto header = extension(next);
    header[2] = 253;
    header[3] = segments;
    return header;
}

Bytes joined(Bytes first, const Bytes& second)
{
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

void expect(const Bytes& prefix, std::uint8_t next, std::size_t address_offset,
    std::uint8_t upper = 17)
{
    const auto* result = ax_checksum::type2_destination(next, prefix.data(), prefix.size(), upper);
    if (address_offset == absent)
        assert(result == nullptr);
    else
    {
        assert(address_offset <= prefix.size() && prefix.size() - address_offset >= 16);
        assert(result == prefix.data() + address_offset);
        // Read the complete returned address under ASan, not just its pointer.
        assert(std::equal(result, result + 16, prefix.data() + address_offset));
    }
    ++checks;
}

Bytes packet(const Bytes& prefix, std::uint8_t next = 43)
{
    Bytes bytes(40, 0);
    bytes[0] = 0x60;
    const std::size_t payload_length = prefix.size() + 32;
    bytes[4] = static_cast<std::uint8_t>(payload_length >> 8);
    bytes[5] = static_cast<std::uint8_t>(payload_length);
    bytes[6] = next;
    bytes = joined(bytes, prefix);
    bytes.resize(40 + payload_length, 0);
    return bytes;
}

void expect_packet(const Bytes& bytes, std::size_t upper_offset,
    std::size_t address_offset, std::uint8_t upper = 17)
{
    assert(bytes.size() >= 40 && upper_offset <= bytes.size());
    const auto* result = ax_checksum::destination(bytes.data(), bytes.data() + upper_offset, upper);
    assert(result == (address_offset == absent ? nullptr : bytes.data() + address_offset));
    ++checks;
}
}

int main()
{
    assert(ax_checksum::type2_destination(43, nullptr, 24, 17) == nullptr);
    assert(ax_checksum::type2_destination(17, nullptr, 0, 17) == nullptr);
    assert(ax_checksum::destination(nullptr, nullptr, 17) == nullptr);
    checks += 3;

    const auto valid = type2();
    expect(valid, 43, 8);
    for (const auto upper : {6, 17, 58})
        expect(type2(static_cast<std::uint8_t>(upper)), 43, 8, static_cast<std::uint8_t>(upper));
    for (unsigned upper = 0; upper <= 255; ++upper)
        expect(valid, 43, upper == 17 ? 8 : absent, static_cast<std::uint8_t>(upper));

    // Each allocation ends at the supplied extent, exposing even one-byte
    // speculative reads beyond the extension prefix to AddressSanitizer.
    for (std::size_t length = 0; length < valid.size(); ++length)
        expect(Bytes(valid.begin(), valid.begin() + length), 43, absent);
    for (unsigned length = 0; length <= 255; ++length)
    {
        auto header = valid;
        header.resize((length + 1) * 8, 0);
        header[1] = static_cast<std::uint8_t>(length);
        expect(header, 43, length == 2 ? 8 : absent);
    }
    for (unsigned segments = 0; segments <= 255; ++segments)
        expect(type2(17, static_cast<std::uint8_t>(segments)), 43, segments == 1 ? 8 : absent);
    for (unsigned offset = 4; offset < 8; ++offset)
        for (unsigned value = 0; value <= 255; ++value)
        {
            auto header = valid;
            header[offset] = static_cast<std::uint8_t>(value);
            expect(header, 43, 8);
        }

    expect(joined(type2(43), type2()), 43, 32);
    expect(joined(type2(43, 0), type2()), 43, 32);
    // A processed route no longer supplies a destination or undoes a still
    // active route earlier in the chain; a lone processed route uses the base.
    expect(joined(type2(43), type2(17, 0)), 43, 8);
    expect(joined(type2(43, 0), type2(17, 0)), 43, absent);
    expect(joined(type2(43), route(17, 0)), 43, 8);
    expect(joined(type2(43), route(17, 1)), 43, absent);
    expect(joined(route(43, 1), type2()), 43, 16);
    expect(joined(joined(type2(43), route(43, 1)), type2()), 43, 40);
    expect(joined(joined(type2(43), route(43, 1)), type2(17, 0)), 43, absent);
    for (unsigned kind = 0; kind <= 255; ++kind)
    {
        if (kind == 2)
            continue;
        auto ignored = route(17, 0);
        ignored[2] = static_cast<std::uint8_t>(kind);
        expect(joined(type2(43), ignored), 43, 8);
        ignored[3] = 1;
        expect(joined(type2(43), ignored), 43, absent);
    }

    for (const auto kind : {0, 60})
    {
        expect(joined(extension(43), valid), static_cast<std::uint8_t>(kind), 16);
        expect(joined(type2(static_cast<std::uint8_t>(kind)), extension(17)), 43, 8);
    }
    // A transport-looking octet inside its own payload is never scanned.
    expect(joined(type2(17), valid), 43, absent);
    // Stop at nested IPv4/IPv6, ESP, No Next Header, and unknown protocol IDs.
    for (const auto kind : {4, 41, 50, 59, 253})
        expect(joined(type2(static_cast<std::uint8_t>(kind)), valid), 43, absent);

    Bytes eight = valid;
    for (unsigned i = 0; i < 7; ++i)
        eight = joined(extension(i == 0 ? 43 : 60), eight);
    expect(eight, 60, 7 * 8 + 8);
    expect(joined(extension(60), eight), 60, absent);
    for (std::size_t length = 0; length < eight.size(); ++length)
        expect(Bytes(eight.begin(), eight.begin() + length), 60, absent);

    for (unsigned length = 0; length <= 255; ++length)
    {
        Bytes ah((length + 2) * 4, 0);
        ah[0] = 43;
        ah[1] = static_cast<std::uint8_t>(length);
        const bool valid_ah = ah.size() >= 16 && ah.size() % 8 == 0;
        const auto address_offset = ah.size() + 8;
        expect(joined(ah, valid), 51, valid_ah ? address_offset : absent);
    }
    auto fragment = extension(43);
    expect(joined(fragment, valid), 44, 16); // Atomic fragment.
    fragment[3] = 1;
    expect(joined(fragment, valid), 44, absent); // First, incomplete fragment.
    for (unsigned offset = 1; offset <= 8191; ++offset)
    {
        const auto field = static_cast<std::uint16_t>(offset << 3);
        fragment[2] = static_cast<std::uint8_t>(field >> 8);
        fragment[3] = static_cast<std::uint8_t>(field);
        expect(joined(fragment, valid), 44, absent);
    }

    auto bytes = packet(valid);
    expect_packet(bytes, 64, 48);
    for (std::size_t offset = 0; offset < 64; ++offset)
        expect_packet(bytes, offset, absent);
    for (std::size_t offset = 65; offset <= bytes.size(); ++offset)
        expect_packet(bytes, offset, absent);
    assert(ax_checksum::destination(bytes.data(), nullptr, 17) == nullptr);
    assert(ax_checksum::destination(nullptr, bytes.data(), 17) == nullptr);
    assert(ax_checksum::destination(bytes.data() + 16, bytes.data(), 17) == nullptr);
    checks += 3;
    for (unsigned length = 0; length < 24; ++length)
    {
        auto short_declared = bytes;
        short_declared[5] = static_cast<std::uint8_t>(length);
        expect_packet(short_declared, 64, absent);
    }
    // Resize changes the transport size after its checksum update; the old
    // IPv6 length need only contain the unchanged extension prefix here.
    bytes[5] = 24;
    expect_packet(bytes, 64, 48);
    for (unsigned version = 0; version < 16; ++version)
    {
        auto changed = bytes;
        changed[0] = static_cast<std::uint8_t>(version << 4);
        expect_packet(changed, 64, version == 6 ? 48 : absent);
    }
    auto oversized = packet(valid);
    oversized.resize(40 + 65536);
    expect_packet(oversized, oversized.size(), absent);

    // A parent IP route cannot leak into an inner IPv6 transport checksum.
    auto inner = packet(type2(), 43);
    auto nested = packet(joined(type2(41), inner), 43);
    expect_packet(nested, 40 + 24 + 64, absent);
    assert(ax_checksum::destination(nested.data() + 64, nested.data() + 128, 17)
        == nested.data() + 112);
    ++checks;

    // Reproducible randomized bounds coverage, including tiny exact extents.
    std::mt19937 random(0xa6c5d357U);
    for (unsigned trial = 0; trial < 100000; ++trial)
    {
        Bytes prefix(random() % 513);
        for (auto& byte : prefix)
            byte = static_cast<std::uint8_t>(random());
        const auto next = static_cast<std::uint8_t>(random());
        const auto upper = static_cast<std::uint8_t>(random());
        const auto* result = ax_checksum::type2_destination(next, prefix.data(), prefix.size(), upper);
        if (result)
        {
            const auto start = reinterpret_cast<std::uintptr_t>(prefix.data());
            const auto selected = reinterpret_cast<std::uintptr_t>(result);
            assert(selected >= start && selected - start <= prefix.size());
            assert(prefix.size() - (selected - start) >= 16);
            volatile std::uint8_t address_xor = 0;
            for (unsigned i = 0; i < 16; ++i)
                address_xor = static_cast<std::uint8_t>(address_xor ^ result[i]);
            (void)address_xor;
        }
        ++checks;
    }
    std::cout << checks << " IPv6 checksum destination assertions passed (100000 random spans)\n";
}
