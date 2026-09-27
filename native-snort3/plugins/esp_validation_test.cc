#include "esp_validation.h"

#include <cassert>
#include <iostream>
#include <random>
#include <vector>

int main()
{
    unsigned checks = 0;
    auto expect = [&](std::uint8_t next, const std::vector<std::uint8_t>& payload,
        bool ipv6, bool invalid, std::uint16_t fragment_offset = 0, bool more = false)
    {
        assert(ax_esp::invalid_visible_framing(next, payload.data(), payload.size(),
            ipv6, fragment_offset, more) == invalid);
        ++checks;
    };
    auto esp = [](std::size_t size, unsigned spi_byte = 3)
    {
        std::vector<std::uint8_t> bytes(size);
        if (size > spi_byte)
            bytes[spi_byte] = 1;
        return bytes;
    };
    for (bool ipv6 : {false, true})
        for (std::size_t size = 0; size <= 64; ++size)
            for (unsigned spi_byte = 0; spi_byte < 4; ++spi_byte)
            {
                expect(50, esp(size, spi_byte), ipv6, size < 10);
                expect(50, std::vector<std::uint8_t>(size), ipv6, true);
                if (!ipv6)
                {
                    expect(50, esp(size, spi_byte), false, false, 0, true);
                    expect(50, std::vector<std::uint8_t>(size), false, size >= 4, 0, true);
                    expect(50, std::vector<std::uint8_t>(size), false, false, 8, true);
                    expect(50, std::vector<std::uint8_t>(size), false, false, 65528, false);
                }
            }

    // Every remaining IPv4 protocol is outside this ESP/AH parser. Do not
    // accidentally apply IPv6 extension-header formats to an IPv4 payload.
    for (unsigned protocol = 0; protocol <= 255; ++protocol)
        if (protocol != 50 && protocol != 51)
            expect(protocol, {}, false, false);
    for (unsigned protocol = 0; protocol <= 255; ++protocol)
        if (protocol != 0 && protocol != 43 && protocol != 44 &&
            protocol != 50 && protocol != 51 && protocol != 60)
            expect(protocol, {}, true, false);

    auto prepend = [](std::vector<std::uint8_t> header,
        const std::vector<std::uint8_t>& body)
    {
        header.insert(header.end(), body.begin(), body.end());
        return header;
    };
    for (unsigned type : {0u, 43u, 60u})
        for (unsigned units = 0; units <= 255; ++units)
        {
            std::vector<std::uint8_t> header((units + 1) * 8);
            header[0] = 50; header[1] = units;
            expect(type, prepend(header, esp(10)), true, false);
            expect(type, prepend(header, esp(9)), true, true);
            expect(type, prepend(header, std::vector<std::uint8_t>(10)), true, true);
            expect(type, header, true, true);
            header.pop_back(); expect(type, header, true, true);
        }
    for (bool ipv6 : {false, true})
        for (unsigned size : {8u, 12u, 16u, 20u, 24u})
        {
            std::vector<std::uint8_t> ah(size);
            ah[0] = 50; ah[1] = size / 4 - 2;
            const bool malformed = size < 12 || (ipv6 && size % 8);
            expect(51, prepend(ah, esp(10)), ipv6, malformed);
            expect(51, prepend(ah, esp(9)), ipv6, true);
            if (!ipv6)
                expect(51, prepend(ah, esp(8)), false, malformed, 0, true);
        }

    // IPv4 routers may split an AH-protected packet before its complete AH
    // or ESP fixed header. The original first fragment is deferred; the
    // reassembled packet still undergoes the complete framing/SPI checks.
    std::vector<std::uint8_t> split_ah(8);
    split_ah[0] = 50; split_ah[1] = 2; // Sixteen-byte AH, first half present.
    expect(51, split_ah, false, false, 0, true);
    expect(51, split_ah, false, true);
    expect(51, split_ah, true, true);
    split_ah.resize(16);
    expect(51, prepend(split_ah, esp(10)), false, false);
    expect(51, prepend(split_ah, std::vector<std::uint8_t>(10)), false, true);

    std::vector<std::uint8_t> ah12(12);
    ah12[0] = 50; ah12[1] = 1;
    expect(51, prepend(ah12, esp(4)), false, false, 0, true);
    expect(51, prepend(ah12, esp(4)), false, true);
    expect(51, prepend(ah12, std::vector<std::uint8_t>(4)), false, true, 0, true);
    expect(51, prepend(ah12, esp(10)), false, false);
    for (unsigned length = 0; length < 16; ++length)
    {
        const auto incomplete = std::vector<std::uint8_t>(split_ah.begin(), split_ah.begin() + length);
        expect(51, incomplete, false, false, 0, true);
        expect(51, incomplete, false, true);
    }
    // A declared AH length that omits mandatory fixed fields is never a
    // legitimate split. Reject as soon as the length byte is visible.
    for (unsigned length = 2; length <= 8; ++length)
    {
        std::vector<std::uint8_t> malformed_ah(length);
        malformed_ah[0] = 50;
        expect(51, malformed_ah, false, true, 0, true);
    }

    // First-fragment controls must remain accepted with exactly eight ESP
    // bytes. Noninitial fragments contain arbitrary data, not another SPI.
    for (unsigned offset : {0u, 8u, 256u, 65528u})
        for (bool more : {false, true})
            for (std::size_t size = 0; size <= 16; ++size)
            {
                std::vector<std::uint8_t> fragment(8);
                fragment[0] = 50; fragment[2] = offset >> 8;
                fragment[3] = (offset & 0xff) | more;
                const bool incomplete = !offset && size < (more ? 8u : 10u);
                expect(44, prepend(fragment, esp(size)), true, incomplete);
                expect(44, prepend(fragment, std::vector<std::uint8_t>(size)), true, !offset);
                fragment[0] = 60;
                std::vector<std::uint8_t> destination(8);
                destination[0] = 50;
                expect(44, prepend(fragment, prepend(destination, esp(size))), true, incomplete);
            }
    for (std::size_t size = 0; size < 8; ++size)
        expect(44, std::vector<std::uint8_t>(size), true, true);
    std::vector<std::uint8_t> fragment(8);
    fragment[0] = 50; fragment[3] = 1;
    std::vector<std::uint8_t> before(8);
    before[0] = 44;
    expect(60, prepend(before, prepend(fragment, esp(8))), true, false);
    expect(60, prepend(before, prepend(fragment, esp(7))), true, true);
    for (unsigned count : {8u, 9u})
    {
        std::vector<std::uint8_t> chain(count * 8);
        for (unsigned index = 0; index < count; ++index)
            chain[index * 8] = index + 1 == count ? 50 : 60;
        expect(60, prepend(chain, esp(10)), true, count > 8);
    }
    assert(ax_esp::invalid_visible_framing(50, nullptr, 10, true)); ++checks;
    assert(ax_esp::invalid_visible_framing(50, nullptr, 0, true)); ++checks;
    assert(!ax_esp::invalid_visible_framing(50, nullptr, 10, false, 8)); ++checks;

    std::mt19937 random(4303);
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        std::vector<std::uint8_t> payload(random() % 512);
        for (auto& byte : payload) byte = random();
        (void)ax_esp::invalid_visible_framing(random(), payload.data(), payload.size(),
            random() & 1, random() & 1 ? 0 : random(), random() & 1);
    }
    std::cout << checks << " ESP framing assertions and 100000 deterministic randomized cases passed\n";
}
