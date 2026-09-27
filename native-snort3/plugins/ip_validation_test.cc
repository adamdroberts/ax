#include "ip_validation.h"

#include <cassert>
#include <iostream>
#include <random>
#include <vector>

int main()
{
    unsigned checks = 0;
    // Exhaust every representable Payload Len and every possible size of the
    // supplied AH span, including absent, truncated and trailing bytes. The
    // expected result is independent of unrelated header and payload values.
    for (unsigned length = 0; length <= 255; ++length)
    {
        const std::size_t declared = (length + 2) * 4;
        for (std::size_t size = 0; size <= 1032; ++size)
        {
            std::vector<std::uint8_t> header(size, 0xa5);
            if (size > 1)
                header[1] = length;
            for (bool ipv6 : {false, true})
            {
                const bool valid = size >= 12 && size == declared &&
                    (!ipv6 || size % 8 == 0);
                assert(ax_ip::invalid_ah_header(header.data(), size, ipv6) == !valid);
                ++checks;
            }
        }
    }
    for (std::size_t size : {0u, 1u, 2u, 8u, 12u, 16u, 1028u})
        for (bool ipv6 : {false, true})
        {
            assert(ax_ip::invalid_ah_header(nullptr, size, ipv6));
            ++checks;
        }
    using Error = ax_ip::FirstFragmentError;
    auto expect = [&](std::uint8_t next, const std::vector<std::uint8_t>& bytes, Error error)
    {
        assert(ax_ip::first_fragment_error(next, bytes.data(), bytes.size()) == error);
        assert(ax_ip::invalid_first_fragment(next, bytes.data(), bytes.size()) == (error != Error::none));
        checks += 2;
    };
    for (auto protocol : {17u, 50u, 58u})
    {
        const unsigned minimum = protocol == 58 ? 4 : 8;
        for (unsigned length = 0; length <= 16; ++length)
            expect(protocol, std::vector<std::uint8_t>(length),
                length < minimum ? Error::truncated : Error::none);
    }
    for (unsigned tcp_words = 0; tcp_words <= 15; ++tcp_words)
        for (unsigned length = 0; length <= 64; ++length)
        {
            std::vector<std::uint8_t> tcp(length);
            if (length > 12)
                tcp[12] = tcp_words << 4;
            expect(6, tcp, length < 20 ? Error::truncated : tcp_words < 5 ? Error::malformed :
                length < tcp_words * 4 ? Error::truncated : Error::none);
        }
    for (unsigned ipv4_words = 0; ipv4_words <= 15; ++ipv4_words)
        for (unsigned length = 0; length <= 64; ++length)
        {
            std::vector<std::uint8_t> ip(length);
            if (length)
                ip[0] = 0x40 | ipv4_words;
            expect(4, ip, length < 20 ? Error::truncated : ipv4_words < 5 ? Error::malformed :
                length < ipv4_words * 4 ? Error::truncated : Error::none);
        }
    std::vector<std::uint8_t> ip4(20, 0x65), ip6(40, 0x60);
    expect(4, ip4, Error::malformed);
    expect(41, ip6, Error::none);
    ip6.pop_back(); expect(41, ip6, Error::truncated);
    ip6.push_back(0); ip6[0] = 0x40; expect(41, ip6, Error::malformed);

    // The six reproduced first-fragment truncations: Destination/UDP,
    // Destination/Destination/UDP and Destination/AH/UDP. Each full header
    // chain control succeeds, and later payload bytes do not affect framing.
    const std::vector<std::uint8_t> destination_udp = {17, 0, 0, 0, 0, 0, 0, 0};
    auto destination_destination = destination_udp;
    destination_destination[0] = 60;
    destination_destination.insert(destination_destination.end(), destination_udp.begin(), destination_udp.end());
    auto destination_ah = destination_udp;
    destination_ah[0] = 51;
    destination_ah.resize(24);
    destination_ah[8] = 17; destination_ah[9] = 2;
    for (auto chain : {destination_udp, destination_destination, destination_ah})
    {
        const auto header_size = chain.size();
        chain.resize(header_size + 8);
        for (std::size_t length = 0; length < chain.size(); ++length)
            expect(60, std::vector<std::uint8_t>(chain.begin(), chain.begin() + length), Error::truncated);
        expect(60, chain, Error::none);
        chain.resize(chain.size() + 64, 0xff);
        expect(60, chain, Error::none);
    }
    for (unsigned type : {43u, 60u})
        for (unsigned units = 0; units <= 255; ++units)
        {
            std::vector<std::uint8_t> extension((units + 1) * 8);
            extension[0] = 59; extension[1] = units;
            expect(type, extension, Error::none);
            extension.pop_back(); expect(type, extension, Error::truncated);
        }
    for (unsigned size : {8u, 12u, 16u, 20u, 24u})
    {
        std::vector<std::uint8_t> ah(size);
        ah[0] = 59; ah[1] = size / 4 - 2;
        expect(51, ah, size < 12 || size % 8 ? Error::malformed : Error::none);
        ah.pop_back(); expect(51, ah, Error::truncated);
    }
    for (unsigned count : {8u, 9u})
    {
        std::vector<std::uint8_t> extensions(count * 8);
        for (unsigned index = 0; index < count; ++index)
            extensions[index * 8] = index + 1 == count ? 59 : 60;
        expect(60, extensions, count == 8 ? Error::none : Error::extension_limit);
    }
    expect(0, {}, Error::malformed);
    expect(44, {}, Error::nested_fragment);
    expect(59, {}, Error::none);
    for (unsigned protocol = 0; protocol <= 255; ++protocol)
    {
        switch (protocol)
        {
        case 0: case 4: case 6: case 17: case 41: case 43: case 44:
        case 50: case 51: case 58: case 59: case 60: continue;
        }
        expect(protocol, {}, Error::unsupported_protocol);
    }
    assert(ax_ip::first_fragment_error(17, nullptr, 8) == Error::malformed); ++checks;
    assert(ax_ip::first_fragment_error(59, nullptr, 0) == Error::none); ++checks;
    std::mt19937 random(7112);
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        std::vector<std::uint8_t> fragment(random() % 512);
        for (auto& byte : fragment) byte = random();
        (void)ax_ip::first_fragment_error(random(), fragment.data(), fragment.size());
    }
    std::cout << checks << " IP framing assertions and 100000 deterministic randomized cases passed\n";
}
