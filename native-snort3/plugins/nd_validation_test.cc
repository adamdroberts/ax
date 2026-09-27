#include "nd_validation.h"

#include <array>
#include <cassert>
#include <iostream>
#include <random>
#include <vector>

int main()
{
    unsigned checks = 0;
    for (std::uint8_t type = 133; type <= 137; ++type)
    {
        const auto base = ax_nd::fixed_size(type);
        std::vector<std::uint8_t> message(base);
        message[0] = type;
        assert(!ax_nd::malformed_options(type, message.data(), message.size())); ++checks;
        assert(ax_nd::malformed_options(type, message.data(), base - 1)); ++checks;
        for (unsigned option_type : {0u, 1u, 5u, 25u, 254u, 255u})
        {
            message.resize(base + 8);
            message[base] = option_type;
            message[base + 1] = 1;
            assert(!ax_nd::malformed_options(type, message.data(), message.size())); ++checks;
            assert(ax_nd::malformed_options(type, message.data(), base + 1)); ++checks;
            message[base + 1] = 0;
            assert(ax_nd::malformed_options(type, message.data(), message.size())); ++checks;
            message[base + 1] = 2;
            assert(ax_nd::malformed_options(type, message.data(), message.size())); ++checks;
            message[base + 1] = 1;
            message.resize(base + 16);
            message[base + 8] = 1;
            message[base + 9] = 0;
            assert(ax_nd::malformed_options(type, message.data(), message.size())); ++checks;
            message[base + 9] = 1;
            assert(!ax_nd::malformed_options(type, message.data(), message.size())); ++checks;
        }
    }

    std::array<std::uint8_t, 16> source = {0xfe, 0x80}, destination = {0xfe, 0x80};
    std::array<std::uint8_t, 16> zero = {}, multicast = {0xff, 2};
    std::array<std::uint8_t, 16> solicited = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 1};
    for (std::uint8_t type : {133, 135})
    {
        const auto base = ax_nd::fixed_size(type);
        std::vector<std::uint8_t> message(base + 16);
        message[0] = type;
        message[base] = 254; message[base + 1] = 1;
        message[base + 8] = 1; message[base + 9] = 1;
        assert(ax_nd::invalid_semantics(type, message.data(), message.size(), zero.data(), solicited.data())); ++checks;
        assert(!ax_nd::invalid_semantics(type, message.data(), message.size(), source.data(), solicited.data())); ++checks;
        message[base + 8] = 254;
        assert(!ax_nd::invalid_semantics(type, message.data(), message.size(), zero.data(), solicited.data())); ++checks;
        if (type == 135)
        {
            assert(ax_nd::invalid_semantics(type, message.data(), message.size(), zero.data(), multicast.data())); ++checks;
            message[8] = 0xff;
            assert(ax_nd::invalid_semantics(type, message.data(), message.size(), source.data(), solicited.data())); ++checks;
        }
    }
    std::vector<std::uint8_t> na(24);
    assert(!ax_nd::invalid_semantics(136, na.data(), na.size(), source.data(), multicast.data())); ++checks;
    na[4] = 0x40;
    assert(ax_nd::invalid_semantics(136, na.data(), na.size(), source.data(), multicast.data())); ++checks;
    assert(!ax_nd::invalid_semantics(136, na.data(), na.size(), source.data(), destination.data())); ++checks;
    na[8] = 0xff;
    assert(ax_nd::invalid_semantics(136, na.data(), na.size(), source.data(), destination.data())); ++checks;
    std::vector<std::uint8_t> redirect(40);
    redirect[8] = 0xfe; redirect[9] = 0x80; redirect[24] = 0x20; redirect[25] = 1;
    assert(!ax_nd::invalid_semantics(137, redirect.data(), redirect.size(), source.data(), destination.data())); ++checks;
    redirect[8] = 0x20; redirect[9] = 1;
    assert(!ax_nd::invalid_semantics(137, redirect.data(), redirect.size(), source.data(), destination.data())); ++checks;
    redirect[10] = 1;
    assert(ax_nd::invalid_semantics(137, redirect.data(), redirect.size(), source.data(), destination.data())); ++checks;
    redirect[24] = 0xff;
    assert(ax_nd::invalid_semantics(137, redirect.data(), redirect.size(), source.data(), destination.data())); ++checks;

    // Deterministic bounded fuzz smoke test; compile with ASan+UBSan to exercise
    // every short length and arbitrary option chains without out-of-span reads.
    std::mt19937 random(4861);
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        std::vector<std::uint8_t> message(random() % 512);
        for (auto& byte : message) byte = random();
        const auto type = static_cast<std::uint8_t>(133 + random() % 5);
        (void)ax_nd::malformed_options(type, message.data(), message.size());
        (void)ax_nd::invalid_semantics(type, message.data(), message.size(), source.data(), destination.data());
    }
    std::cout << checks << " assertions and 100000 deterministic randomized cases passed\n";
}
