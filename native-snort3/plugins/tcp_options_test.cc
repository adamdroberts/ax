#include "tcp_options.h"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <random>
#include <vector>

#ifdef NDEBUG
#error "TCP option tests require assertions"
#endif

int main()
{
    std::size_t checks = 0;
    auto expect = [&](const std::vector<std::uint8_t>& data, bool syn, bool invalid)
    {
        assert(ax_tcp::invalid_options(data.data(), data.size(), syn) == invalid);
        ++checks;
    };
    assert(!ax_tcp::invalid_options(nullptr, 0, false)); ++checks;
    assert(ax_tcp::invalid_options(nullptr, 4, true)); ++checks;
    std::uint8_t byte = 0;
    assert(ax_tcp::invalid_options(&byte, std::numeric_limits<std::size_t>::max(), true)); ++checks;
    for (unsigned size = 0; size <= 64; ++size)
        expect(std::vector<std::uint8_t>(size, 1), true, size > 40 || size % 4);
    for (unsigned end = 0; end < 40; ++end)
    {
        std::vector<std::uint8_t> data(40, 0);
        std::fill(data.begin(), data.begin() + end, 1);
        expect(data, true, false);
        for (unsigned at = end + 1; at < 40; ++at)
            for (unsigned value = 1; value <= 255; ++value)
            {
                data[at] = value;
                expect(data, true, true);
                data[at] = 0;
            }
    }
    for (unsigned kind = 2; kind <= 255; ++kind)
        for (unsigned length = 0; length <= 255; ++length)
            for (unsigned span = 4; span <= 40; span += 4)
                for (bool syn : {false, true})
                {
                    std::vector<std::uint8_t> data(span, 0);
                    data[0] = kind; data[1] = length;
                    bool valid = length >= 2 && length <= span;
                    if (kind == 2) valid = valid && length == 4 && syn;
                    if (kind == 3) valid = valid && length == 3;
                    if (kind == 4) valid = valid && length == 2 && syn;
                    if (kind == 5) valid = valid && (length == 10 || length == 18 || length == 26 || length == 34);
                    if (kind == 8) valid = valid && length == 10;
                    expect(data, syn, !valid);
                }
    for (unsigned scale = 0; scale <= 255; ++scale)
        expect({3,3,static_cast<std::uint8_t>(scale),0}, true, false); // Receiver clamps >14.
    expect({1,2,4,5,180,1,1,0}, true, false); // Unaligned MSS.
    expect({200,4,0,255,4,2,1,1}, true, false); // Unknown content is not parsed as options.
    expect({200,4,0,255,4,2,1,1}, false, true);
    expect({1,1,1,200}, true, true); // Length byte cannot come from payload.
    expect({2,4,5,180,2,4,5,180}, true, false); // No invented option uniqueness rule.
    std::mt19937 random(92932018);
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        const std::size_t size = random() % 65;
        std::vector<std::uint8_t> data(size);
        for (auto& value : data) value = random();
        const bool syn = random() & 1;
        const bool invalid = ax_tcp::invalid_options(data.data(), size, syn);
        auto extended = data;
        extended.resize(size + 32, 255);
        assert(ax_tcp::invalid_options(extended.data(), size, syn) == invalid);
        if (size > 40 || size % 4) assert(invalid);
    }
    std::cout << checks << " assertions and 100000 deterministic randomized cases passed\n";
}
