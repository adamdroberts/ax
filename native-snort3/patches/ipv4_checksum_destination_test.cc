#include "ipv4_checksum_destination.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <vector>

static std::size_t checks;
static void require(bool condition)
{
    ++checks;
    if (!condition)
        std::abort();
}

static std::vector<std::uint8_t> option(unsigned type, unsigned count, unsigned pointer,
    unsigned prefix = 0)
{
    std::vector<std::uint8_t> data(prefix, 1);
    data.insert(data.end(), {static_cast<std::uint8_t>(type),
        static_cast<std::uint8_t>(3 + count * 4), static_cast<std::uint8_t>(pointer)});
    for (unsigned i = 0; i < count; ++i)
        data.insert(data.end(), {203, 0, 113, static_cast<std::uint8_t>(i + 1)});
    while (data.size() % 4)
        data.push_back(0);
    return data;
}

static std::vector<std::uint8_t> packet(const std::vector<std::uint8_t>& options,
    unsigned between = 0)
{
    std::vector<std::uint8_t> data(20, 0);
    data[0] = static_cast<std::uint8_t>(0x45 + options.size() / 4);
    data.insert(data.end(), options.begin(), options.end());
    data.resize(data.size() + between + 8);
    data[2] = static_cast<std::uint8_t>(data.size() >> 8);
    data[3] = static_cast<std::uint8_t>(data.size());
    data[16] = 198; data[17] = 51; data[18] = 100; data[19] = 20;
    return data;
}

int main()
{
    using ax_checksum::ipv4_destination;
    using ax_checksum::ipv4_route_destination;
    const std::uint8_t* final = nullptr;
    require(ipv4_route_destination(nullptr, 0, final) && !final);
    require(!ipv4_route_destination(nullptr, 4, final));
    for (unsigned type : {131u, 137u})
        for (unsigned count = 0; count <= 9; ++count)
            for (unsigned prefix = 0; prefix < 4 && prefix + 3 + count * 4 <= 40; ++prefix)
                for (unsigned pointer = 0; pointer < 256; ++pointer)
                {
                    const auto data = option(type, count, pointer, prefix);
                    const unsigned length = 3 + count * 4;
                    const bool active = pointer <= length;
                    const bool valid = pointer >= 4 && (!active || pointer % 4 == 0);
                    require(ipv4_route_destination(data.data(), data.size(), final) == valid);
                    if (valid)
                        require(final == (active ? data.data() + prefix + length - 4 : nullptr));
                    auto network = packet(data, 12); // Intervening AH is not an options span.
                    const auto* selected = ipv4_destination(network.data(), network.data() + 20 + data.size() + 12);
                    require(selected == (valid ? network.data() +
                        (active ? 20 + prefix + length - 4 : 16) : nullptr));
                }

    for (unsigned length = 0; length <= 41; ++length)
    {
        std::vector<std::uint8_t> data(40, 1);
        data[0] = 131; data[1] = length; data[2] = 4;
        if (length < 40)
            data[std::max(3u, length)] = 0;
        const bool valid = length >= 3 && length <= 40 && (length - 3) % 4 == 0;
        require(ipv4_route_destination(data.data(), data.size(), final) == valid);
    }
    auto duplicate = option(131, 1, 4);
    duplicate.pop_back();
    const auto second = option(137, 1, 4);
    duplicate.insert(duplicate.end(), second.begin(), second.end());
    duplicate.push_back(0);
    require(!ipv4_route_destination(duplicate.data(), duplicate.size(), final));

    // Unknown option data and bytes after EOL are never interpreted as routes.
    std::vector<std::uint8_t> opaque = {158, 10, 131, 7, 4, 203, 0, 113, 9, 0, 0, 0};
    require(ipv4_route_destination(opaque.data(), opaque.size(), final) && !final);
    opaque[0] = 0;
    require(ipv4_route_destination(opaque.data(), opaque.size(), final) && !final);
    auto network = packet({});
    network[20] = 131; network[21] = 7; network[22] = 4;
    require(ipv4_destination(network.data(), network.data() + 20) == network.data() + 16);
    require(!ipv4_destination(nullptr, network.data()));
    require(!ipv4_destination(network.data(), nullptr));
    for (unsigned distance = 0; distance < 20; ++distance)
        require(!ipv4_destination(network.data(), network.data() + distance));
    require(!ipv4_destination(network.data() + 1, network.data()));
    for (unsigned ihl = 0; ihl < 16; ++ihl)
    {
        network[0] = 0x40 | ihl;
        require((ipv4_destination(network.data(), network.data() + 20) != nullptr) == (ihl == 5));
    }
    network[0] = 0x65;
    require(!ipv4_destination(network.data(), network.data() + 20));
    network[0] = 0x45; network[3] = 19;
    require(!ipv4_destination(network.data(), network.data() + 20));
    std::vector<std::uint8_t> huge(65537, 0);
    huge[0] = 0x45; huge[2] = 255; huge[3] = 255;
    require(!ipv4_destination(huge.data(), huge.data() + 65536));
    require(ipv4_destination(huge.data(), huge.data() + 65535) == huge.data() + 16);

    std::mt19937 generator(0x4a785eed);
    for (unsigned trial = 0; trial < 100000; ++trial)
    {
        const auto size = generator() % 45;
        std::vector<std::uint8_t> data(size);
        for (auto& value : data)
            value = static_cast<std::uint8_t>(generator());
        const auto before = data;
        const bool valid = ipv4_route_destination(data.data(), data.size(), final);
        if (valid && final)
            require(final >= data.data() && final + 4 <= data.data() + data.size());
        require(data == before);
    }
    std::cout << checks << " assertions; 100000 randomized spans\n";
}
