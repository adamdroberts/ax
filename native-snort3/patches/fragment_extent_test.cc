// SPDX-License-Identifier: GPL-2.0-only
#include "fragment_extent.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <vector>

using State = ax_fragment::Extent;
static size_t assertions = 0;
static void check(bool value)
{
    ++assertions;
    if (!value)
    {
        std::fprintf(stderr, "assertion %zu failed\n", assertions);
        std::abort();
    }
}
struct Wire
{
    uint16_t offset, size;
    bool more;
};
static bool oracle(const std::vector<Wire>& saved, Wire next)
{
    const uint64_t end = static_cast<uint64_t>(next.offset) + next.size;
    if (!next.size || end > 65535)
        return false;
    for (const auto& old : saved)
    {
        const uint64_t old_end = static_cast<uint64_t>(old.offset) + old.size;
        if ((!old.more && !next.more && old_end != end) ||
            (!old.more && next.more && end >= old_end) ||
            (old.more && !next.more && old_end >= end))
            return false;
    }
    return true;
}
static bool apply(State& state, std::vector<Wire>& saved, Wire next)
{
    const State before = state;
    const bool expected = oracle(saved, next);
    check(ax_fragment::observe_extent(state, next.offset, next.size, next.more) == expected);
    if (!expected)
        check(state.more_end == before.more_end && state.final_end == before.final_end &&
            state.final_seen == before.final_seen);
    else
        saved.push_back(next);
    return expected;
}
struct Node
{
    uint32_t offset, size;
    Node* next;
};
static bool coverage_oracle(const std::vector<Node>& nodes, unsigned end)
{
    if (!end || end > 65535 || nodes.empty())
        return false;
    std::vector<unsigned> bytes(end, 0);
    unsigned last = 0;
    for (const auto& node : nodes)
    {
        if (!node.size || node.offset < last || node.offset > end || node.size > end - node.offset)
            return false;
        for (unsigned i = node.offset; i < node.offset + node.size; ++i)
            ++bytes[i];
        last = node.offset + node.size;
    }
    return std::all_of(bytes.begin(), bytes.end(), [](unsigned count) { return count == 1; });
}
int main()
{
    static_assert(std::is_trivial<State>::value, "Native tracker requires trivial storage");
    std::vector<Wire> candidates;
    for (unsigned offset = 0; offset <= 64; offset += 8)
        for (unsigned size = 0; size <= 32; ++size)
            for (bool more : {false, true})
                candidates.push_back({static_cast<uint16_t>(offset), static_cast<uint16_t>(size), more});
    for (auto first : candidates)
        for (auto second : candidates)
        {
            State state{};
            std::vector<Wire> saved;
            if (apply(state, saved, first))
                apply(state, saved, second);
        }
    for (unsigned end = 65528; end <= 65542; ++end)
        for (unsigned offset : {0u, 24u, 32768u, 65528u})
            if (end >= offset && end - offset <= 65535)
                for (bool more : {false, true})
                {
                    State state{};
                    std::vector<Wire> saved;
                    apply(state, saved, {static_cast<uint16_t>(offset), static_cast<uint16_t>(end - offset), more});
                }
    for (unsigned offset = 0; offset <= 65528; offset += 8)
        for (unsigned size : {0u, 1u, 7u, 8u, 24u, 32768u, 65535u})
        {
            State state{};
            std::vector<Wire> saved;
            apply(state, saved, {static_cast<uint16_t>(offset), static_cast<uint16_t>(size), false});
        }
    uint32_t seed = 0x783192a5;
    auto random = [&]() { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; };
    for (unsigned trial = 0; trial < 100000; ++trial)
    {
        State state{};
        std::vector<Wire> saved;
        for (unsigned i = 0; i < 16; ++i)
            if (!apply(state, saved, {static_cast<uint16_t>(random()),
                    static_cast<uint16_t>(random()), bool(random() & 1)}))
                break;
        const unsigned end = 1 + random() % 128;
        std::vector<Node> nodes(1 + random() % 8);
        for (size_t i = 0; i < nodes.size(); ++i)
            nodes[i] = {random() % 128, random() % 32,
                i + 1 < nodes.size() ? &nodes[i + 1] : nullptr};
        std::sort(nodes.begin(), nodes.end(), [](const Node& a, const Node& b) { return a.offset < b.offset; });
        for (size_t i = 0; i < nodes.size(); ++i)
            nodes[i].next = i + 1 < nodes.size() ? &nodes[i + 1] : nullptr;
        check(ax_fragment::complete_ranges(nodes.data(), end) == coverage_oracle(nodes, end));
    }
    for (unsigned split = 8; split < 65535; split += 8)
    {
        std::array<Node, 2> nodes{{{0, split, nullptr}, {split, 65535 - split, nullptr}}};
        nodes[0].next = &nodes[1];
        check(ax_fragment::complete_ranges(nodes.data(), 65535));
        ++nodes[1].offset; // hole with the same byte total
        check(!ax_fragment::complete_ranges(nodes.data(), 65535));
        nodes[1].offset -= 2; // overlap with the same byte total
        check(!ax_fragment::complete_ranges(nodes.data(), 65535));
    }
    Node cycle{0, 8, nullptr}; cycle.next = &cycle;
    check(!ax_fragment::complete_ranges(&cycle, 16));
    cycle.size = 0;
    check(!ax_fragment::complete_ranges(&cycle, 16));
    check(!ax_fragment::complete_ranges<Node>(nullptr, 16));
    check(!ax_fragment::complete_ranges(&cycle, 65536));
    std::printf("{\"assertions\":%zu,\"random_sequences\":100000,\"random_coverage_lists\":100000}\n", assertions);
}
