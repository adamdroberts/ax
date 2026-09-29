#include "tcp_sack_state.h"

#include <cassert>
#include <iostream>
#include <random>

#ifdef NDEBUG
#error "TCP SACK state tests require assertions"
#endif

int main()
{
    const std::uint8_t permit[] = {4, 2, 1, 1};
    const std::uint8_t opaque[] = {200, 4, 4, 2};
    const std::uint8_t hidden[] = {0, 0, 4, 2};
    const std::uint8_t sack[] = {5, 10, 0, 0, 0, 10, 0, 0, 0, 20, 1, 1};
    assert(ax_tcp::sack_options(permit, 4, true).permitted);
    assert(ax_tcp::sack_options(permit, 4, false).malformed);
    assert(!ax_tcp::sack_options(opaque, 4, true).permitted);
    assert(ax_tcp::sack_options(hidden, 4, true).malformed);
    assert(ax_tcp::sack_options(sack, 12, false).sack);
    assert(!ax_tcp::sack_options(nullptr, 0, false).sack);
    std::mt19937 random(20189293);
    for (unsigned iteration = 0; iteration < 100000; ++iteration)
    {
        ax_tcp::SackNegotiation state, independent;
        const std::uint32_t first = random(), second = random();
        const unsigned mask = random() & 3;
        const unsigned start = random() & 1;
        assert(!state.permits(0) && !state.permits(1) && !state.permits(2));
        // A single admitted offer cannot establish the observed handshake.
        state.observe(start, start ? second : first, mask & (1 << start), true);
        assert(!state.permits(0) && !state.permits(1));
        state.observe(1-start, start ? first : second, mask & (1 << (1-start)), true);
        assert(state.permits(0) == bool(mask & 2));
        assert(state.permits(1) == bool(mask & 1));
        for (unsigned denied = 0; denied < 8; ++denied)
            state.observe(random() & 1, random(), random() & 1, false);
        assert(state.permits(0) == bool(mask & 2));
        assert(state.permits(1) == bool(mask & 1));
        // Accepted retransmissions can narrow ambiguous grants, never restore
        // permission absent from one of the admitted offers for this flow.
        const unsigned revoke = random() & 1;
        state.observe(revoke, revoke ? second : first, false, true);
        assert(!state.permits(1-revoke));
        state.observe(revoke, revoke ? second : first, true, true);
        assert(!state.permits(1-revoke));
        // Invalid direction values and unrelated flows cannot grant permission.
        state.observe(2 + random() % 10, random(), true, true);
        assert(!state.permits(1-revoke));
        assert(!independent.permits(0) && !independent.permits(1));
    }
    std::cout << "100000 deterministic randomized connection histories passed\n";
}
