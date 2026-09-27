// SPDX-License-Identifier: GPL-2.0-only
#ifndef AX_HOME_ADDRESS_H
#define AX_HOME_ADDRESS_H

#include <cstddef>
#include <cstdint>

namespace ax_home
{
enum class Error { none, framing, budget, length, placement, alignment, duplicate, address };
struct Result
{
    Error error = Error::none;
    const std::uint8_t* source = nullptr;
    std::size_t consumed = 0;
    std::uint8_t next = 0;
    bool real_fragment = false;
};

inline bool malformed_home(Error error)
{
    return error >= Error::length;
}

// Necessary stateless exclusions only. Routability, address ownership and the
// RFC 6275 binding-cache relationship require independent endpoint state.
inline bool invalid_address(const std::uint8_t* address)
{
    if (address[0] == 0xff || (address[0] == 0xfe && (address[1] & 0xc0) == 0x80))
        return true;
    bool zero = true;
    for (unsigned i = 0; i < 15; ++i)
        zero = zero && address[i] == 0;
    return zero && address[15] <= 1;
}

// Walk the capture-checked payload of one selected IPv6 header, or its exact
// extension prefix. Unknown/upper-layer data and ESP are opaque. Noninitial
// fragments stop traversal. Eight extensions is the supplied profile's local
// resource limit, not an RFC extension-count restriction.
inline Result chain(std::uint8_t next, const std::uint8_t* payload, std::size_t size)
{
    Result result;
    result.next = next;
    if (!payload && size)
    {
        result.error = Error::framing;
        return result;
    }
    bool fragment_or_ah = false;
    unsigned extensions = 0;
    while (true)
    {
        next = result.next;
        if (next != 0 && next != 60 && next != 43 && next != 51 && next != 44)
            return result;
        if (extensions++ == 8)
        {
            result.error = Error::budget;
            return result;
        }
        const auto remaining = size - result.consumed;
        if (remaining < 8)
        {
            result.error = Error::framing;
            return result;
        }
        const auto* header = payload + result.consumed;
        const std::size_t length = next == 44 ? 8 : next == 51 ?
            (static_cast<std::size_t>(header[1]) + 2) * 4 :
            (static_cast<std::size_t>(header[1]) + 1) * 8;
        if (length > remaining || (next == 51 && (length < 16 || length % 8)))
        {
            result.error = Error::framing;
            return result;
        }
        if (next == 43 && result.source)
        {
            result.error = Error::placement; // HAO must follow Routing.
            return result;
        }
        if (next == 44 || next == 51)
            fragment_or_ah = true;
        if (next == 0 || next == 60)
        {
            for (std::size_t option = 2; option < length; )
            {
                const auto type = header[option];
                if (type == 0)
                {
                    ++option;
                    continue;
                }
                if (length - option < 2 || header[option + 1] > length - option - 2)
                {
                    result.error = type == 0xc9 ? Error::length : Error::framing;
                    return result;
                }
                const auto bytes = header[option + 1];
                if (type == 0xc9)
                {
                    if (bytes != 16)
                        result.error = Error::length;
                    else if (next != 60 || fragment_or_ah)
                        result.error = Error::placement;
                    else if (option % 8 != 6)
                        result.error = Error::alignment;
                    else if (result.source)
                        result.error = Error::duplicate;
                    else if (invalid_address(header + option + 2))
                        result.error = Error::address;
                    if (result.error != Error::none)
                        return result;
                    result.source = header + option + 2;
                }
                option += 2 + bytes;
            }
        }
        result.next = header[0];
        result.consumed += length;
        if (next == 44)
        {
            const unsigned field = (static_cast<unsigned>(header[2]) << 8) | header[3];
            result.real_fragment = result.real_fragment || (field & 0xfff9) != 0;
            if (field & 0xfff8)
                return result;
        }
    }
}

// Decode/update callers guarantee these pointers belong to the same packet.
// Bounds end exactly at the upper-layer boundary; payload lookalikes cannot
// become source addresses. The IPv6 payload length may be stale during resize
// but must still cover the prefix. This does not rewrite IP addresses or flow
// identity, authenticate bindings, process AH/ESP, or inspect response buffers.
inline const std::uint8_t* source(const std::uint8_t* ip6,
    const std::uint8_t* upper, std::uint8_t protocol)
{
    if (!ip6 || !upper)
        return nullptr;
    const auto start = reinterpret_cast<std::uintptr_t>(ip6);
    const auto finish = reinterpret_cast<std::uintptr_t>(upper);
    if (finish < start || finish - start < 40 || finish - start > 40 + 65535)
        return nullptr;
    const auto size = static_cast<std::size_t>(finish - start - 40);
    const auto declared = (static_cast<unsigned>(ip6[4]) << 8) | ip6[5];
    if ((ip6[0] >> 4) != 6 || size > declared)
        return nullptr;
    const auto result = chain(ip6[6], ip6 + 40, size);
    return result.error == Error::none && !result.real_fragment &&
        result.consumed == size && result.next == protocol ? result.source : nullptr;
}
}
#endif
