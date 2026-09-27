#ifndef AX_ND_VALIDATION_H
#define AX_ND_VALIDATION_H

#include <cstddef>
#include <cstdint>
#include <cstring>

// Stateless RFC 4861 checks. All message spans begin at the ICMPv6 type octet;
// the caller supplies the decoded message length, excluding link-layer padding.
namespace ax_nd
{
inline std::size_t fixed_size(std::uint8_t type)
{
    switch (type)
    {
    case 133: return 8;
    case 134: return 16;
    case 135: case 136: return 24;
    case 137: return 40;
    default: return 0;
    }
}

inline bool malformed_options(std::uint8_t type, const std::uint8_t* message, std::size_t size)
{
    std::size_t offset = fixed_size(type);
    if (!offset)
        return false;
    if (!message || size < offset)
        return true;
    while (offset < size)
    {
        const std::size_t remaining = size - offset;
        if (remaining < 2)
            return true;
        const std::size_t length = static_cast<std::size_t>(message[offset + 1]) * 8;
        if (!length || length > remaining)
            return true;
        // RFC 4861 section 9 requires ignoring unknown option types. Their
        // framing still matters, and scanning must continue after them.
        offset += length;
    }
    return false;
}

inline bool unspecified(const std::uint8_t* address)
{
    for (std::size_t i = 0; i < 16; ++i)
        if (address[i])
            return false;
    return true;
}

inline bool link_local(const std::uint8_t* address)
{ return address[0] == 0xfe && (address[1] & 0xc0) == 0x80; }

inline bool solicited_node(const std::uint8_t* address)
{
    constexpr std::uint8_t prefix[13] = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff};
    return std::memcmp(address, prefix, sizeof(prefix)) == 0;
}

inline bool has_source_link_layer(std::uint8_t type, const std::uint8_t* message, std::size_t size)
{
    // Called only after the entire option chain has passed malformed_options.
    for (std::size_t offset = fixed_size(type); offset < size;
         offset += static_cast<std::size_t>(message[offset + 1]) * 8)
        if (message[offset] == 1)
            return true;
    return false;
}

inline bool invalid_semantics(std::uint8_t type, const std::uint8_t* message, std::size_t size,
    const std::uint8_t* source, const std::uint8_t* destination)
{
    if (!fixed_size(type))
        return false;
    if (!message || !source || !destination || size < fixed_size(type))
        return true;
    // Structural errors have their own rule option. Never traverse an invalid
    // chain here or report duplicate semantic alerts for the same TLV failure.
    if (malformed_options(type, message, size))
        return false;
    switch (type)
    {
    case 133:
        return unspecified(source) && has_source_link_layer(type, message, size);
    case 135:
        return message[8] == 0xff || (unspecified(source) &&
            (!solicited_node(destination) || has_source_link_layer(type, message, size)));
    case 136:
        return message[8] == 0xff || (destination[0] == 0xff && (message[4] & 0x40));
    case 137:
        return message[24] == 0xff ||
            (!link_local(message + 8) && std::memcmp(message + 8, message + 24, 16) != 0);
    default:
        return false;
    }
}
}
#endif
