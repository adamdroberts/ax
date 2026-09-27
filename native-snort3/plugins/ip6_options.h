#ifndef AX_IP6_OPTIONS_H
#define AX_IP6_OPTIONS_H

#include "ip_validation.h"
#include "home_address.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace ax_ip
{
enum class IP6OptionError
{
    none,
    header_length,
    truncated_option,
    option_overrun,
    router_alert_placement,
    router_alert_length,
    router_alert_alignment,
    duplicate_router_alert,
    jumbo_placement,
    jumbo_length,
    jumbo_alignment,
    jumbo_base_length,
    jumbo_small_payload,
    jumbo_fragment,
    missing_jumbo,
    // Refuse ambiguous repeated length declarations as an explicit local
    // inspection policy; RFC 2675 does not state a duplicate-option rule.
    duplicate_jumbo,
};

// Check one exact Hop-by-Hop/Destination Options extension, including its
// Next Header and Hdr Ext Len octets. The caller establishes capture bounds,
// the containing IPv6 header, and whether that packet has a Fragment header.
// The encoded header length bounds this walk to 2048 octets.
//
// RFC 8200 section 4.2 supplies TLV framing; RFC 2711 section 2.1 supplies
// Router Alert format/placement/alignment/uniqueness; RFC 2675 sections 2-3
// supply Jumbo format and IPv6-header relationships. Rejecting malformed
// sender formats here is the sensor's strict policy, not a claim that every
// destination is required to discard all of these cases.
//
// Home Address relationships are checked across the complete chain below.
// Other types are walked without interpreting their values. The action bits
// apply only when the processing endpoint does not recognize the entire option
// type; this sensor does not know its endpoints' supported extensions. Likewise,
// unknown Router Alert values are ignored as RFC 2711 section 2.2 requires.
// PadN data, reserved option contents, Jumbo actual-payload-length verification,
// endpoint processing, and ICMP error generation are outside this helper.
inline IP6OptionError ip6_options_error(const std::uint8_t* header,
    std::size_t size, bool hop_by_hop, std::uint16_t ipv6_payload_length,
    bool fragment_present)
{
    if (!header || size < 8 ||
        size != (static_cast<std::size_t>(header[1]) + 1) * 8)
        return IP6OptionError::header_length;

    bool router_alert_seen = false;
    bool jumbo_seen = false;
    std::size_t offset = 2;
    while (offset < size)
    {
        const auto type = header[offset];
        if (type == 0) // Pad1 has neither a length nor a data field.
        {
            ++offset;
            continue;
        }
        if (size - offset < 2)
            return IP6OptionError::truncated_option;
        const std::size_t length = header[offset + 1];
        if (length > size - offset - 2)
            return IP6OptionError::option_overrun;

        if (type == 5) // Router Alert: full eight-bit option type, not low bits.
        {
            if (!hop_by_hop)
                return IP6OptionError::router_alert_placement;
            if (length != 2)
                return IP6OptionError::router_alert_length;
            if (offset % 2 != 0)
                return IP6OptionError::router_alert_alignment;
            if (router_alert_seen)
                return IP6OptionError::duplicate_router_alert;
            router_alert_seen = true;
        }
        else if (type == 0xc2) // Jumbo Payload.
        {
            if (!hop_by_hop)
                return IP6OptionError::jumbo_placement;
            if (length != 4)
                return IP6OptionError::jumbo_length;
            if (offset % 4 != 2)
                return IP6OptionError::jumbo_alignment;
            if (ipv6_payload_length != 0)
                return IP6OptionError::jumbo_base_length;
            const auto length32 = (static_cast<std::uint32_t>(header[offset + 2]) << 24)
                | (static_cast<std::uint32_t>(header[offset + 3]) << 16)
                | (static_cast<std::uint32_t>(header[offset + 4]) << 8)
                | static_cast<std::uint32_t>(header[offset + 5]);
            if (length32 < 65536)
                return IP6OptionError::jumbo_small_payload;
            if (fragment_present)
                return IP6OptionError::jumbo_fragment;
            if (jumbo_seen)
                return IP6OptionError::duplicate_jumbo;
            jumbo_seen = true;
        }
        offset += length + 2;
    }
    if (hop_by_hop && ipv6_payload_length == 0 && !jumbo_seen)
        return IP6OptionError::missing_jumbo;
    return IP6OptionError::none;
}

inline bool invalid_ip6_options(const std::uint8_t* header, std::size_t size,
    bool hop_by_hop, std::uint16_t ipv6_payload_length, bool fragment_present)
{
    return ip6_options_error(header, size, hop_by_hop, ipv6_payload_length,
        fragment_present) != IP6OptionError::none;
}

// Inspect the selected IPv6 packet's exact payload span, before reassembly can
// remove a Fragment header. Decode only lengths of the known extension kinds;
// stop at an upper/unknown protocol or a noninitial fragment. In particular,
// do not interpret continuation-fragment bytes as an extension header.
//
// The caller supplies a capture-checked span bounded by this IPv6 packet's
// declared payload length, excluding Ethernet padding and outer packet data.
// A maximum of eight extensions matches the native profile's local resource
// policy. Truncated known extension framing or an exhausted traversal budget
// fails closed. Routing contents and unknown option action-bit policy remain
// outside this structural/known-option check.
inline bool invalid_ip6_option_chain(std::uint8_t next_header,
    const std::uint8_t* payload, std::size_t size,
    std::uint16_t ipv6_payload_length)
{
    if (!payload && size)
        return true;
    if (ax_home::malformed_home(ax_home::chain(next_header, payload, size).error))
        return true;
    struct OptionSpan
    {
        const std::uint8_t* data;
        std::size_t size;
        bool hop;
    };
    std::array<OptionSpan, 8> options{};
    std::size_t option_count = 0;
    std::size_t offset = 0;
    unsigned extensions = 0;
    bool fragment_present = false;
    bool finished = false;
    while (!finished)
    {
        const std::size_t remaining = size - offset;
        switch (next_header)
        {
        case 0: // Hop-by-Hop.
        case 60: // Destination Options.
        case 43: // Routing.
        case 51: // Authentication Header.
        {
            if (extensions++ == 8 || remaining < 2)
                return true;
            const std::size_t length = next_header == 51 ?
                (static_cast<std::size_t>(payload[offset + 1]) + 2) * 4 :
                (static_cast<std::size_t>(payload[offset + 1]) + 1) * 8;
            if (length > remaining)
                return true;
            if (next_header == 51 && invalid_ah_header(payload + offset, length, true))
                return true;
            if (next_header == 0 || next_header == 60)
                options[option_count++] = {payload + offset, length, next_header == 0};
            next_header = payload[offset];
            offset += length;
            break;
        }
        case 44: // Fragment: the eight-octet header is always unfragmented.
        {
            if (extensions++ == 8 || remaining < 8)
                return true;
            fragment_present = true;
            const auto field = (static_cast<unsigned>(payload[offset + 2]) << 8)
                | payload[offset + 3];
            next_header = payload[offset];
            offset += 8;
            if ((field & 0xfff8) != 0)
                finished = true;
            break;
        }
        default:
            finished = true;
            break;
        }
    }
    for (std::size_t i = 0; i < option_count; ++i)
    {
        const auto& option = options[i];
        if (invalid_ip6_options(option.data, option.size, option.hop,
            ipv6_payload_length, fragment_present))
            return true;
    }
    return false;
}
}

#endif
