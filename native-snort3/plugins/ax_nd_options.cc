#include "framework/ips_option.h"
#include "framework/module.h"
#include "protocols/icmp4.h"
#include "protocols/layer.h"
#include "protocols/packet.h"

#include "nd_validation.h"
#include "ip_validation.h"
#include "ip4_options.h"
#include "ip6_options.h"
#include "esp_validation.h"
#include "routing_validation.h"
#include "tcp_options.h"
#include "tcp_sack_option.h"

namespace
{
constexpr const char* options_name = "ax_nd_options";
constexpr const char* options_help = "detect malformed IPv6 neighbor-discovery option framing";
constexpr const char* semantics_name = "ax_nd_semantics";
constexpr const char* semantics_help = "detect stateless RFC 4861 neighbor-discovery receive violations";
constexpr const char* hop_order_name = "ax_ip6_hop_order";
constexpr const char* hop_order_help = "detect IPv6 Hop-by-Hop headers outside the first extension position";
constexpr const char* ah_name = "ax_ah_header";
constexpr const char* ah_help = "detect malformed IP Authentication Header lengths";
constexpr const char* fragment_name = "ax_ip6_first_fragment";
constexpr const char* fragment_help = "detect incomplete or unsupported IPv6 first-fragment header chains";
constexpr const char* next_header_name = "ax_ip6_base_next_header";
constexpr const char* next_header_help = "enforce the pinned IPv6 base Next Header policy with AH support";
constexpr const char* ip4_options_name = "ax_ip4_options";
constexpr const char* ip4_options_help = "detect malformed original IPv4 options and padding";
constexpr const char* ip6_options_name = "ax_ip6_options";
constexpr const char* ip6_options_help = "detect malformed IPv6 extension options";
constexpr const char* esp_name = "ax_esp_header";
constexpr const char* esp_help = "detect impossible visible ESP framing without decrypting payloads";
constexpr const char* routing_name = "ax_ip6_type2_routing";
constexpr const char* routing_help = "validate original-wire IPv6 Type 2 routing headers";
constexpr const char* tcp_options_name = "ax_tcp_options";
constexpr const char* tcp_options_help = "validate original TCP option geometry, padding and mandatory SYN context";

bool ip_layer(ProtocolId protocol)
{
    return protocol == ProtocolId::ETHERTYPE_IPV4 || protocol == ProtocolId::IPIP ||
        protocol == ProtocolId::ETHERTYPE_IPV6 || protocol == ProtocolId::IPV6;
}

// Compare integer offsets before constructing a span. IP-rule evaluation
// replaces Packet::data/dsize with the selected IP payload, which includes all
// extension headers, rather than the codec's last payload position.
bool captured_span(const snort::Packet* packet, const std::uint8_t* start, std::size_t size)
{
    if (!packet->pkt || !start)
        return false;
    const auto begin = reinterpret_cast<std::uintptr_t>(packet->pkt);
    const auto address = reinterpret_cast<std::uintptr_t>(start);
    return address >= begin && address - begin <= packet->pktlen &&
        size <= packet->pktlen - (address - begin);
}

class NDModule final : public snort::Module
{
public:
    NDModule(const char* name, const char* help) : Module(name, help) { }
    Usage get_usage() const override { return DETECT; }
};

class TCPOptionsOption final : public snort::IpsOption
{
public:
    TCPOptionsOption() : IpsOption(tcp_options_name) { }
    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.tcph)
            return NO_MATCH;
        const auto* header = reinterpret_cast<const std::uint8_t*>(packet->ptrs.tcph);
        if (!captured_span(packet, header, 20))
            return MATCH;
        const std::size_t size = (header[12] >> 4) * 4;
        if (size < 20 || !captured_span(packet, header, size))
            return MATCH;
        // The decoder's option span ends at EOL or its first invalid option.
        // Use the original Data Offset, including every padding byte.
        return ax_tcp::invalid_options(header + 20, size - 20, header[13] & 2) ? MATCH : NO_MATCH;
    }
};

class IP4OptionsOption final : public snort::IpsOption
{
public:
    IP4OptionsOption() : IpsOption(ip4_options_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip4())
            return NO_MATCH;
        const auto* ipv4 = packet->ptrs.ip_api.get_ip4h();
        const auto* header = reinterpret_cast<const std::uint8_t*>(ipv4);
        if (!captured_span(packet, header, 20))
            return MATCH;
        const std::size_t size = (header[0] & 0x0f) * 4;
        if (size < 20 || size > 60 || !captured_span(packet, header, size))
            return MATCH;
        // The codec's valid option span stops at EOL or the first malformed
        // option. Inspect the original IHL-bounded bytes, including padding.
        return ax_ip4::invalid_options(header + 20, size - 20) ? MATCH : NO_MATCH;
    }
};

class IP6OptionsOption final : public snort::IpsOption
{
public:
    IP6OptionsOption() : IpsOption(ip6_options_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6())
            return NO_MATCH;
        const auto* ipv6 = packet->ptrs.ip_api.get_ip6h();
        const auto* header = reinterpret_cast<const std::uint8_t*>(ipv6);
        if (!captured_span(packet, header, 40))
            return MATCH;
        const std::size_t size = packet->ptrs.ip_api.pay_len();
        if (!captured_span(packet, header + 40, size))
            return MATCH;
        return ax_ip::invalid_ip6_option_chain(header[6], header + 40, size,
            (static_cast<std::uint16_t>(header[4]) << 8) | header[5]) ? MATCH : NO_MATCH;
    }
};

class ESPOption final : public snort::IpsOption
{
public:
    ESPOption() : IpsOption(esp_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet)
            return NO_MATCH;
        const auto& ip = packet->ptrs.ip_api;
        if (!ip.is_ip4() && !ip.is_ip6())
            return NO_MATCH;
        const std::uint8_t* header;
        std::size_t header_size;
        std::uint8_t protocol;
        std::uint16_t fragment = 0;
        if (ip.is_ip6())
        {
            const auto* ipv6 = ip.get_ip6h();
            header = reinterpret_cast<const std::uint8_t*>(ipv6);
            if (!captured_span(packet, header, 40))
                return MATCH;
            header_size = 40;
            protocol = header[6];
        }
        else
        {
            const auto* ipv4 = ip.get_ip4h();
            header = reinterpret_cast<const std::uint8_t*>(ipv4);
            if (!captured_span(packet, header, 20))
                return MATCH;
            header_size = (header[0] & 0x0f) * 4;
            if (header_size < 20 || header_size > 60 || !captured_span(packet, header, header_size))
                return MATCH;
            protocol = header[9];
            fragment = (static_cast<std::uint16_t>(header[6]) << 8) | header[7];
        }
        const auto size = static_cast<std::size_t>(ip.pay_len());
        if (!captured_span(packet, header + header_size, size))
            return MATCH;
        return ax_esp::invalid_visible_framing(protocol, header + header_size,
            size, ip.is_ip6(), fragment & 0x1fff, (fragment & 0x2000) != 0) ? MATCH : NO_MATCH;
    }
};

class Type2RoutingOption final : public snort::IpsOption
{
public:
    Type2RoutingOption() : IpsOption(routing_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6())
            return NO_MATCH;
        const auto* ipv6 = packet->ptrs.ip_api.get_ip6h();
        const auto* header = reinterpret_cast<const std::uint8_t*>(ipv6);
        if (!captured_span(packet, header, 40))
            return MATCH;
        const auto size = static_cast<std::size_t>(packet->ptrs.ip_api.pay_len());
        if (!captured_span(packet, header + 40, size))
            return MATCH;
        return ax_ip::invalid_type2_chain(header[6], header + 40, size) ? MATCH : NO_MATCH;
    }
};

// The pinned decoder's validity list omits AH even though its AH codec is
// present. Retain the previous rejection set, exempting exactly AUTH; its
// framing remains subject to the AH decoder and ax_ah_header. This is a local
// protocol-admission set, not a claim that all other IANA protocols are invalid.
class BaseNextHeaderOption final : public snort::IpsOption
{
public:
    BaseNextHeaderOption() : IpsOption(next_header_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6())
            return NO_MATCH;
        const auto* ipv6 = reinterpret_cast<const std::uint8_t*>(packet->ptrs.ip_api.get_ip6h());
        if (!captured_span(packet, ipv6, 40))
            return MATCH;
        // Ethernet payloads need not align the SDK's typed IP header. Keep
        // its reviewed predicate, which uses only the Next Header field.
        snort::ip::IP6Hdr aligned{};
        aligned.ip6_next = static_cast<IpProtocol>(ipv6[6]);
        return !aligned.is_valid_next_header() && aligned.next() != IpProtocol::AUTH ? MATCH : NO_MATCH;
    }
};

class NDOption final : public snort::IpsOption
{
public:
    explicit NDOption(bool semantic) : IpsOption(semantic ? semantics_name : options_name),
        semantic(semantic) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6() || !packet->ptrs.icmph)
            return NO_MATCH;
        const auto* message = reinterpret_cast<const std::uint8_t*>(packet->ptrs.icmph);
        if (!captured_span(packet, message, 4))
            return MATCH;
        const auto type = message[0];
        if (!ax_nd::fixed_size(type))
            return NO_MATCH;
        // In the pinned 3.12.2.0 ICMPv6 codec, ND consumes the four common
        // header octets. dsize is the decoded IP-bounded remainder. Refuse an
        // unexpected selected-ND layout rather than bypassing this check.
        if (!packet->data || packet->data != message + 4)
            return MATCH;
        const std::size_t size = static_cast<std::size_t>(packet->dsize) + 4;
        if (!captured_span(packet, message, size))
            return MATCH;
        if (!semantic)
            return ax_nd::malformed_options(type, message, size) ? MATCH : NO_MATCH;
        const auto* ipv6 = reinterpret_cast<const std::uint8_t*>(packet->ptrs.ip_api.get_ip6h());
        if (!captured_span(packet, ipv6, 40))
            return MATCH;
        return ax_nd::invalid_semantics(type, message, size, ipv6 + 8, ipv6 + 24) ? MATCH : NO_MATCH;
    }

private:
    const bool semantic;
};

// RFC 8200 permits most extension-header orders and repetitions, but the
// Hop-by-Hop header can only immediately follow its IPv6 header. The pinned
// decoder reports both cases through the same advisory, so check this precise
// exception separately using its bounded, decoded layer inventory.
class HopOrderOption final : public snort::IpsOption
{
public:
    HopOrderOption() : IpsOption(hop_order_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6())
            return NO_MATCH;
        if (!packet->layers)
            return MATCH;
        const auto* ipv6 = reinterpret_cast<const std::uint8_t*>(packet->ptrs.ip_api.get_ip6h());
        unsigned base = packet->num_layers;
        for (unsigned i = 0; i < packet->num_layers; ++i)
        {
            const auto& layer = packet->layers[i];
            if (layer.start == ipv6 &&
                (layer.prot_id == ProtocolId::ETHERTYPE_IPV6 || layer.prot_id == ProtocolId::IPV6))
                base = i;
            else if (base < i && ip_layer(layer.prot_id))
                break; // The next encapsulated IP chain is evaluated separately.
            else if (base < i && layer.prot_id == ProtocolId::HOPOPTS && i != base + 1)
                return MATCH;
            else if (base < i && layer.prot_id == ProtocolId::FRAGMENT &&
                layer.start && layer.length >= 8 && layer.start[0] == 0 &&
                (layer.start[2] == 0 && (layer.start[3] & 0xf8) == 0))
                // Reassembly removes Fragment, which would otherwise make the
                // misplaced Hop-by-Hop header appear immediately after IPv6.
                return MATCH;
        }
        return base == packet->num_layers ? MATCH : NO_MATCH;
    }
};

class AHOption final : public snort::IpsOption
{
public:
    AHOption() : IpsOption(ah_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->layers)
            return NO_MATCH;
        bool ipv6 = packet->ptrs.ip_api.is_ip6();
        for (unsigned i = 0; i < packet->num_layers; ++i)
        {
            const auto& layer = packet->layers[i];
            if (layer.prot_id == ProtocolId::ETHERTYPE_IPV6 || layer.prot_id == ProtocolId::IPV6)
                ipv6 = true;
            else if (layer.prot_id == ProtocolId::ETHERTYPE_IPV4 || layer.prot_id == ProtocolId::IPIP)
                ipv6 = false;
            else if (layer.prot_id == ProtocolId::AUTH &&
                ax_ip::invalid_ah_header(layer.start, layer.length, ipv6))
                return MATCH;
        }
        return NO_MATCH;
    }
};

class FirstFragmentOption final : public snort::IpsOption
{
public:
    FirstFragmentOption() : IpsOption(fragment_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6() || !packet->layers)
            return NO_MATCH;
        const auto* ipv6 = reinterpret_cast<const std::uint8_t*>(packet->ptrs.ip_api.get_ip6h());
        if (!captured_span(packet, ipv6, 40))
            return MATCH;
        const auto* payload = ipv6 + 40;
        const std::size_t payload_size = packet->ptrs.ip_api.pay_len();
        if (!captured_span(packet, payload, payload_size))
            return MATCH;
        bool selected = false;
        for (unsigned i = 0; i < packet->num_layers; ++i)
        {
            const auto& layer = packet->layers[i];
            if (ip_layer(layer.prot_id))
            {
                if (selected)
                    break;
                selected = layer.start == ipv6;
                continue;
            }
            if (!selected)
                continue;
            if (layer.prot_id != ProtocolId::FRAGMENT)
                continue;
            if (layer.length < 8 || !captured_span(packet, layer.start, 8))
                return MATCH;
            // Noninitial fragments do not begin with an upper-layer header.
            if (layer.start[2] != 0 || (layer.start[3] & 0xf8) != 0)
                continue;
            const auto address = reinterpret_cast<std::uintptr_t>(layer.start);
            const auto begin = reinterpret_cast<std::uintptr_t>(payload);
            if (address < begin || address - begin > payload_size ||
                payload_size - (address - begin) < 8)
                return MATCH;
            const std::size_t offset = address - begin + 8;
            return ax_ip::invalid_first_fragment(layer.start[0], payload + offset,
                payload_size - offset) ? MATCH : NO_MATCH;
        }
        return selected ? NO_MATCH : MATCH;
    }
};

snort::Module* options_module() { return new NDModule(options_name, options_help); }
snort::Module* semantics_module() { return new NDModule(semantics_name, semantics_help); }
snort::Module* hop_order_module() { return new NDModule(hop_order_name, hop_order_help); }
snort::Module* ah_module() { return new NDModule(ah_name, ah_help); }
snort::Module* fragment_module() { return new NDModule(fragment_name, fragment_help); }
snort::Module* next_header_module() { return new NDModule(next_header_name, next_header_help); }
snort::Module* ip4_options_module() { return new NDModule(ip4_options_name, ip4_options_help); }
snort::Module* ip6_options_module() { return new NDModule(ip6_options_name, ip6_options_help); }
snort::Module* esp_module() { return new NDModule(esp_name, esp_help); }
snort::Module* routing_module() { return new NDModule(routing_name, routing_help); }
snort::Module* tcp_options_module() { return new NDModule(tcp_options_name, tcp_options_help); }
void module_delete(snort::Module* module) { delete module; }
snort::IpsOption* options_create(snort::Module*, IpsInfo&) { return new NDOption(false); }
snort::IpsOption* semantics_create(snort::Module*, IpsInfo&) { return new NDOption(true); }
snort::IpsOption* hop_order_create(snort::Module*, IpsInfo&) { return new HopOrderOption; }
snort::IpsOption* ah_create(snort::Module*, IpsInfo&) { return new AHOption; }
snort::IpsOption* fragment_create(snort::Module*, IpsInfo&) { return new FirstFragmentOption; }
snort::IpsOption* next_header_create(snort::Module*, IpsInfo&) { return new BaseNextHeaderOption; }
snort::IpsOption* ip4_options_create(snort::Module*, IpsInfo&) { return new IP4OptionsOption; }
snort::IpsOption* ip6_options_create(snort::Module*, IpsInfo&) { return new IP6OptionsOption; }
snort::IpsOption* esp_create(snort::Module*, IpsInfo&) { return new ESPOption; }
snort::IpsOption* routing_create(snort::Module*, IpsInfo&) { return new Type2RoutingOption; }
snort::IpsOption* tcp_options_create(snort::Module*, IpsInfo&) { return new TCPOptionsOption; }
void option_delete(snort::IpsOption* option) { delete option; }

const snort::IpsApi options_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, options_name, options_help, options_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__ICMP,
    nullptr, nullptr, nullptr, nullptr, options_create, option_delete, nullptr
};
const snort::IpsApi semantics_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, semantics_name, semantics_help, semantics_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__ICMP,
    nullptr, nullptr, nullptr, nullptr, semantics_create, option_delete, nullptr
};
const snort::IpsApi hop_order_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, hop_order_name, hop_order_help, hop_order_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, hop_order_create, option_delete, nullptr
};
const snort::IpsApi ah_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, ah_name, ah_help, ah_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, ah_create, option_delete, nullptr
};
const snort::IpsApi fragment_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, fragment_name, fragment_help, fragment_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, fragment_create, option_delete, nullptr
};
const snort::IpsApi next_header_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, next_header_name, next_header_help, next_header_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, next_header_create, option_delete, nullptr
};
const snort::IpsApi ip4_options_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, ip4_options_name, ip4_options_help, ip4_options_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, ip4_options_create, option_delete, nullptr
};
const snort::IpsApi ip6_options_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, ip6_options_name, ip6_options_help, ip6_options_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, ip6_options_create, option_delete, nullptr
};
const snort::IpsApi esp_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, esp_name, esp_help, esp_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, esp_create, option_delete, nullptr
};
const snort::IpsApi routing_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, routing_name, routing_help, routing_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, routing_create, option_delete, nullptr
};
const snort::IpsApi tcp_options_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, tcp_options_name, tcp_options_help, tcp_options_module, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__TCP,
    nullptr, nullptr, nullptr, nullptr, tcp_options_create, option_delete, nullptr
};
}

extern "C"
{
SO_PUBLIC const snort::BaseApi* snort_plugins[] = {&options_api.base, &semantics_api.base,
    &hop_order_api.base, &ah_api.base, &fragment_api.base, &next_header_api.base,
    &ip4_options_api.base, &ip6_options_api.base, &esp_api.base, &routing_api.base,
    &tcp_options_api.base, &ax_tcp_sack_state_api.base, nullptr};
}
