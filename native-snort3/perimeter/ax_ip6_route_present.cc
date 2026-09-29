#include "framework/ips_option.h"
#include "framework/module.h"
#include "protocols/layer.h"
#include "protocols/packet.h"
#include "../plugins/home_address.h"

namespace
{
constexpr const char* route_name = "ax_ip6_route_present";
constexpr const char* route_help = "detect decoded IPv6 routing headers for exact-endpoint egress policy";
constexpr const char* home_name = "ax_ip6_home_present";
constexpr const char* home_help = "detect IPv6 Home Address options at the fixed-peer agent boundary";

class Module final : public snort::Module
{
public:
    Module(const char* option_name, const char* option_help) : snort::Module(option_name, option_help) { }
    Usage get_usage() const override { return DETECT; }
};

class Option final : public snort::IpsOption
{
public:
    Option() : IpsOption(route_name) { }
    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6())
            return NO_MATCH;
        if (!packet->layers)
            return MATCH; // No reduced-inspection fallback at this boundary.
        for (unsigned i = 0; i < packet->num_layers; ++i)
            if (packet->layers[i].prot_id == ProtocolId::ROUTING)
                return MATCH;
        return NO_MATCH;
    }
};

// Use the same bounded Home Address parser as the protocol validator. The
// local policy only rejects presence; it does not authenticate mobility state.
class HomeOption final : public snort::IpsOption
{
public:
    HomeOption() : IpsOption(home_name) { }
    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.ip_api.is_ip6())
            return NO_MATCH;
        const auto* header = reinterpret_cast<const std::uint8_t*>(packet->ptrs.ip_api.get_ip6h());
        if (!packet->pkt || !header)
            return MATCH;
        const auto begin = reinterpret_cast<std::uintptr_t>(packet->pkt);
        const auto address = reinterpret_cast<std::uintptr_t>(header);
        // Integer bounds precede any pointer arithmetic or reads. IP rule
        // cursors include extensions and cannot substitute for this wire span.
        if (address < begin || address - begin > packet->pktlen ||
            packet->pktlen - (address - begin) < 40)
            return MATCH;
        const auto length = packet->ptrs.ip_api.pay_len();
        if (length > packet->pktlen - (address - begin) - 40)
            return MATCH;
        const auto result = ax_home::chain(header[6], header + 40, length);
        // Malformed options remain covered by the existing protocol rules.
        return result.source ? MATCH : NO_MATCH;
    }
};

snort::Module* module_create() { return new Module(route_name, route_help); }
snort::Module* home_module_create() { return new Module(home_name, home_help); }
void module_delete(snort::Module* p) { delete p; }
snort::IpsOption* option_create(snort::Module*, IpsInfo&) { return new Option; }
snort::IpsOption* home_option_create(snort::Module*, IpsInfo&) { return new HomeOption; }
void option_delete(snort::IpsOption* p) { delete p; }
const snort::IpsApi api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, route_name, route_help, module_create, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, option_create, option_delete, nullptr
};
const snort::IpsApi home_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, PLUGIN_SO_RELOAD,
        API_OPTIONS, home_name, home_help, home_module_create, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__IP,
    nullptr, nullptr, nullptr, nullptr, home_option_create, option_delete, nullptr
};
}

SO_PUBLIC const snort::BaseApi* snort_plugins[] = {&api.base, &home_api.base, nullptr};
