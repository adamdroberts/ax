#include "tcp_sack_option.h"
#include "tcp_sack_state.h"

#include "detection/ips_context.h"
#include "detection/ips_context_data.h"
#include "flow/flow.h"
#include "flow/flow_data.h"
#include "framework/data_bus.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "pub_sub/finalize_packet_event.h"

#include <memory>

namespace
{
constexpr const char* sack_name = "ax_tcp_sack_state";
constexpr const char* sack_help = "require an admitted peer SYN offer before TCP SACK";
unsigned flow_id = 0;
unsigned context_id = 0;

bool span(const snort::Packet* packet, const std::uint8_t* bytes, std::size_t size)
{
    if (!packet->pkt || !bytes)
        return false;
    const auto base = reinterpret_cast<std::uintptr_t>(packet->pkt);
    const auto position = reinterpret_cast<std::uintptr_t>(bytes);
    return position >= base && position - base <= packet->pktlen &&
        size <= packet->pktlen - (position - base);
}

class SackFlow final : public snort::FlowData
{
public:
    SackFlow() : FlowData(flow_id, sack_name), state(std::make_shared<ax_tcp::SackNegotiation>()) { }
    std::shared_ptr<ax_tcp::SackNegotiation> state;
};

// At most one TCP handshake offer can belong to the one admitted IP packet.
// Keep it on the original wire context so a rebuilt fragment's early return
// cannot commit an offer before the enclosing packet's final drop decision.
class PendingOffer final : public snort::IpsContextData
{
public:
    void clear() override
    {
        // The pinned engine removes a completed fragment flow before its
        // flow-gated FINALIZE_PACKET event. Context cleanup is later than DAQ
        // finalization: pkth is cleared there, and Active remains live until
        // after this callback. With no flow, these exclusions leave only the
        // PASS/REPLACE branches of Analyzer::distill_verdict. Never infer an
        // admission on abort, retry, hold, injection, trust, or an active drop.
        if (state && !final_seen && !conflict && wire && wire->context &&
            wire->context->packet_number == packet_number && !wire->flow &&
            !wire->pkth && wire->active && wire->active->session_was_allowed() &&
            !wire->active->session_was_trusted() &&
            !(wire->packet_flags & (PKT_IGNORE | PKT_RESIZED)) &&
            !(wire->ptrs.decode_flags & DECODE_PKT_TRUST))
            state->observe(side, sequence, permitted, true);
        state.reset();
        conflict = false;
        final_seen = false;
        wire = nullptr;
    }

    bool stage(const std::shared_ptr<ax_tcp::SackNegotiation>& next_state,
               unsigned next_side, std::uint32_t next_sequence, bool next_permitted,
               const snort::Packet* next_wire)
    {
        if (state && (state != next_state || side != next_side || sequence != next_sequence || permitted != next_permitted))
            conflict = true;
        if (conflict)
            return false;
        state = next_state;
        side = next_side;
        sequence = next_sequence;
        permitted = next_permitted;
        wire = next_wire;
        packet_number = wire->context->packet_number;
        return true;
    }

    std::shared_ptr<ax_tcp::SackNegotiation> state;
    unsigned side = 0;
    std::uint32_t sequence = 0;
    bool permitted = false;
    bool conflict = false;
    bool final_seen = false;
    const snort::Packet* wire = nullptr;
    std::uint64_t packet_number = 0;
};

class FinalizeOffer final : public snort::DataHandler
{
public:
    FinalizeOffer() : DataHandler(sack_name) { }

    void handle(snort::DataEvent& event, snort::Flow*) override
    {
        auto& final = static_cast<snort::FinalizePacketEvent&>(event);
        const auto* packet = final.get_packet();
        if (!packet || !packet->context)
            return;
        auto* pending = static_cast<PendingOffer*>(packet->context->get_context_data(context_id));
        if (!pending || !pending->state)
            return;
        const auto verdict = final.get_verdict();
        pending->final_seen = true;
        pending->state->observe(pending->side, pending->sequence, pending->permitted,
            !pending->conflict && (verdict == DAQ_VERDICT_PASS || verdict == DAQ_VERDICT_REPLACE));
        pending->clear();
    }
};

class SackOption final : public snort::IpsOption
{
public:
    SackOption() : IpsOption(sack_name) { }

    EvalStatus eval(Cursor&, snort::Packet* packet) override
    {
        if (!packet || !packet->ptrs.tcph || (packet->packet_flags & PKT_REBUILT_STREAM))
            return NO_MATCH;
        const auto* header = reinterpret_cast<const std::uint8_t*>(packet->ptrs.tcph);
        if (!span(packet, header, 20))
            return MATCH;
        const std::size_t size = (header[12] >> 4) * 4;
        if (size < 20 || !span(packet, header, size))
            return MATCH;
        const bool syn = header[13] & 2;
        const auto options = ax_tcp::sack_options(header + 20, size - 20, syn);
        // SID 9201017 rejects malformed options. They must never stage state.
        if (options.malformed || (!syn && !options.sack))
            return NO_MATCH;
        if (!packet->flow || packet->is_from_client() == packet->is_from_server())
            return MATCH;
        const unsigned side = packet->is_from_client_originally() ? 0 : 1;
        auto* flow = static_cast<SackFlow*>(packet->flow->get_flow_data(flow_id));
        if (options.sack)
        {
            if (syn || !(header[13] & 16) || !flow ||
                !(packet->flow->get_session_flags() & SSNFLAG_ESTABLISHED) || !flow->state->permits(side))
                return MATCH;
        }
        if (!syn)
            return NO_MATCH;
        auto* wire = packet->context ? packet->context->wire_packet : nullptr;
        if (!wire || !wire->context || !wire->flow)
            return MATCH;
        if (!flow)
        {
            flow = new SackFlow;
            packet->flow->set_flow_data(flow);
        }
        auto* pending = static_cast<PendingOffer*>(wire->context->get_context_data(context_id));
        if (!pending)
        {
            pending = new PendingOffer;
            wire->context->set_context_data(context_id, pending);
        }
        wire->flow->flags.trigger_finalize_event = true;
        const std::uint32_t sequence = (std::uint32_t(header[4]) << 24) |
            (std::uint32_t(header[5]) << 16) | (std::uint32_t(header[6]) << 8) | header[7];
        return pending->stage(flow->state, side, sequence, options.permitted, wire) ? NO_MATCH : MATCH;
    }
};

class SackModule final : public snort::Module
{
public:
    SackModule() : Module(sack_name, sack_help) { }
    Usage get_usage() const override { return DETECT; }
};

void initialize()
{
    flow_id = snort::FlowData::create_flow_data_id();
    context_id = snort::IpsContextData::get_ips_id();
}
void verify(const snort::SnortConfig* config)
{
    // IpsApi's verify hook supplies a const config while the public DataBus
    // registration API takes a mutable config to install its owned handler.
    snort::DataBus::subscribe_global(snort::intrinsic_pub_key, snort::IntrinsicEventIds::FINALIZE_PACKET,
        new FinalizeOffer, *const_cast<snort::SnortConfig*>(config));
}
snort::Module* module_create() { return new SackModule; }
void module_delete(snort::Module* module) { delete module; }
snort::IpsOption* option_create(snort::Module*, IpsInfo&) { return new SackOption; }
void option_delete(snort::IpsOption* option) { delete option; }
}

const snort::IpsApi ax_tcp_sack_state_api = {
    {PT_IPS_OPTION, sizeof(snort::IpsApi), IPSAPI_VERSION, 1, 0,
        API_OPTIONS, sack_name, sack_help, module_create, module_delete},
    snort::OPT_TYPE_DETECTION, 1, PROTO_BIT__TCP,
    initialize, nullptr, nullptr, nullptr, option_create, option_delete, verify
};
