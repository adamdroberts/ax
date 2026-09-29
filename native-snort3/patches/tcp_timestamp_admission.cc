#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_timestamp_admission.h"
#include "tcp_stream_tracker.h"

#include "detection/ips_context.h"
#include "detection/ips_context_data.h"
#include "flow/flow.h"
#include "framework/data_bus.h"
#include "packet_io/active.h"
#include "protocols/packet.h"
#include "pub_sub/finalize_packet_event.h"

#include <array>

namespace
{
unsigned context_id = 0;
constexpr const char* name = "tcp_timestamp_admission";

class PendingTimestamps final : public snort::IpsContextData
{
public:
    bool stage(const std::shared_ptr<TcpTimestampState>& state,
               const TcpTimestampValue& value, std::uint64_t revision,
               const snort::Packet* original)
    {
        if (conflict || (wire && wire != original))
            return conflict = true, false;
        wire = original;
        packet_number = wire->context->packet_number;
        for (unsigned i = 0; i < count; ++i)
        {
            if (entries[i].state != state)
                continue;
            if (entries[i].revision != revision || !(entries[i].value == value))
                return conflict = true, false;
            return true;
        }
        // Bound nested/repeated TCP processing on one wire packet. Exceeding
        // this local budget rejects that packet and grants no new state.
        if (count == entries.size())
            return conflict = true, false;
        entries[count++] = {state, value, revision};
        return true;
    }

    void finish(bool admitted)
    {
        if (admitted && !conflict)
            for (unsigned i = 0; i < count; ++i)
            {
                auto& entry = entries[i];
                // A stale callback cannot overwrite a newer admitted update
                // or a tracker reset performed outside this packet's scope.
                if (entry.state->revision == entry.revision)
                {
                    entry.state->value = entry.value;
                    ++entry.state->revision;
                }
            }
        for (unsigned i = 0; i < count; ++i)
            entries[i].state.reset();
        count = 0;
        conflict = false;
        wire = nullptr;
    }

    void clear() override
    {
        // Completed IP reassembly can remove the original flow before the
        // flow-gated finalization event. The pinned engine clears pkth only
        // after choosing a final DAQ verdict and clears this context later.
        // These exclusions leave only PASS/REPLACE in that flowless path.
        const bool admitted = wire && wire->context &&
            wire->context->packet_number == packet_number && !wire->flow &&
            !wire->pkth && wire->active && wire->active->session_was_allowed() &&
            !wire->active->session_was_trusted() &&
            !(wire->packet_flags & (PKT_IGNORE | PKT_RESIZED)) &&
            !(wire->ptrs.decode_flags & DECODE_PKT_TRUST);
        finish(admitted);
    }

private:
    struct Entry
    {
        std::shared_ptr<TcpTimestampState> state;
        TcpTimestampValue value;
        std::uint64_t revision = 0;
    };
    std::array<Entry, 8> entries;
    const snort::Packet* wire = nullptr;
    std::uint64_t packet_number = 0;
    unsigned count = 0;
    bool conflict = false;
};

class FinalizeTimestamps final : public snort::DataHandler
{
public:
    FinalizeTimestamps() : DataHandler(name) { }

    void handle(snort::DataEvent& event, snort::Flow*) override
    {
        auto& final = static_cast<snort::FinalizePacketEvent&>(event);
        const auto* packet = final.get_packet();
        if (!packet || !packet->context)
            return;
        auto* pending = static_cast<PendingTimestamps*>(packet->context->get_context_data(context_id));
        if (pending)
            pending->finish(final.get_verdict() == DAQ_VERDICT_PASS ||
                            final.get_verdict() == DAQ_VERDICT_REPLACE);
    }
};
}

void tcp_timestamp_admission_init()
{ context_id = snort::IpsContextData::get_ips_id(); }

void tcp_timestamp_admission_configure(snort::SnortConfig* config)
{
    snort::DataBus::subscribe_global(snort::intrinsic_pub_key,
        snort::IntrinsicEventIds::FINALIZE_PACKET, new FinalizeTimestamps, *config);
}

TcpTimestampAdmission::TcpTimestampAdmission(
    TcpStreamTracker& client, TcpStreamTracker& server, snort::Packet* p) : packet(p)
{
    snapshots[0].state = client.get_timestamp_state();
    snapshots[1].state = server.get_timestamp_state();
    for (auto& snapshot : snapshots)
    {
        snapshot.value = snapshot.state->value;
        snapshot.revision = snapshot.state->revision;
    }
}

TcpTimestampAdmission::~TcpTimestampAdmission()
{
    auto* wire = packet && packet->context ? packet->context->wire_packet : nullptr;
    for (auto& snapshot : snapshots)
    {
        const auto candidate = snapshot.state->value;
        const bool changed = !(candidate == snapshot.value) ||
                             snapshot.state->revision != snapshot.revision;
        snapshot.state->value = snapshot.value;
        snapshot.state->revision = snapshot.revision;
        if (!changed)
            continue;
        if (!wire || !wire->context || !wire->flow)
        {
            if (packet && packet->active)
                packet->active->drop_packet(packet, true);
            continue;
        }
        auto* pending = static_cast<PendingTimestamps*>(wire->context->get_context_data(context_id));
        if (!pending)
        {
            pending = new PendingTimestamps;
            wire->context->set_context_data(context_id, pending);
        }
        wire->flow->flags.trigger_finalize_event = true;
        if (!pending->stage(snapshot.state, candidate, snapshot.revision, wire))
        {
            wire->active->drop_packet(wire, true);
            packet->active->drop_packet(packet, true);
        }
    }
}
