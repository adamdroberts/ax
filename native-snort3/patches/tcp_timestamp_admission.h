// Local cumulative Snort repair: timestamp state follows final admission.
#ifndef AX_TCP_TIMESTAMP_ADMISSION_H
#define AX_TCP_TIMESTAMP_ADMISSION_H

#include <cstdint>
#include <memory>

namespace snort { struct Packet; struct SnortConfig; }
class TcpStreamTracker;

struct TcpTimestampValue
{
    std::uint32_t last = 0;
    std::uint32_t packet_time = 0;
    std::uint16_t flags = 0;

    bool operator==(const TcpTimestampValue& rhs) const
    { return last == rhs.last && packet_time == rhs.packet_time && flags == rhs.flags; }
};

struct TcpTimestampState
{
    TcpTimestampValue value;
    std::uint64_t revision = 0;

    void reset()
    { value = {}; ++revision; }
};

void tcp_timestamp_admission_init();
void tcp_timestamp_admission_configure(snort::SnortConfig*);

// Native processing may use provisional values within this scope. Before it
// returns to detection, restore the admitted values and stage the candidate on
// the original wire context. Shared cells outlive a deleted/reused flow safely.
class TcpTimestampAdmission
{
public:
    TcpTimestampAdmission(TcpStreamTracker&, TcpStreamTracker&, snort::Packet*);
    ~TcpTimestampAdmission();
    TcpTimestampAdmission(const TcpTimestampAdmission&) = delete;
    TcpTimestampAdmission& operator=(const TcpTimestampAdmission&) = delete;

private:
    struct Snapshot
    {
        std::shared_ptr<TcpTimestampState> state;
        TcpTimestampValue value;
        std::uint64_t revision = 0;
    } snapshots[2];
    snort::Packet* packet;
};
#endif
