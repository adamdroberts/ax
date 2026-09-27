// SPDX-License-Identifier: GPL-2.0-only
// Included by the pinned ip_defrag.cc after its native declarations.
static bool CaptureIp4Prefix(FragTracker* ft, const Packet* p, uint16_t fragment_offset)
{
    const auto start = reinterpret_cast<uintptr_t>(p->pkt);
    const auto selected = reinterpret_cast<uintptr_t>(p->ptrs.ip_api.get_ip4h());
    auto result = ax_fragment::Ip4PrefixResult::invalid_header_or_size;
    if (selected >= start && selected - start <= p->pktlen)
    {
        const auto* ip = reinterpret_cast<const uint8_t*>(selected);
        const size_t available = p->pktlen - (selected - start);
        // Require the decoded fragment span to refer to the bounded wire header.
        if (available >= 20 && static_cast<size_t>((ip[0] & 15) * 4) <= available &&
            p->data == ip + (ip[0] & 15) * 4)
            result = ax_fragment::observe_ip4_prefix(ft->ip4_prefix, ip, available,
                fragment_offset, p->dsize);
    }
    if (result == ax_fragment::Ip4PrefixResult::okay)
        return true;
    ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS |
        (result == ax_fragment::Ip4PrefixResult::conflicting_ecn ? FRAG_ECN_BAD : FRAG_PREFIX_BAD);
    return false;
}

static bool RestoreIp4Prefix(FragTracker* ft, Packet* rebuilt)
{
    const auto& saved = ft->ip4_prefix;
    const auto start = reinterpret_cast<uintptr_t>(rebuilt->pkt);
    const auto selected = reinterpret_cast<uintptr_t>(rebuilt->ptrs.ip_api.get_ip4h());
    const size_t header = (saved.first[0] & 15) * 4;
    const int inner = layer::get_inner_ip_lyr_index(rebuilt);
    if (!saved.first_seen || !ft->ip_options_first_seen || inner < 0 ||
        inner >= rebuilt->num_layers || rebuilt->layers[inner].start != reinterpret_cast<const uint8_t*>(selected) ||
        selected < start || selected - start > Codec::PKT_MAX ||
        header != ip::IP4_HEADER_LEN + ft->ip_options_len ||
        (ft->ip_options_len && !ft->ip_options_data) ||
        !ax_fragment::ip4_rebuilt_fits(header, ft->calculated_size, selected - start, Codec::PKT_MAX))
        return false;
    // RFC 3168's reassembly table is the same for both IP versions. Reuse the
    // previously tested helper; first-header codepoint is used where unspecified.
    const auto ecn = ax_fragment::ip6_rebuilt_ecn(saved.ecn_seen, saved.first[1] & 3);
    if (ecn == 0xff)
        return false;
    auto* ip = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(selected));
    memcpy(ip, saved.first, sizeof(saved.first));
    ip[1] = (ip[1] & 0xfc) | ecn;
    rebuilt->ptrs.ip_api.set(reinterpret_cast<const ip::IP4Hdr*>(ip));
    // Existing reconstruction copies saved options immediately after this base
    // header and updates total length/checksum before decoding the rebuilt packet.
    rebuilt->data = ip + ip::IP4_HEADER_LEN;
    rebuilt->layers[inner].length = ip::IP4_HEADER_LEN;
    return true;
}
