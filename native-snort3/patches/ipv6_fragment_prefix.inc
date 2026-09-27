// SPDX-License-Identifier: GPL-2.0-only
// Included by the pinned ip_defrag.cc after its native declarations.
struct SavedIp6Prefix
{
    uint8_t* bytes = nullptr;
    Layer* layers = nullptr;
    size_t length = 0;
    unsigned layer_count = 0;
    ~SavedIp6Prefix()
    {
        delete[] bytes;
        delete[] layers;
    }
};

static inline void delete_tracker(FragTracker*);
static void DropTrackedFragment(Packet*, const FragTracker*);

static bool CaptureIp6Prefix(FragTracker* ft, const Packet* p, uint16_t fragment_offset)
{
    const auto start = reinterpret_cast<uintptr_t>(p->pkt);
    const auto selected = reinterpret_cast<uintptr_t>(p->ptrs.ip_api.get_ip6h());
    if (selected < start || selected - start > p->pktlen)
    {
        ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_PREFIX_BAD;
        return false;
    }
    const auto* ip = reinterpret_cast<const uint8_t*>(selected);
    const auto parsed = ax_fragment::ip6_prefix(ip, p->pktlen - (selected - start),
        PacketManager::get_max_layers());
    if (!parsed.valid || parsed.fragment_offset != fragment_offset)
    {
        ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_PREFIX_BAD;
        return false;
    }
    // Check before any legacy 16-bit first/last-fragment geometry can wrap.
    const uint32_t end = static_cast<uint32_t>(fragment_offset) + p->dsize;
    const uint32_t known_end = end > ft->calculated_size ? end : ft->calculated_size;
    const size_t known_prefix = ft->ip6_prefix ? ft->ip6_prefix->length :
        fragment_offset ? 40 : parsed.length;
    if (!ax_fragment::ip6_rebuilt_fits(known_prefix, known_end, 0, Codec::PKT_MAX))
    {
        ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_PREFIX_BAD;
        return false;
    }
    ft->ip6_ecn_seen |= 1u << parsed.ecn;
    if ((ft->ip6_ecn_seen & 9) == 9)
    {
        ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_ECN_BAD;
        return false;
    }
    if (fragment_offset || ft->ip6_prefix)
        return true;

    const int first = layer::get_inner_ip_lyr_index(p);
    const int fragment = layer::get_inner_ip6_frag_index(p);
    bool valid = first >= 0 && fragment > first && fragment < p->num_layers &&
        p->layers[first].start == ip && p->layers[fragment].start == ip + parsed.length;
    size_t position = 0;
    for (int i = first; valid && i < fragment; ++i)
    {
        const auto& l = p->layers[i];
        valid = l.start == ip + position && l.length && l.length <= parsed.length - position;
        if (valid)
            position += l.length;
    }
    if (!valid || position != parsed.length)
    {
        ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_PREFIX_BAD;
        return false;
    }
    auto* saved = new SavedIp6Prefix;
    saved->length = parsed.length;
    saved->layer_count = fragment - first;
    saved->bytes = new uint8_t[saved->length];
    saved->layers = new Layer[saved->layer_count];
    memcpy(saved->bytes, ip, saved->length);
    saved->bytes[parsed.next_offset] = parsed.next; // Remove Fragment on reconstruction.
    for (unsigned i = 0; i < saved->layer_count; ++i)
    {
        saved->layers[i] = p->layers[first + i];
        saved->layers[i].start = saved->bytes + (p->layers[first + i].start - ip);
    }
    ft->ip6_prefix = saved;
    ft->ip_proto = static_cast<IpProtocol>(parsed.next);
    return true;
}

static bool RestoreIp6Prefix(FragTracker* ft, Packet* rebuilt)
{
    const auto* saved = ft->ip6_prefix;
    const int first = layer::get_inner_ip_lyr_index(rebuilt);
    const auto start = reinterpret_cast<uintptr_t>(rebuilt->pkt);
    const auto selected = reinterpret_cast<uintptr_t>(rebuilt->ptrs.ip_api.get_ip6h());
    if (!saved || first < 0 || selected < start || selected - start > Codec::PKT_MAX ||
        first + saved->layer_count > PacketManager::get_max_layers() ||
        !ax_fragment::ip6_rebuilt_fits(saved->length, ft->calculated_size,
            selected - start, Codec::PKT_MAX))
        return false;
    const auto ecn = ax_fragment::ip6_rebuilt_ecn(ft->ip6_ecn_seen, (saved->bytes[1] >> 4) & 3);
    if (ecn == 0xff)
        return false;
    auto* ip = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(selected));
    memcpy(ip, saved->bytes, saved->length);
    ip[1] = (ip[1] & 0xcf) | (ecn << 4);
    for (unsigned i = 0; i < saved->layer_count; ++i)
    {
        rebuilt->layers[first + i] = saved->layers[i];
        rebuilt->layers[first + i].start = ip + (saved->layers[i].start - saved->bytes);
    }
    rebuilt->num_layers = first + saved->layer_count;
    rebuilt->ptrs.ip_api.set(reinterpret_cast<const ip::IP6Hdr*>(ip));
    rebuilt->data = ip + saved->length;
    rebuilt->ip_proto_next = ft->ip_proto;
    return true;
}

static void RejectIp6Rebuild(FragTracker* ft, Packet* p)
{
    ft->frag_flags |= FRAG_BAD | FRAG_DROP_FRAGMENTS | FRAG_PREFIX_BAD;
    delete_tracker(ft);
    DropTrackedFragment(p, ft);
}
