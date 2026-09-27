-- Native packet policy for Snort 3.12.2.0. See README.md before deployment.
-- This is independent of the AX HTTP matcher and contains no agent credentials.
local source = debug.getinfo(1, 'S').source
assert(source:sub(1, 1) == '@', 'load this profile from a file')
local directory = source:sub(2):match('^(.*[/\\])') or './'
local states_file = assert(io.open(directory .. 'protocol.states', 'r'))
local states = states_file:read('*a')
states_file:close()
local builtin_file = assert(io.open(directory .. 'protocol-builtins.rules', 'r'))
local builtin_rules = builtin_file:read('*a')
builtin_file:close()
local validation_file = assert(io.open(directory .. 'protocol-validation.rules', 'r'))
local validation_rules = validation_file:read('*a')
validation_file:close()
local validation_seen = {}
for line in validation_rules:gmatch('[^\n]+') do
    if line:match('^%s*[^#%s]') then
        local sid = assert(line:match('; sid:(%d+);'), 'missing protocol validation SID')
        assert(not validation_seen[sid], 'duplicate protocol validation SID')
        validation_seen[sid] = true
        states = states .. '\ndrop ( gid:1; sid:' .. sid .. '; enable:yes; )'
    end
end

network = {
    checksum_eval = 'all', checksum_drop = 'all',
    min_ttl = 1, layers = 16, max_ip_layers = 1, max_ip6_extensions = 8,
}

stream = {
    require_3whs = 0, max_flows = 4096,
    allowlist_cache = { enable = false, move_on_excess = false },
}
-- Match reassembly policy to the protected endpoint OS before deployment.
stream_ip = {
    policy = 'linux', max_frags = 4096, max_overlaps = 1,
    min_frag_length = 0, min_ttl = 1, session_timeout = 30,
}
stream_tcp = {
    policy = 'linux', track_only = false, no_ack = false,
    reassemble_async = true, max_window = 1073725440, overlap_limit = 8,
    queue_limit = { max_bytes = 131072, max_segments = 256 },
    embryonic_timeout = 15, session_timeout = 120, idle_timeout = 300,
}
stream_udp = { session_timeout = 30 }
stream_icmp = { session_timeout = 30 }

-- Permit the inline normalizer to block invalid TCP state and make overlapping
-- retransmitted bytes consistent. Do not strip valid IP/TCP extension options.
normalizer = { tcp = { ips = true, block = true, trim_win = true } }

-- Native queued events apply their actions when processed. The default log=3
-- can let three earlier advisory decoder events hide a later drop. Process the
-- whole bounded queue; this is an enforcement setting, not merely verbosity.
event_queue = { max_queue = 512, log = 512, process_all_events = true }
-- Native text matches are deduplicated into separate action groups. Keep the
-- bounded per-group capacity above this profile's text-rule counts.
search_engine = { max_queue_events = 100 }

ips = {
    -- Omit unrelated builtin OTNs entirely: disabled-but-loaded events can still
    -- consume queue capacity before their policy state is checked.
    mode = 'inline', enable_builtin_rules = false,
    default_rule_state = 'no', states = states,
    rules = builtin_rules .. '\n' .. validation_rules,
}

alert_json = { fields = 'timestamp pkt_num proto src_ap dst_ap rule action msg' }
