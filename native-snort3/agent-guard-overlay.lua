-- Optional original native signatures, scoped by explicit operator variables.
-- AX_NATIVE_OVERLAY must be perimeter, http, or both. See README.md.
local source = debug.getinfo(1, 'S').source
assert(source:sub(1, 1) == '@', 'load this profile from a file')
local directory = source:sub(2):match('^(.*[/\\])') or './'
include(directory .. 'protocol-ips.lua')

local function required(name)
    local value = os.getenv(name)
    assert(value and value:match('%S'), name .. ' is required for this overlay')
    assert(not value:find('[\r\n]'), name .. ' must be a single line')
    return value
end

local mode = required('AX_NATIVE_OVERLAY')
assert(mode == 'perimeter' or mode == 'http' or mode == 'both',
    'AX_NATIVE_OVERLAY must be perimeter, http, or both')
local perimeter = mode == 'perimeter' or mode == 'both'
local http = mode == 'http' or mode == 'both'

-- A comma-separated list of explicit decimal ports works for both native rule
-- variables and inspector bindings; ranges, negation, and 'any' are rejected.
local function ports(name)
    local value = required(name)
    assert(value:match('^%d[%d,]*%d$') or value:match('^%d$'), name .. ' must contain decimal ports')
    assert(not value:find(',,', 1, true), name .. ' contains an empty port')
    local result, seen = {}, {}
    for token in value:gmatch('[^,]+') do
        local port = tonumber(token)
        assert(token == tostring(port) and port >= 1 and port <= 65535, name .. ' contains an invalid port')
        assert(not seen[port], name .. ' contains a duplicate port')
        seen[port] = true
        result[#result + 1] = token
    end
    return '[' .. table.concat(result, ',') .. ']', table.concat(result, ' ')
end

ips.variables = { nets = {}, ports = {} }
if perimeter then
    ips.variables.nets.AGENT_NET = required('AX_AGENT_NET')
    ips.variables.nets.BROKER_NET = required('AX_BROKER_NET')
    ips.variables.ports.BROKER_PORTS = ports('AX_BROKER_PORTS')
end
if http then
    ips.variables.nets.INSPECT_CLIENTS = required('AX_INSPECT_CLIENTS')
    ips.variables.nets.INSPECT_SERVERS = required('AX_INSPECT_SERVERS')
    local rule_ports, bind_ports = ports('AX_INSPECT_PORTS')
    ips.variables.ports.INSPECT_PORTS = rule_ports
    -- These are finite inspection depths, not fail-closed transfer-size limits.
    -- The plaintext HTTP hop must enforce the corresponding body limits itself.
    http_inspect = { request_depth = 1048576, response_depth = 10485760 }
    binder = {
        { when = { proto = 'tcp', ports = bind_ports, role = 'server',
                   nets = ips.variables.nets.INSPECT_SERVERS },
          use = { type = 'http_inspect' } },
    }
end

local file = assert(io.open(directory .. '../pkg/security/snort/imports/agent-guard-snort3/native-only.rules', 'r'))
local rules, states, seen = {}, {}, {}
local total, perimeter_count, http_count = 0, 0, 0
for line in file:lines() do
    if line:match('^%s*[^#%s]') then
        local action = assert(line:match('^(%a+)%s'), 'invalid source rule action')
        local sid = assert(line:match('; sid:(%d+);'), 'missing source rule SID')
        assert(not seen[sid], 'duplicate source SID ' .. sid)
        seen[sid], total = true, total + 1
        local is_perimeter = line:find('$AGENT_NET', 1, true) ~= nil
        local is_http = line:find('$INSPECT_CLIENTS', 1, true) ~= nil
        assert(is_perimeter ~= is_http, 'ambiguous source sensor scope for SID ' .. sid)
        if is_perimeter then perimeter_count = perimeter_count + 1 else http_count = http_count + 1 end
        if (is_perimeter and perimeter) or (is_http and http) then
            rules[#rules + 1] = line
            states[#states + 1] = action .. ' ( gid:1; sid:' .. sid .. '; enable:yes; )'
        end
    end
end
file:close()
assert(total == 70 and perimeter_count == 7 and http_count == 63,
    'source native inventory changed; review sensor scoping before enabling it')
ips.rules = ips.rules .. '\n' .. table.concat(rules, '\n')
ips.states = ips.states .. '\n' .. table.concat(states, '\n')
