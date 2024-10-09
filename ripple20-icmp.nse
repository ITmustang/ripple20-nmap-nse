local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local ipOps = require "ipOps"

description = [[
Checks for Ripple20 vulnerabilities in the target by sending a custom ICMP packet.
]]

author = "Modified by User"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

portrule = function()
    return false
end

hostrule = function(host)
    return true
end

action = function(host)
    local icmp_type = 8 -- Echo request
    local icmp_code = 0
    local identifier = 0x1234 -- Arbitrary identifier
    local sequence = 1 -- Sequence number
    local checksum = 0

    -- Create a payload for the ICMP packet
    local payload = "Ripple20Test"

    -- Use string.pack to create the ICMP header
    local icmp_header = string.pack(">BBHHH", icmp_type, icmp_code, checksum, identifier, sequence) .. payload

    -- Calculate checksum for the ICMP packet
    local function calculate_checksum(data)
        local sum = 0
        for i = 1, #data - 1, 2 do
            sum = sum + (data:byte(i) * 256 + data:byte(i + 1))
        end
        if #data % 2 == 1 then
            sum = sum + data:byte(#data)
        end
        sum = (sum >> 16) + (sum & 0xFFFF)
        sum = sum + (sum >> 16)
        return ~sum & 0xFFFF
    end

    checksum = calculate_checksum(icmp_header)
    icmp_header = string.pack(">BBHHH", icmp_type, icmp_code, checksum, identifier, sequence) .. payload

    -- Open a raw socket using nmap.new_socket()
    local icmp_socket = nmap.new_socket()
    local success, err = icmp_socket:pcap_open("eth0", 128, true, "ip proto \\icmp")

    if not success then
        -- Provide a default error message if 'err' is nil
        err = err or "Unknown error"
        return "Failed to open raw socket: " .. err
    end

    -- Set socket send timeout
    icmp_socket:set_timeout(5000)

    -- Send the ICMP packet using send()
    local status, send_err = icmp_socket:send(ipOps.ip_to_str(host.bin_ip), icmp_header)

    if not status then
        -- Provide a default error message if 'send_err' is nil
        send_err = send_err or "Unknown error"
        return "Failed to send ICMP packet: " .. send_err
    end

    -- Wait for a response from the host
    local response = icmp_socket:receive()
    icmp_socket:close()

    if response then
        -- Parse the ICMP response type and code
        local icmp_resp_type, icmp_resp_code = string.unpack(">BB", response:sub(1, 2))
        if icmp_resp_type == 0 then
            return "Host responded to ICMP Echo Request, potentially vulnerable to Ripple20."
        else
            return "Host responded with ICMP type " .. icmp_resp_type .. ", code " .. icmp_resp_code .. "."
        end
    else
        return "No response received from the host."
    end
end
