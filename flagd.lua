#!/usr/bin/lua

-- flagd - allows for simple flag captures for Defcon-style Capture-The-Flag challenges
-- Hosted on Github at https://github.com/AlexWebr/flagd
-- Written by Alex Weber <alexwebr@gmail.com>

-- This program requires liblua-md5 and luasocket
-- These can be installed using 'luarocks'.
-- This program is tested with Lua 5.1.

print [[

      _/_/  _/                            _/
   _/      _/    _/_/_/    _/_/_/    _/_/_/
_/_/_/_/  _/  _/    _/  _/    _/  _/    _/
 _/      _/  _/    _/  _/    _/  _/    _/
_/      _/    _/_/_/    _/_/_/    _/_/_/
                           _/
                      _/_/
]]

-- Load libs
hash = require("md5").sumhexa
socket = require "socket"

-- Load configuration
if not arg[1] then
  print "ERROR: You must specify a path to a configuration file"
  os.exit(5)
end
dofile(tostring(arg[1]))
required_configs = {
  { param = "teams",           type = "table"  },
  { param = "flags",            type = "table"  },
  { param = "port",            type = "number" },
  { param = "admin_log",       type = "string" },
  { param = "capture_log",     type = "string" },
  { param = "ip_address",      type = "string" },
  { param = "submission_delay",type = "number" },
  { param = "show_flag_descriptions",   type = "boolean" },
}
-- Validate configuration
for _,v in ipairs(required_configs) do
  if _G[v.param] == nil then
    print("ERROR: Configuration does not contain required parameter '" .. v.param .. "' [" .. v.type .. "]")
    os.exit(1)
  elseif type(_G[v.param]) ~= v.type then
    print("ERROR: Parameter '" .. v.param .. "' should be a " .. v.type .. ", but is a " .. type(_G[v.param]))
    os.exit(2)
  end
end
print("Configuration loaded from '" .. tostring(arg[1]) .. "'")

-- Open the administrative log file, make sure we can append
alog, msg = io.open(admin_log, "a")
if not alog then
  print("ERROR: Could not open administrative log file '" .. admin_log .. "' [" .. msg .. "]")
  os.exit(6)
end
print("Logging administrative information to '" .. admin_log .. "'")

-- Open the capture log file, make sure we can append
clog, msg = io.open(capture_log, "a")
if not clog then
  print("ERROR: Could not open the capture log file '" .. capture_log .. "' [" .. msg .. "]")
  os.exit(6)
end
print("Logging captures to '" .. capture_log .. "'")

-- Calculate all hashes in advance, so that we can do hashtable lookups FOR SPEED
io.write("Precalculating " .. tostring(#teams * #flags) .. " hashes before accepting connections...")
io.flush()
hashes = {}
for _,t in ipairs(teams) do
  for i,f in ipairs(flags) do
    -- Index the table by the hash FOR SPEED
    hashes[ hash(t.name .. ":" .. t.pass .. ":" .. string.lower(f.sec)) ] = {team = t.name, number = i, desc = f.desc, complete = false}
  end
end
print " done."

-- Create our single listening socket - we send and receive with this
s = socket.udp()
s:setsockname(ip_address, port)
if not s:getsockname() then
  print("ERROR: Could not bind to port " .. tostring(port))
  os.exit(3)
end
print("flagd up and listening on " .. ip_address .. ":" .. port .. " (started in " .. os.clock() .. " seconds)")

-- Write critical information to admin log
alog:write("\nSTART: flagd started at " .. os.date() .. "\n")
alog:write("STAT: started in " .. os.clock() .. " seconds\n")
alog:write("STAT: precomputed " .. #teams * #flags .. " hashes\n")
alog:write("STAT: bound to " .. ip_address .. ":" .. port .. "\n")
alog:write("STAT: config file at " .. arg[1] .. "\n")
alog:flush()

-- Prevent brute-forcing by tracking the last submission time
last_submission_time = {}
-- Main packet receiving/processing/responding loop
-- No async here! We block on receivefrom()
while true do
  -- We use MD5, we so only accept 32 bytes per datagram
  local payload, addr, port = s:receivefrom(32)

  -- If an IP has tried already in the last submission_delay seconds, tell them and don't process the submission
  if os.time() - (last_submission_time[addr] or 0) < submission_delay then
    s:sendto("NO BRUTE\n", addr, port)
    alog:write("["..os.date().."] BRUTE: " .. addr .. "\n")
    alog:flush()
  else
    if #payload == 32 and string.match(payload, "^[a-fA-F0-9]+$") then
      -- We want to account for md5sum implementations that output uppercase hex letters
      local hash = hashes[string.lower(payload)]
      if hash then -- If the hash they gave us is a valid one (e.g., real team, real flag)
        if hash.complete then
          s:sendto("ALREADY CAPTURED\n", addr, port)
          alog:write("["..os.date().."] ALREADY CAPTURED: '" .. hash.team .. "', flag #" .. hash.number .. ", " .. addr .. "\n")
          alog:flush()
        else -- If this is the first time this hash has been done, we write to the log
          hash.complete = true
          s:sendto("CONGRATULATIONS - FLAG "..tostring(hash.number).." CAPTURED\n", addr, port)
          clog:write("["..os.date("%a %I:%M%p").."] Team '" .. hash.team .. "' captured flag #" ..  tostring(hash.number) .. "!")
          if show_flag_descriptions and hash.desc then
            clog:write(" (" .. hash.desc .. ")") -- include the hash description if there is one present, and they are not globally disabled
          end
          clog:write("\n")
          clog:flush()
          alog:write("["..os.date().."] CAPTURE: '" .. hash.team .. "', flag #" .. hash.number .. ", " .. addr .. "\n")
          alog:flush()
        end
      else -- If there is no matching hash
        s:sendto("NOPE.\n", addr, port)
        alog:write("["..os.date().."] NO MATCH: " .. addr .. "\n")
        alog:flush()
      end
    else
      s:sendto("EXPECTED 32 HEX CHARACTERS\n", addr, port)
      alog:write("["..os.date().."] BAD FORMAT: " .. addr .. "\n")
      alog:flush()
    end
  end
  -- Reset the timer for a host on every submission.
  last_submission_time[addr]  = os.time()
end
