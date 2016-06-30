-------------------------------------------------------------------
-- raven.lua: a Lua Raven client used to send errors to
-- <a href="http://sentry.readthedocs.org/en/latest/index.html">Sentry</a>
--
-- According to client development guide
--
--    The following items are expected of production-ready clients:
--    <ul>
--    <li> DSN configuration √</li>
--    <li> Graceful failures (e.g. Sentry server unreachable) √</li>
--    <li> Scrubbing w/ processors</li>
--    <li> Tag support √</li>
--    </ul>
--
-- To test a DSN configuration:
-- <pre>$ lua raven.lua test [DSN]</pre>
--
-- @author JGC <jgc@cloudflare.com>
-- @author Jiale Zhi <vipcalio@gmail.com>
-- @copyright (c) 2013-2014, CloudFlare, Inc.
--------------------------------------------------------------------

--
-- Originally written for sentry, ported to support bugsnag.
-- Comments are also rewritten for better understanding.
--

--pcall(require("luacov"))
local json = require("cjson")
local debug = require("debug")

local ngx = ngx
local arg = arg
local setmetatable = setmetatable
local tostring = tostring
local xpcall = xpcall

local os_date        = os.date
local os_time        = os.time
local debug_getinfo  = debug.getinfo
local json_encode    = json.encode
local string_format  = string.format
local string_match   = string.match
local string_find    = string.find
local string_sub     = string.sub
local table_insert   = table.insert
local socket

local debug = false
local payload_version = '2'
local catcher_trace_level = 4

local _M = {
  notifier = {
    url = "https://github.com/APItools/bugsnag-lua",
    name = "Bugsnag Lua",
    version = "0.1"
  }
}

local mt = {
  __index = _M
}

local _json = {}
local _exception = {{}}

-- check if nginx exists.
if not ngx then
  local ok, luasocket = pcall(require, "socket")
  if not ok then
    error("No socket library found, you need ngx.socket or luasocket.")
  end
  socket = luasocket
else
  socket = ngx.socket
end

-- check for env for table.new.
local ok, new_tab = pcall(require, "table.new")
if not ok then
  new_tab = function (narr, nrec) return {} end
end

-- check if env for table.clear.
local ok, clear_tab = pcall(require, "table.clear")
if not ok then
  clear_tab = function(tab)
    for k, v in pairs(tab) do
      tab[k] = nil
    end
  end
end

-- log: log output to print of nginx.
local function log(...)
  if not ngx then
    print(...)
  else
    ngx.log(ngx.NOTICE, ...)
  end
end

-- backup logging when cannot send data to bugsnag.
local function errlog(...)
  if not ngx then
    print("[ERROR]", ...)
  else
    ngx.log(ngx.ERR, ...)
  end
end


-- _get_server_name: returns current nginx server name if ngx_lua is used.
-- If ngx_lua is not used, returns "undefined"
local function _get_server_name()
  return ngx and ngx.var.server_name or "undefined"
end

-- backtrace: trace back the error.
local function backtrace(level)
  local frames = {}
  level = level + 1

  while true do
    local info = debug_getinfo(level, "Snl")
    if not info then
      break
    end

    table_insert(frames, #frames + 1, {
                   file = info.short_src,
                   ["method"] = info.name,
                   lineNumber = info.currentline,
    })

    level = level + 1
  end
  return frames
end

--- Create a new bugsnag client. Two parameters:
-- @param self raven client
-- @param conf client configuration. Conf should be a hash table.
--             <pre>{ app = { version = '0.0.1', releaseStage = 'Staging' }}</pre>
-- @return     a new raven instance
-- @usage
-- local raven = require "raven"
-- local rvn = raven:new(dsn, { app = { version = '0.0.1', releaseStage = 'Staging' }})
function _M.new(self, apiKey, conf)
  if not apiKey then
    return nil, "empty api-key"
  end

  local obj = {
    client_id = string_format("bugsnag-lua/%s", _M.notifier.version),
    apiKey = apiKey,
    level = "error",
    protocol = "https",
    host = "notify.bugsnag.com",
    port = 80,
    request_uri = "/",
    notifier = _M.notifier
  }
  if conf then
    for key, value in pairs(conf) do
      obj[key] = value
    end
  end
  return setmetatable(obj, mt)
end

--- Send an exception to Sentry.
-- see <a href="http://sentry.readthedocs.org/en/latest/developer/interfaces/index.html#sentry.interfaces.Exception">reference</a>.
--
-- @param self       raven client
-- @param exception  a hash table describing an exception. For example:
-- <pre>{{
--     ["type"] = "SyntaxError",
--     ["value"] = "Wattttt!",
--     ["module"] = "__builtins__",
--     stacktrace = {
--         frames = {
--             { filename = "/real/file/name", func = "myfunc", lineno" = 3 },
--             { filename = "/real/file/name", func = "myfunc1", lineno" = 10 },
--         }
--     }
-- }}</pre>
--
-- @param conf       capture configuration. Conf should be a hash table.
--                   Possible keys are: "tags", "trace_level". "tags" will be
--                   send to entry together with "tags" in client
--                   configuration. "trace_level" is used for geting stack
--                   backtracing. You shouldn't pass this argument unless you
--                   know what you are doing.
-- @return           On success, return event id. If not success, return nil and
--                   an error string.
-- @usage
-- local raven = require "raven"
-- local rvn = raven:new(dsn, { tags = { foo = "bar", abc = "def" },
--     logger = "myLogger" })
-- local id, err = rvn:captureException(exception,
--     { tags = { foo = "bar", abc = "def" }})
function _M.captureException(self, exception, conf)
  local trace_level
  if not conf then
    conf = { trace_level = 2 }
  elseif not conf.trace_level then
    conf.trace_level = 2
  else
    conf.trace_level = conf.trace_level + 1
  end

  trace_level = conf.trace_level

  clear_tab(_json)
  exception[1].stacktrace = backtrace(trace_level)
  -- _json.culprit = self.get_culprit(conf.trace_level)

  -- because whether tail call will or will not appear in the stack back trace
  -- is different between PUC-lua or LuaJIT, so just avoid tail call
  local ok, err = self:send_report(exception[1], conf)
  return ok, err
end

--- Send a message to entry.
--
-- @param self       raven client
-- @param message    arbitrary message (most likely an error string)
-- @param conf       capture configuration. Conf should be a hash table.
--                   Possiable keys are: "tags", "trace_level". "tags" will be
--                   send to entry together with "tags" in client
--                   configuration. "trace_level" is used for geting stack
--                   backtracing. You shouldn't pass this argument unless you
--                   know what you are doing.
-- @return           On success, return event id. If not success, return nil and
--                   error string.
-- @usage
-- local raven = require "raven"
-- local rvn = raven:new(dsn, { tags = { foo = "bar", abc = "def" },
--     logger = "myLogger" })
-- local id, err = rvn:captureMessage("Sample message",
--     { tags = { foo = "bar", abc = "def" }})
function _M.captureMessage(self, message, conf)
  if not conf then
    conf = { trace_level = 2 }
  elseif not conf.trace_level then
    conf.trace_level = 2
  else
    conf.trace_level = conf.trace_level + 1
  end

  clear_tab(_json)
  local exception = { message = message }

  -- _json.culprit = self.get_culprit(conf.trace_level)

  local ok, err = self:send_report(exception, conf)
  return ok, err
end

-- send_report: send report for the captured error.
--
-- Parameters:
--   json: json table to be sent. Don't need to fill event_id, culprit,
--   timestamp and level, send_report will fill these fields for you.
function _M.send_report(self, exception, conf)
  local payload = {
    apiKey  = self.apiKey,
    notifier  = self.notifier
  }

  if not exception then
    exception = self.exception
    if not exception then
      return
    end
  end

  local event = { exceptions = { exception } }
  if self.app then
    event.app = self.app
  end
  -- add payload version.
  event.payloadVersion = payload_version
  event.device = { hostname = _get_server_name() }

  if conf then
    if conf.metaData then
      event.metaData = conf.metaData
    end

    if conf.tags then
      if not payload.tags then
        payload.tags = { conf.tags }
      else
        payload.tags[#payload.tags + 1] = conf.tags
      end
    end
    if conf.level then
      payload.level = conf.level
    end
  end

  payload.events = { event }

  local json_str = json_encode(payload)
  local ok, err = self:http_send(json_str)

  if not ok then
    errlog("Failed to send to bugsnag: ", err, " ",  json_str)
    return nil, err
  end
  return ok
end

-- get culprit using given level
function _M.get_culprit(level)
  local culprit

  level = level + 1
  local info = debug_getinfo(level, "Snl")
  if info.name then
    culprit = info.name
  else
    culprit = format("%s:%s", info.short_src, info.linedefined)
  end
  return culprit
end

function _M.split_error(exception)
  -- extract message from errors like: "/usr/share/lua/5.1/raven.lua:545: attempt to concatenate a nil value"
  local file,message = string_match(exception, "^(%g+):%d+:%s*(.+)$")
  return file,message
end

-- catcher: used to catch an error from xpcall.
function _M.catcher(self, err)
  if debug then
    log("catch: ", err)
  end

  clear_tab(_exception[1])
  local file, message = _M.split_error(err)
  _exception[1].errorClass = message
  _exception[1].stacktrace = backtrace(catcher_trace_level)
  _exception[1].groupingHash = file

  clear_tab(_json)

  return _exception[1]
end

--- Call function f with parameters ... wrapped in a xpcall and
-- send any exception to entry. Returns a boolean indicating whether
-- the function execution worked and an error if not
-- @param self  raven client
-- @param f     function to be called
-- @param ...   function "f" 's arguments
-- @return      the same with xpcall
-- @usage
-- function func(a, b, c)
--     return a * b + c
-- end
-- return rvn:call(func, a, b, c)
function _M.call(self, f, ...)
  -- When used with ngx_lua, connecting a tcp socket in xpcall error handler
  -- will cause a "yield across C-call boundary" error. To avoid this, we
  -- move all the network operations outside of the xpcall error handler.
  local json_exception
  local res = { xpcall(f, function (err)
                         local ok
                         ok, json_exception = pcall(self.catcher, self, err)
                         if not ok then
                           -- when failed, json_exception is error message
                           errlog(json_exception)
                         end
                         return err
                       end,
                       ...) }
  if json_exception then
    self:send_report(json_exception)
  end

  return unpack(res)
end

function _M.gen_capture_err(self)
  return function (err)
    local ok, exception = pcall(self.catcher, self, err)
    if not ok then
      -- when failed, exception is error message
      errlog(exception)
      self.exception = nil
    else
      self.exception = exception
    end
    return err
  end
end

-- HTTP request template
local http_request_template = "POST %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: %s\r\n\r\n%s"

-- http_send_core: do the actual network send. Expects an already
-- connected socket.
function _M.http_send_core(self, json_str)
  local req = string_format(http_request_template,
                            self.request_uri,
                            self.host,
                            #json_str,
                            self.client_id,
                            json_str)
  local bytes, err = self.sock:send(req)
  if not bytes then
    return nil, err
  end

  local res, err = self.sock:receive("*a")
  if not res then
    return nil, err
  end

  local s1, s2, status = string_find(res, "HTTP/%d%.%d (%d%d%d) %w+")
  if status ~= "200" then
    return nil, "Server response status not 200:" .. (status or "nil")
  end

  local s1, s2 = string_find(res, "\r\n\r\n")
  if not s1 and s2 then
    return ""
  end
  return string_sub(res, s2 + 1)
end

-- http_send: actually sends the structured data to the bugsnag server using
-- HTTP
function _M.http_send(self, json_str)
  local ok, err
  local sock

  sock, err = socket.tcp()
  if not sock then
    return nil, err
  end
  self.sock = sock

  ok, err = sock:connect(self.host, self.port)
  if not ok then
    return nil, err
  end

  ok, err = self:http_send_core(json_str)

  sock:close()
  return ok, err
end

-- test client’s configuration from CLI
local function bugsnag_test(apiKey)
  local bugsnag, err = _M.new(_M, apiKey)

  if not bugsnag then
    print(err)
  end

  print(string_format("Using api key:\n  %s\n", apiKey))
  print(string_format([[Client configuration:
  Host        : %s
  Port        : %s
  Protocol    : %s
  secret_key     : %s
]], bugsnag.host, bugsnag.port, bugsnag.protocol, bugsnag.secret_key))
    print("Send a message...")
  local msg = "Hello from raven-lua!"
  local ok, err = bugsnag:captureMessage(msg)

  if ok then
    print("success!")
  else
    print("failed to send message '" .. msg .. "'\n" .. tostring(err))
  end

  print("Send an exception...")
  local exception = {{
      ["errorClass"] = "SyntaxError",
      ["message"] = "Wattttt!",
      --["module"] = "__builtins__"
  }}
  local ok, err = bugsnag:captureException(exception)

  if ok then
    print("success!")
  else
    print("failed to send message '" .. msg .. "'\n" .. tostring(err))
  end

  bugsnag:call(function()
      print('error ' .. nil)
      print('failed')
  end)

  print("All done.")
end

if arg and arg[1] and arg[1] == "test" then
  local apiKey = arg[2]
  bugsnag_test(apiKey)
end

return _M
