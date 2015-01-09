require "lunit"
local socket = require "socket"
local raven = require "raven"
local cjson = require "cjson"
local posix = require "posix"

local print = print
local error = error
local string_find    = string.find
local string_sub     = string.sub
local string_match   = string.match
local os_exit        = os.exit
local random         = math.random

math.randomseed(os.time())

module("test_http", lunit.testcase)

local server = {}
local rvn
local dsn
local port = -1

function setup()
   port = random(20000, 65535)
   local sock = socket.tcp()
   assert(sock)
   assert(sock:bind("*", port))
   assert(sock:listen(64))
   server.sock = sock
end

function teardown()
   -- socket has already been closed in http_responde
   --server.sock:close()
end

local function get_body(response)
   local i = assert(string_find(response, "\n\n"))
   return string_sub(response, i + 1)
end

local function get_config()
   return { host = '127.0.0.1', port = port }
end

local function http_read(sock)
   local content_len
   local function get_data()
       return function() return sock:receive("*l") end
   end
   for res, err in get_data() do
      if res == "" then
         break
      end
      local s1, s2, len = string_find(res, "Content%-Length: (%d+)")
      if s1 and s2 then
         content_len = len
      end
   end
   local res, err = sock:receive(content_len)

   if not res then
      error("receive failed: " .. err)
   end
   return res
end

local function http_responde(sock)
   sock:send("HTTP/1.1 200 OK\r\nServer: nginx/1.2.6\r\nDate: Mon, 10 Mar 2014 22:25:51 GMT\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Language: en-us\r\nExpires: Mon, 10 Mar 2014 22:25:51 GMT\r\nVary: Accept-Language, Cookie\r\nLast-Modified: Mon, 10 Mar 2014 22:25:51 GMT\r\nCache-Control: max-age=0\r\n\r\nOK")
   sock:close()
end

function test_capture_message()
   local cpid = posix.fork()
   if cpid == 0 then
      rvn = raven:new('api-key', get_config())
      local ok = rvn:captureMessage("Sentry is a realtime event logging and aggregation platform.")
      assert_not_nil(ok)
      teardown = os_exit
   else
      local client = server.sock:accept()
      local json_str = http_read(client)
      --local json_str = get_body(res)
      local json = cjson.decode(json_str)
      http_responde(client)

      assert_not_nil(json)
      assert_equal("api-key", json.apiKey)
      assert_not_nil("lua", json.events)
      posix.wait(cpid)
   end
end

function test_capture_exception()
   local cpid = posix.fork()
   if cpid == 0 then
      rvn = raven:new('api-key', get_config())
      local ok = rvn:captureException({{}})
      assert_not_nil(ok)
      teardown = os_exit
   else
      local client = server.sock:accept()
      local json_str = http_read(client)
      --local json_str = get_body(res)
      local json = cjson.decode(json_str)
      http_responde(client)

      assert_not_nil(json)
      assert_equal("api-key", json.apiKey)
      assert_not_nil("lua", json.events)
      posix.wait(cpid)
   end
end
