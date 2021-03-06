
require "lunit"
local socket = require "socket"
local raven = require "raven"
local cjson = require "cjson"

local print = print
local error = error
local xpcall = xpcall

module("test_exceptions", lunit.testcase)

local rvn
local port = 29999

function test_capture_message_connection_refused_http()
   local rvn = raven:new('api-key', { port = 23, host = '127.0.0.1' })
   local id, err = rvn:captureMessage("IF YOU ARE READING THIS IT IS CORRECT; THIS TEST SHOULD GENERATE AN ERROR.")

   assert_nil(id)
   assert_equal("connection refused", err)
end

function test_capture_message_connection_refused_http_xpcall()
   local rvn = raven:new('api-key', { port = 23, host = '127.0.0.1' })
   local capture_err = rvn:gen_capture_err()
   local ok, err = xpcall(function () error("bad") end, capture_err)
   assert_equal(false, ok)
   assert_match("bad", err)
   assert_match("bad", rvn.exception.errorClass)
   local id, err = rvn:send_report()
   assert_nil(id)
   assert_equal("connection refused", err)
end
