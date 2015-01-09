require "lunit"
local cjson = require "cjson"
local raven = require "raven"

local string_match   = string.match
local print = print

module("sanity", lunit.testcase )

function test_new()
   local rvn, msg = raven:new("api-key")
   assert_not_nil(rvn)
   assert_equal("bugsnag-lua/0.1", rvn.client_id)
end

function test_new1()
   local rvn, msg = raven:new()
   assert_nil(rvn)
   assert_equal("empty apiKey", msg)
end

function test_new2()
   local rvn, msg = raven:new("api-key", { host = 'example.com', port = 90 })
   assert_not_nil(rvn)
   assert_equal("bugsnag-lua/0.1", rvn.client_id)
   assert_equal("example.com", rvn.host)
   assert_equal(90, rvn.port)
end
