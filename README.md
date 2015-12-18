bugsnag-lua [![Build Status](https://travis-ci.org/APItools/bugsnag-lua.svg?branch=master)](https://travis-ci.org/APItools/bugsnag-lua)
=========

A small Lua interface to [Bugsnag](http://bugsnag.com/) that supports
the HTTP notification interface and also has a helpful wrapper function
`call()` that takes any arbitrary Lua function (with arguments) and executes
it, traps any errors and reports it automatically to Bugsnag.

Synopsis
========

```lua

    local bugsnag = require "raven"

    local bug = bugsnag:new("api-key", {app = { version = "0.0.1"}})

    -- Send a message to sentry
    local ok, err = bug:captureMessage(
      "Sentry is a realtime event logging and aggregation platform.",
      { tags = { abc = "def" } } -- optional
    )
    if not ok then
       print(err)
    end

    -- Send an exception to sentry
    local exception = {{
       ["errorClass"]= "SyntaxError",
       ["value"]= "Wattttt!",
       ["module"]= "__builtins__"
    }}
    local ok, err = bug:captureException(
       exception,
       { tags = { abc = "def" } } -- optional
    )
    if not ok then
       print(err)
    end

    -- Catch an exception and send it to sentry
    function bad_func(n)
       return not_defined_func(n)
    end

    -- variable 'ok' should be false, and an exception will be sent to sentry
    local ok = bug:call(bad_func, 1)

```
Documents
=========

See docs/index.html for more details.

Prerequisites
=============
```
    #for unit tests
    $luarocks install lunit
    $luarocks install luaposix

    #for generating docs
    $luarocks install ldoc
```
