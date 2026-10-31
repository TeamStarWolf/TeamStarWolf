# Lua

Lua is a dynamically typed, garbage-collected, multi-paradigm language created by a team at the Pontifical Catholic University of Rio de Janeiro (Roberto Ierusalimschy, Luiz Henrique de Figueiredo, and Waldemar Celes) and first released in 1993. It is small, fast, and designed to embed in larger applications as a configuration and scripting layer. It runs on a register-based virtual machine (the reference implementation is written in portable C) and is used for game scripting, embedded configuration, network device logic, and application extension.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: procedural, functional, with prototype-style objects via tables |
| Typing | Dynamic, strong, with a small fixed set of types |
| First appeared | 1993 |
| Memory model | Automatic: incremental or generational tracing garbage collector |
| Reference implementation | [PUC-Rio Lua](https://www.lua.org/) (ANSI C) |
| Typical uses | Game scripting, embedded configuration, application extension |
| Governance | Core team at PUC-Rio; versioned releases, no formal committee |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [JavaScript](/languages/javascript.md), [languages index](/languages/README.md).

## Overview and history

Lua (Portuguese for moon) was created to give Brazilian engineers a configuration and data-description language that could be embedded in applications, at a time when import restrictions made buying commercial tools difficult. Its design priorities are a small footprint, portability across platforms through standard C, and a clean interface for embedding in host programs.

Lua is widely embedded: it scripts games (including the engines behind many titles), extends the Redis data store, drives configuration in the Nginx web server through OpenResty, and runs inside network devices and Adobe applications. The reference implementation is a small ANSI C codebase; the just-in-time compiler [LuaJIT](https://luajit.org/) is a separate, fast implementation that tracks Lua 5.1.

## Paradigm and type system

Lua is dynamically typed with a deliberately small set of types: `nil`, `boolean`, `number`, `string`, `function`, `table`, `userdata`, and `thread`. The table is the single data-structuring mechanism: it serves as array, dictionary, object, and namespace. Objects and inheritance are built from tables and metatables rather than a class keyword.

```lua
-- A table used as an object with a metatable for methods
local Point = {}
Point.__index = Point

function Point.new(x, y)
  return setmetatable({ x = x, y = y }, Point)
end
```

Numbers were a single floating-point type until Lua 5.3 introduced a distinct integer subtype.

## Toolchain and ecosystem

- Interpreter: `lua` runs scripts and an interactive prompt; `luac` precompiles to bytecode.
- Packaging: [LuaRocks](https://luarocks.org/) is the module manager and repository; a `rockspec` file describes a package.
- Alternative runtime: [LuaJIT](https://luajit.org/) offers a tracing just-in-time compiler and a foreign function interface to C.
- Linting: [luacheck](https://github.com/lunarmodules/luacheck) reports undefined globals and unused variables; [stylua](https://github.com/JohnnyMorganz/StyLua) formats.

```bash
luarocks install penlight
luac -p script.lua   # parse and check without running
```

## Syntax tour

```lua
-- Variables are global unless marked local
local name = "world"
print("hello, " .. name)   -- .. concatenates

-- Tables as array and as map
local squares = {}
for n = 0, 4 do squares[#squares + 1] = n * n end  -- {0,1,4,9,16}
local lookup = { a = 1, b = 2 }

-- Functions are first-class values
local function greet(who, excited)
  local tail = excited and "." or "."
  return "hi " .. who .. tail
end

-- Iteration
for key, value in pairs(lookup) do
  print(key, value)
end

-- Errors use pcall for protected calls
local ok, result = pcall(function()
  return tonumber("not a number") + 1
end)
if not ok then result = 0 end
```

## Idioms and different approaches

- Declare variables `local` by default; an undeclared assignment creates a global, which is a common source of bugs.
- Use tables for everything structured, and metatables to add behavior such as operator overloading or method lookup through `__index`.
- Numeric `for` loops (`for i = 1, n`) and the `ipairs`/`pairs` iterators cover most iteration.
- Multiple return values are idiomatic: `pcall` returns a success flag and the result, and functions often return a value plus an error.
- Lua uses 1-based indexing for its array convention; account for it when porting algorithms.

## Design principles

Lua aims to be a small, portable, embeddable language that does a few things well rather than offering one construct for every need. The whole interpreter fits in a small C library with no external dependencies, which is why it ends up inside games, databases, and routers. The single table type and the metatable mechanism give the language flexibility while keeping the core specification short. The project values backward stability within a version line but allows incompatible changes between major versions (for example 5.1 to 5.2 to 5.3).

## Standard library and notable packages

The standard library is intentionally small: modules for strings (with pattern matching rather than full regular expressions), tables, math, I/O, and OS access. The ecosystem extends it through LuaRocks: [Penlight](https://github.com/lunarmodules/Penlight) adds general utilities, [LuaSocket](https://github.com/lunarmodules/luasocket) adds networking, [OpenResty](https://openresty.org/) embeds Lua in Nginx, and [love2d](https://love2d.org/) is a game framework.

## Testing and packaging

[busted](https://lunarmodules.github.io/busted/) is a common behavior-style test framework; [luaunit](https://github.com/bluebird75/luaunit) offers xUnit-style assertions.

```lua
local luaunit = require("luaunit")

function testAdd()
  luaunit.assertEquals(2 + 3, 5)
end

os.exit(luaunit.LuaUnit.run())
```

A distributable module is described by a `rockspec` and published to LuaRocks with `luarocks upload`.

## Performance and concurrency

The reference interpreter is fast for a scripting language and compiles source to bytecode for a register-based virtual machine. [LuaJIT](https://luajit.org/) raises performance further with a tracing just-in-time compiler and often approaches compiled-language speed on numeric code. Concurrency is cooperative rather than preemptive:

- Coroutines (`coroutine.create`, `coroutine.yield`, `coroutine.resume`) provide collaborative multitasking within one operating-system thread.
- There is no built-in operating-system threading in the core; the host application or a library (such as one built on the C threading APIs) provides parallelism.
- Embedding hosts often run multiple independent Lua states, one per thread, to achieve parallel execution without shared mutable state.

## Common pitfalls

- Forgetting `local` creates a global variable silently; enable luacheck to catch it.
- Indexing a table with a key that does not exist returns `nil` rather than raising an error, so typos surface later.
- `nil` and `false` are the only falsy values; `0` and `""` are truthy, unlike in C.
- String pattern matching uses Lua patterns, not POSIX or PCRE regular expressions, so expressions do not translate directly.

## Secure coding

Lua is usually embedded in a host, so the main risk is giving untrusted scripts too much reach:

- Sandboxing untrusted Lua: scripts can call `os.execute`, `io.open`, `loadstring`/`load`, and `require`, which reach the file system and shell. Run untrusted code in a restricted environment that removes or wraps these globals; the host controls what the script's environment table exposes. Unsafe dynamic loading maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Command injection: `os.execute` and `io.popen` pass strings to the shell; never build them from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Loading bytecode: `load` on precompiled bytecode from an untrusted source can crash or subvert the interpreter because bytecode is not verified; only load bytecode you produced.
- Resource limits: untrusted scripts can loop forever or allocate without bound; the host should set instruction-count hooks and memory limits.
- Dependency supply chain: review LuaRocks modules before embedding them; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [luacheck](https://github.com/lunarmodules/luacheck) catches undefined globals and shadowing, and host applications commonly build a vetted environment table that whitelists safe standard-library functions.

## Learning resources

- [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/), the official language definition.
- [Programming in Lua](https://www.lua.org/pil/) by Roberto Ierusalimschy, with the first edition freely available online.
- [LuaRocks](https://luarocks.org/), the module repository.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [JavaScript](/languages/javascript.md)
- [All languages](/languages/README.md)
