# WebAssembly

WebAssembly (abbreviated Wasm) is a portable binary instruction format for a stack-based virtual machine, first released in 2017 and standardized by the World Wide Web Consortium. It is a compilation target rather than a language people write by hand: compilers for C, C++, Rust, and others emit Wasm modules that run at near-native speed in web browsers and, through standalone runtimes, on servers and at the edge. It is designed to run inside a sandbox with explicit, capability-based access to the outside world.

| Attribute | Value |
|---|---|
| Paradigm | Low-level compilation target; stack-based virtual machine |
| Typing | Statically typed instruction set (i32, i64, f32, f64, plus reference types) |
| First appeared | 2017 |
| Memory model | Linear memory (a resizable byte array); the host manages collection |
| Reference implementation / runtime | Browser engines; standalone runtimes [Wasmtime](https://wasmtime.dev/), [Wasmer](https://wasmer.io/), [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) |
| Typical uses | Performance-sensitive web code, plugins, edge and serverless compute |
| Governance | [W3C WebAssembly Working Group](https://www.w3.org/groups/wg/wasm/) |

Related: [JavaScript](/languages/javascript.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

WebAssembly grew out of earlier efforts to run fast, low-level code in browsers, notably asm.js and Google's Native Client. Browser vendors (from Mozilla, Google, Microsoft, and Apple) designed it jointly, and it reached a cross-browser release in 2017. The core specification became a W3C recommendation in 2019. The goals were a compact binary format that loads and compiles quickly, predictable near-native performance, and a sandbox that fits the security model of the web.

Although it started in the browser, WebAssembly now runs outside it through standalone runtimes, where the [WebAssembly System Interface (WASI)](https://wasi.dev/) defines a portable, capability-based way for modules to reach files, clocks, and networking. The [Bytecode Alliance](https://bytecodealliance.org/) stewards several of the server-side runtimes and tools.

## Paradigm and type system

WebAssembly is not a surface language; it is a typed instruction set for a stack machine. Instructions push and pop values of four numeric types (`i32`, `i64`, `f32`, `f64`), with later proposals adding vector (`v128`) and reference types. A module declares functions, a linear memory, tables of references, globals, and imports and exports. Code is validated against the type rules before it runs, so a module cannot read outside its declared memory or jump to an arbitrary address.

```wat
;; WebAssembly text format (.wat): a function that adds two i32 values
(module
  (func (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add))
```

People usually write a high-level language and compile it; the text format above exists mainly for tooling and inspection.

## Toolchain and ecosystem

- Producing modules: [Emscripten](https://emscripten.org/) compiles C and C++; Rust targets `wasm32-unknown-unknown` or `wasm32-wasip1` through `rustup` and `cargo`; [TinyGo](https://tinygo.org/) and [AssemblyScript](https://www.assemblyscript.org/) (a TypeScript-like language) also emit Wasm.
- Tooling: [wabt](https://github.com/WebAssembly/wabt) converts between the binary and text formats and validates modules; [Binaryen](https://github.com/WebAssembly/binaryen) optimizes them; [wasm-tools](https://github.com/bytecodealliance/wasm-tools) inspects and manipulates them.
- Runtimes: browsers run Wasm through the JavaScript `WebAssembly` API; standalone runtimes include [Wasmtime](https://wasmtime.dev/), [Wasmer](https://wasmer.io/), and [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime).
- Packaging: the [component model](https://component-model.bytecodealliance.org/) and registries such as [warg](https://warg.io/) aim to standardize distributing and composing Wasm components.

```bash
rustc --target wasm32-wasip1 hello.rs -o hello.wasm
wasmtime hello.wasm
```

## Syntax tour

Developers rarely write WebAssembly directly, but the text format makes the model concrete:

```wat
(module
  ;; Import a function the host provides
  (import "env" "log" (func $log (param i32)))

  ;; Declare a linear memory of one 64 KiB page
  (memory (export "memory") 1)

  ;; A loop that sums 0..n using a local accumulator
  (func (export "sum") (param $n i32) (result i32)
    (local $i i32) (local $acc i32)
    (loop $continue
      local.get $i
      local.get $n
      i32.lt_s
      (if (then
        local.get $acc
        local.get $i
        i32.add
        local.set $acc
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $continue)))
    local.get $acc))
```

## Idioms and different approaches

- Treat WebAssembly as a target: write C, C++, Rust, or another supported language, and let the compiler emit the module.
- Keep the boundary small: cross the JavaScript-to-Wasm call boundary in bulk rather than per element, because each crossing has overhead.
- Pass complex data through the shared linear memory with an agreed layout, or use wasm-bindgen (Rust) and Emscripten glue to generate the marshaling code.
- Prefer the component model and WASI for portable modules that must reach the outside world through defined interfaces rather than ad hoc imports.
- Profile before porting: Wasm helps CPU-bound inner loops, not code dominated by DOM or network work.

## Design principles

WebAssembly was designed to be fast to compile and run, compact on the wire, portable across architectures, and safe by construction. Safety comes from validation (a module is type-checked before execution), a sandbox with no ambient authority (a module can touch only its own linear memory and the imports the host grants), and the absence of direct access to the host's address space. Capability-based access, embodied by WASI, means a module gets a file or socket only if the host explicitly hands it one, rather than being able to open anything by name.

## Standard library and notable interfaces

WebAssembly's core has no standard library; a module imports whatever host functions it needs. On the web, those imports come from JavaScript and the browser APIs. Off the web, [WASI](https://wasi.dev/) standardizes a library of host functions for files, clocks, random numbers, and networking under a capability model. Toolchains add their own support libraries: Emscripten provides a C standard library and partial POSIX emulation, and wasm-bindgen connects Rust to JavaScript objects.

## Testing and packaging

Testing usually happens in the source language before compilation (for example `cargo test` for Rust), with additional tests that load the compiled module and exercise it through the host API.

```javascript
// Node.js: load a module and call an exported function
const bytes = await readFile("add.wasm");
const { instance } = await WebAssembly.instantiate(bytes);
console.assert(instance.exports.add(2, 3) === 5);
```

A module ships as a `.wasm` binary. The emerging [component model](https://component-model.bytecodealliance.org/) packages modules with their interface types so they can be composed and distributed through a registry.

## Performance and concurrency

WebAssembly aims for predictable, near-native speed: engines validate and then compile a module to machine code, and the instruction set avoids the dynamic dispatch and boxing that slow interpreted languages. Concurrency:

- The [threads proposal](https://github.com/WebAssembly/threads) adds shared linear memory and atomic instructions, mapped to Web Workers in the browser; threads are created by the host, not by Wasm itself.
- SIMD vector instructions (`v128`) accelerate data-parallel loops.
- On servers, runtimes can instantiate many isolated module instances cheaply, which suits per-request or per-tenant isolation.

Startup is fast because the binary format is designed for streaming compilation while it downloads.

## Common pitfalls

- The JavaScript boundary has a cost; moving a hot loop to Wasm but calling into it per element can be slower than staying in JavaScript.
- Linear memory is a flat byte array with manual layout; a miscalculated offset corrupts data within the module (though it cannot escape the sandbox).
- Not every language maps cleanly: those that need a garbage collector historically shipped one inside the module, enlarging it, until the garbage-collection proposal landed.
- Debugging compiled modules needs source maps or DWARF information; without them you are reading the text format, not your source.
- A module can only do what the host grants; forgetting to import a needed capability yields a module that cannot perform I/O.

## Secure coding

WebAssembly's sandbox addresses host-level memory safety, but it does not make the compiled program logically correct, and classic bugs in the source language survive the compile:

- Memory-unsafe source languages still have bugs inside the sandbox: a buffer overflow in C or C++ compiled to Wasm corrupts the module's own linear memory and can be exploited to subvert the module's logic, even though it cannot reach host memory. This maps to [CWE-787](https://cwe.mitre.org/data/definitions/787.html). Compile with the source language's hardening options and keep its own safety practices.
- Limited defenses inside linear memory: there are no guard pages between allocations in a single linear memory, so overflows that would crash on a native platform may silently overwrite adjacent data; rely on source-language checks rather than hardware traps.
- Host capability grants: a runtime that hands a module broad file-system or network access widens the blast radius; grant the narrowest WASI capabilities a module needs, which relates to least privilege in the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Imported-function trust: a module is only as safe as the host functions it is given; untrusted modules should receive vetted, validating imports, and untrusted modules themselves should run with resource limits to prevent denial of service ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)).
- Supply chain: a `.wasm` binary is opaque; verify its provenance and build it from reviewed source. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: scan the source language with its own analyzers (for example [semgrep](https://semgrep.dev/) or language-specific linters) before compiling, and inspect modules with [wasm-tools](https://github.com/bytecodealliance/wasm-tools). See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).

## Learning resources

- [WebAssembly specification](https://webassembly.github.io/spec/), the formal definition.
- [MDN WebAssembly guide](https://developer.mozilla.org/en-US/docs/WebAssembly), for the browser API and concepts.
- [WASI](https://wasi.dev/) and the [Bytecode Alliance](https://bytecodealliance.org/), for the off-browser runtimes and interfaces.

## Related pages

- [JavaScript](/languages/javascript.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
