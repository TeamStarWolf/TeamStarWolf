# Zig

Zig is a statically typed, compiled systems language created by Andrew Kelley, with a first release in 2016. It aims to be a small, explicit alternative to C: no hidden control flow, no hidden memory allocation, and compile-time code execution through the `comptime` keyword. It is used for systems programming, embedded targets, and as a drop-in C and C++ cross-compiler toolchain. As of 2026 the language has not reached a 1.0 release and its design is still changing.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, with compile-time metaprogramming |
| Typing | Static, strong, with inference |
| First appeared | 2016 (pre-1.0 as of 2026) |
| Memory model | Manual, with explicit allocator parameters |
| Reference compiler | [The Zig compiler](https://github.com/ziglang/zig), self-hosted with an LLVM back end |
| Typical uses | Systems programming, embedded, C/C++ cross-compilation |
| Governance/standard | [Zig Software Foundation](https://ziglang.org/zsf/); no formal standard |

Related: [C](/languages/c.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Zig began as an effort to give systems programmers the control of C with fewer surprises. It makes allocation explicit by passing an allocator to any function that allocates, so there is no hidden global heap use. Compile-time execution with `comptime` replaces macros and templates: types are values, and generic code is ordinary code run at compile time. The project is pre-1.0, so the standard library and language syntax continue to change between releases; check the version you target.

The compiler is self-hosted and can also act as a C and C++ compiler and cross-compiler, bundling libc headers for many targets. Governance is through the nonprofit Zig Software Foundation.

## Paradigm and type system

Zig is statically typed and procedural, with no classes or inheritance. Error handling uses error-union types (`!T`) and the `try` operator, which propagates errors up the call stack without exceptions. Optionals (`?T`) make the absence of a value explicit, replacing null pointers. Generics are expressed by taking and returning `type` values at compile time.

```zig
fn maxOf(comptime T: type, a: T, b: T) T {
    return if (a > b) a else b;
}
```

There is no operator overloading and no hidden control flow, so what a line does is visible where it is written.

## Toolchain and ecosystem

- The `zig` command compiles, runs, tests, and builds; `build.zig` describes a build in Zig itself.
- The compiler can cross-compile to many targets out of the box and can compile C and C++ with `zig cc`.
- A package manager is built into the toolchain, with dependencies declared in `build.zig.zon`.

```bash
zig init
zig build
zig build test
```

## Syntax tour

```zig
const std = @import("std");

const Shape = union(enum) {
    circle: f64,
    rect: struct { w: f64, h: f64 },

    fn area(self: Shape) f64 {
        return switch (self) {
            .circle => |r| std.math.pi * r * r,
            .rect => |d| d.w * d.h,
        };
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var list = std.ArrayList(Shape).init(allocator);
    defer list.deinit();

    try list.append(.{ .circle = 2.0 });
    try list.append(.{ .rect = .{ .w = 3.0, .h = 4.0 } });

    var total: f64 = 0;
    for (list.items) |shape| total += shape.area();

    std.debug.print("total area: {d:.2}\n", .{total});
}
```

## Idioms and different approaches

- Accept an allocator parameter in any function that allocates; the caller controls the memory strategy.
- Use `defer` and `errdefer` to release resources, including on the error path.
- Propagate errors with `try` and handle them with `catch`; name the error set where it matters.
- Use `comptime` for generics and compile-time configuration rather than macros.
- Prefer slices (`[]T`) with explicit lengths over raw pointers.

## Design principles

Zig's stated principles include no hidden control flow, no hidden memory allocation, no preprocessor, and no macros: compile-time code runs the same language as run-time code. The aim is that reading a line of Zig tells you what it does, and that the programmer, not the language, decides when memory is allocated and freed.

## Standard library and notable libraries

The standard library ships data structures (`ArrayList`, `HashMap`), allocators (`GeneralPurposeAllocator`, `ArenaAllocator`, `FixedBufferAllocator`), formatting and I/O, a build system, and a testing harness. Because the language is pre-1.0, the standard library is a moving target and the third-party ecosystem is young; many projects use Zig primarily as a C/C++ build toolchain.

## Testing and packaging

Testing is built into the language: `test "name" { ... }` blocks run with `zig build test` or `zig test`. Packages are described in `build.zig.zon` and fetched by the integrated package manager.

```zig
const std = @import("std");

fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "add sums two integers" {
    try std.testing.expectEqual(@as(i32, 5), add(2, 3));
}
```

## Performance and concurrency

Zig compiles to native code through an LLVM back end (with a self-hosted back end in progress), and its explicit-allocation model avoids hidden heap traffic. The language provides `async` and `await` primitives in some versions, though the async model has changed across releases and may not be present in the version you use; confirm against the target version. Threading is available through the standard library's `std.Thread`. For data-race freedom the programmer uses explicit synchronization.

## Common pitfalls

- Targeting a tutorial written for an older version, since syntax and the standard library change pre-1.0.
- Forgetting `defer`/`errdefer`, which leaks memory on the error path.
- Allocator lifetime mistakes: freeing with a different allocator than the one that allocated.
- Assuming async features exist in your version when they may have been removed or reworked.
- Undefined behavior from out-of-bounds access in release modes that omit safety checks.

## Secure coding

Zig is a manual-memory language, so classic systems risks apply, moderated by built-in safety checks in debug and safe-release builds:

- Out-of-bounds access: slices carry a length and are bounds-checked in safe build modes; keep safety checks on where they matter. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Use-after-free and double-free: use `defer`/`errdefer` and a consistent allocator per allocation. The `GeneralPurposeAllocator` can detect some leaks and double-frees in debug mode. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow: default arithmetic traps on overflow in safe modes; use wrapping operators (`+%`) only when wraparound is intended. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: build child-process arguments as a list rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: build in a safe release mode (`ReleaseSafe`) to keep run-time checks, and use the standard library's testing allocator to catch leaks in tests. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The official Zig documentation](https://ziglang.org/documentation/master/) and language reference.
- [Zig Learn](https://ziglearn.org/), a community tutorial.
- [The Zig standard library source](https://github.com/ziglang/zig/tree/master/lib/std), often the most current reference pre-1.0.

## Related pages

- [C](/languages/c.md)
- [Rust](/languages/rust.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
