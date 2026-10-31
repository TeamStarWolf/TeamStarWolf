# Haxe

Haxe is a statically typed, multi-paradigm language that compiles to several other languages and platforms from one source. Created by Nicolas Cannasse and first released in 2005, it has a type system with inference and a macro system, and its compiler emits JavaScript, C++, C#, Java, Python, Lua, PHP, and its own HashLink and Neko virtual machines. It is used for cross-platform games, and for tools and libraries that must run in more than one environment from a single codebase.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: object-oriented, functional, generic |
| Typing | Static, strong, with type inference and algebraic data types (enums) |
| First appeared | 2005 |
| Memory model | Depends on the target: garbage-collected on most, following the host runtime |
| Reference implementation | The [Haxe compiler](https://github.com/HaxeFoundation/haxe) and its targets |
| Typical uses | Cross-platform games, cross-platform libraries and tools |
| Governance | [Haxe Foundation](https://haxe.org/foundation/) and the community |

Related: [GDScript](/languages/gdscript.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Haxe (originally written "haXe") was created by Nicolas Cannasse in 2005, growing out of earlier work on a language that targeted Adobe Flash. Its defining idea is a single statically typed language that compiles to many back ends, so a codebase can run on the web, on native platforms, and on servers without being rewritten. The compiler translates Haxe to idiomatic source in each target language (or to bytecode for its own virtual machines), and a target-specific standard library plus conditional compilation handle the differences.

Haxe found a durable home in game development, where shipping to web, desktop, mobile, and consoles from one codebase is valuable, through frameworks such as Heaps, OpenFL, and Kha. It is also used for cross-platform business logic shared between a server and multiple clients.

## Paradigm and type system

Haxe is statically and strongly typed with thorough type inference, so most local types need not be written. It supports classes and interfaces, generics (type parameters), and functional features including first-class functions, pattern matching, and algebraic data types through its `enum` construct (tagged unions, distinct from a plain C-style enum). Anonymous structure types describe a value by its fields. Abstract types let a new type reuse an underlying representation with its own API and operators.

```haxe
enum Shape {
    Circle(radius:Float);
    Rect(w:Float, h:Float);
}

function area(s:Shape):Float {
    return switch s {
        case Circle(r): Math.PI * r * r;
        case Rect(w, h): w * h;
    };
}
```

The macro system runs Haxe code at compile time to inspect and generate code, which libraries use for serialization and boilerplate reduction.

## Toolchain and ecosystem

- Compiler: the `haxe` command compiles a project, driven by `.hxml` build files that select the target and options.
- Package manager: [haxelib](https://lib.haxe.org/) installs libraries and manages versions.
- Targets: JavaScript, C++, C#, Java/JVM, Python, Lua, PHP, and the [HashLink](https://hashlink.haxe.org/) and Neko virtual machines, selected per build.
- Frameworks: [Heaps](https://heaps.io/), [OpenFL](https://www.openfl.org/), and [Kha](https://github.com/Kode/Kha) for games and graphics.
- Editor support: a language server backs extensions for Visual Studio Code and other editors.

```bash
haxelib install heaps          # install a library
haxe build.hxml                # compile per the build file
```

## Syntax tour

```haxe
class Main {
    static function main() {
        var greeting = greet("world");     // type inferred as String
        trace(greeting);                   // prints via the target's console

        var nums = [1, 2, 3, 4];
        var evens = nums.filter(n -> n % 2 == 0);
        trace(evens);
    }

    static function greet(name:String):String {
        return 'hello, $name';             // string interpolation
    }
}

// Conditional compilation selects code per target
#if js
    // JavaScript-only code
#elseif cpp
    // C++-only code
#end
```

## Idioms and different approaches

- Use `enum` and `switch` pattern matching for state and variant data, letting the compiler check that all cases are handled.
- Keep platform-specific code behind conditional compilation (`#if target`) and a small shared interface, so the bulk of the code stays portable.
- Prefer type inference for locals and annotate public APIs, which documents intent and stabilizes the interface.
- Reach for abstract types to wrap a primitive with domain meaning (units, identifiers) without run-time overhead.
- Use macros only where they clearly pay off; they are expressive but make code harder to follow and debug.

## Design principles

Haxe's central principle is write-once, compile-to-many: one strict, inferred type system over a set of back ends, with the compiler producing readable output in each target language. Strong typing catches errors before they reach any platform, which matters more when the same code must run in several. The macro system and abstract types reflect a preference for solving repetition and representation problems in the language rather than through external code generators.

## Standard library and notable packages

Haxe's standard library has a cross-platform core (collections, `String`, `Math`, `Date`, regular expressions, `haxe.Json`, `haxe.io`) that behaves the same on every target, plus target-specific APIs under namespaces like `js`, `cpp`, and `sys` for platforms with a file system and processes. The [haxelib](https://lib.haxe.org/) registry hosts libraries, including the game frameworks Heaps, OpenFL, and Kha, the `tink` family of utility libraries, and testing and serialization tools.

## Testing and packaging

Testing uses community frameworks such as [utest](https://github.com/haxe-utest/utest) or munit, compiled and run on whichever targets a project ships to, so behavior is verified per platform. Libraries are packaged and published to haxelib with a `haxelib.json` manifest, and applications are "packaged" by compiling to the target and bundling with that platform's tools (a web build, a native executable, a HashLink package).

```haxe
import utest.Test;
import utest.Assert;

class AreaTest extends Test {
    function testRect() {
        Assert.equals(6.0, area(Rect(2, 3)));
    }
}
```

## Performance and concurrency

Because Haxe compiles to other platforms, its performance and concurrency are largely those of the chosen target:

- Native targets (C++ through hxcpp, or HashLink's just-in-time compiler) give the best raw speed and are common for shipping games; JavaScript performance follows the host engine; the Python and PHP targets trade speed for reach into those ecosystems.
- Memory management follows the target: most targets are garbage-collected (the host runtime's collector, or hxcpp's), so pause behavior and allocation cost vary by platform.
- Concurrency is target-dependent: `sys.thread` offers threads on targets that support them, the JavaScript target is single-threaded with an event loop, and asynchronous patterns (callbacks, promises, or library-provided futures such as `tink_core`) are the portable way to express concurrency.

The practical implication is to profile on the target you actually ship, since the same Haxe code can perform quite differently across back ends.

## Common pitfalls

- Assuming uniform behavior across targets: numeric types, integer overflow, string handling, and the standard library's system APIs differ, so test on each target you ship.
- Using `sys`-based file and process APIs on targets that lack them (such as the browser), which fails to compile or at run time; guard with conditional compilation.
- Overusing macros, which can make build errors cryptic and debugging hard.
- Confusing Haxe's `enum` (algebraic data type) with a C-style enumeration; it is more capable and matched with `switch`.
- Relying on `Dynamic` to bypass the type system, which discards the safety that is Haxe's main benefit.

## Secure coding

Haxe's security profile depends on where a build runs, so apply the practices of the target platform, plus a few Haxe-specific points:

- Platform-specific vulnerabilities carry over: a web build is subject to cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) when it writes untrusted data into the DOM, and a server or native build using `sys` APIs is subject to command and path injection ([CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-22](https://cwe.mitre.org/data/definitions/22.html)). Validate and encode output for the target, and apply the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) to web builds.
- Deserialization of untrusted data ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)): Haxe's native serialization format can reconstruct typed objects; prefer `haxe.Json` with validation for data from untrusted sources rather than restoring arbitrary objects.
- Untrusted input in games and clients: save files and network messages from peers are untrusted; validate them, and authorize multiplayer actions on a server rather than trusting the client. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Hardcoded secrets ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): keys compiled into a client build (web or native) are recoverable; keep them server-side.
- Supply chain: haxelib libraries and macros run at compile time and in the product; macros in particular execute arbitrary code during the build. Pin versions and review third-party libraries, especially macro-based ones. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: lean on the strict type system and the compiler's warnings, and run the target platform's own analyzers against the generated output where available. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Haxe Manual](https://haxe.org/manual/), the language reference.
- [Haxe API documentation](https://api.haxe.org/), the standard library per target.
- [haxelib](https://lib.haxe.org/), the library registry.

## Related pages

- [GDScript](/languages/gdscript.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
