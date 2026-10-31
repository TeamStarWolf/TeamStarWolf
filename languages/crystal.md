# Crystal

Crystal is a statically typed, compiled language with Ruby-like syntax, created by Ary Borenszweig and others at Manas, with a first release in 2014 and version 1.0 in 2021. It aims to feel like Ruby while compiling to native code with static type checking and type inference, so that much code needs no explicit type annotations. It is used for web services, command-line tools, and general application programming where Ruby's readability is wanted with native speed.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented, with functional elements |
| Typing | Static, strong, with global type inference |
| First appeared | 2014 (1.0 in 2021) |
| Memory model | Automatic: garbage collected (Boehm collector) |
| Reference compiler | [The Crystal compiler](https://github.com/crystal-lang/crystal), with an LLVM back end |
| Typical uses | Web services, CLI tools, application programming |
| Governance/standard | Crystal core team and the [Crystal community](https://crystal-lang.org/); no ISO standard |

Related: [Rust](/languages/rust.md), [C](/languages/c.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Crystal started from the premise that Ruby's syntax is pleasant but its interpreter is slow and dynamically typed. The language keeps a Ruby-like surface while adding a static type system with inference that fills in most types, and it compiles through LLVM to native binaries. Version 1.0 in 2021 brought a stability commitment. The language has no separate specification; it is defined by its compiler and documentation.

The compiler is self-hosted (written in Crystal) and uses LLVM for code generation. Development is community-driven around the core team, with sponsorship from several organizations over the project's history.

## Paradigm and type system

Crystal is object-oriented with everything an object, and it borrows Ruby's blocks and mixins. Its type system performs global inference: the compiler deduces types across the program, so annotations are often unnecessary, yet every expression has a static type. Union types (`String | Nil`) model values that may be one of several types, and the compiler uses flow analysis to narrow them. The `nil` case must be handled, which removes many null-reference errors.

```crystal
def first_even(numbers : Array(Int32)) : Int32?
  numbers.find { |n| n.even? }
end
```

Generics are written with type variables, and macros run at compile time to generate code.

## Toolchain and ecosystem

- The `crystal` command compiles and runs programs and includes a formatter (`crystal tool format`).
- [Shards](https://github.com/crystal-lang/shards) is the dependency manager, reading a `shard.yml` file.
- The compiler links against system C libraries directly through `lib` bindings.

```bash
crystal init app myapp
cd myapp
shards install
crystal build --release src/myapp.cr
```

## Syntax tour

```crystal
abstract struct Shape
  abstract def area : Float64
end

struct Circle < Shape
  def initialize(@r : Float64)
  end

  def area : Float64
    Math::PI * @r ** 2
  end
end

struct Rect < Shape
  def initialize(@w : Float64, @h : Float64)
  end

  def area : Float64
    @w * @h
  end
end

shapes = [Circle.new(2.0), Rect.new(3.0, 4.0)] of Shape
total = shapes.sum(&.area)
puts "total area: #{total.round(2)}"
```

## Idioms and different approaches

- Let inference do the work: annotate public method signatures, but allow local types to be deduced.
- Handle the `Nil` branch of a union explicitly; the compiler requires it.
- Use blocks and the `&.method` shorthand for concise iteration, as in Ruby.
- Prefer `struct` for small immutable value types and `class` for reference types.
- Use macros for compile-time code generation rather than run-time metaprogramming, which Crystal does not have.

## Design principles

Crystal's stated goals include a syntax that Ruby programmers find familiar, static type checking with minimal annotation, native compilation for speed, and the ability to call C libraries without a separate binding layer. The language trades Ruby's run-time dynamism for compile-time checking and performance.

## Standard library and notable libraries

The standard library covers HTTP servers and clients (`HTTP::Server`, `HTTP::Client`), JSON and YAML (`JSON`, `YAML`), collections, concurrency (`Channel`, fibers), and a built-in `Spec` testing framework. Widely used third-party shards include [Kemal](https://kemalcr.com/) and [Lucky](https://luckyframework.org/) for web applications, and [Granite](https://github.com/amberframework/granite) for database modeling.

## Testing and packaging

Crystal ships a `Spec` framework in its standard library, with `describe`, `it`, and `should`, run through `crystal spec`. Libraries, called shards, are described by `shard.yml` and distributed through Git repositories resolved by Shards.

```crystal
require "spec"

def add(a : Int32, b : Int32) : Int32
  a + b
end

describe "add" do
  it "sums two integers" do
    add(2, 3).should eq(5)
  end
end
```

## Performance and concurrency

Crystal compiles through LLVM to native code, so its performance is far above interpreted Ruby and in range of other compiled languages. Concurrency uses fibers, lightweight cooperative units scheduled by the runtime, with `Channel` for communication in the style of communicating sequential processes. As of the 1.x line, parallel execution across operating-system threads is available behind a multithreading flag and continues to be refined; confirm the model for your version.

## Common pitfalls

- Expecting Ruby's run-time metaprogramming (`method_missing`, `define_method`); Crystal resolves everything at compile time through macros instead.
- Not handling the `Nil` member of a union, which the compiler rejects.
- Long compile times on large programs, a consequence of global type inference.
- Assuming libraries from Ruby work unchanged; Crystal has its own ecosystem of shards.
- Integer overflow behavior differing from Ruby's arbitrary-precision integers.

## Secure coding

Crystal is garbage collected and type checked, which removes many memory-safety bugs, but risks remain:

- OS command injection: use `Process.run` with an argument array rather than passing a command through a shell, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- SQL injection: use parameterized queries from the database shard rather than string interpolation, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Integer overflow: Crystal's fixed-width integers raise `OverflowError` on overflow in checked operations; validate untrusted arithmetic rather than using unchecked wrapping operators. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Unsafe C bindings and pointers: `lib` bindings and `Pointer` bypass safety and can cause out-of-bounds writes, which maps to [CWE-787](https://cwe.mitre.org/data/definitions/787.html). Confine and audit them.

Tooling: review `lib` bindings carefully, keep dependencies current through Shards, and consult the [Crystal security guidance](https://crystal-lang.org/reference/) in the official reference. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The Crystal reference and documentation](https://crystal-lang.org/reference/).
- [The Crystal API docs](https://crystal-lang.org/api/), the standard-library reference.
- [Crystal for Rubyists](https://www.crystalforrubyists.com/), an introduction aimed at Ruby programmers.

## Related pages

- [Rust](/languages/rust.md)
- [C](/languages/c.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
