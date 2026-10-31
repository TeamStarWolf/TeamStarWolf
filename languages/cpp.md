# C++

C++ is a statically typed, compiled, multi-paradigm language created by Bjarne Stroustrup at Bell Labs, beginning as "C with Classes" in 1979 and renamed C++ in 1983. It extends C with classes, templates, exceptions, and a large standard library, while keeping close control over memory and performance. It is used for game engines, browsers, databases, high-frequency trading systems, embedded software, and other code where both abstraction and speed matter.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: procedural, object-oriented, generic, functional |
| Typing | Static, strong-ish, with explicit and implicit conversions |
| First appeared | 1985 (standardized 1998) |
| Memory model | Manual, with RAII and smart pointers for scoped ownership |
| Reference compiler | No single reference; [GCC](https://gcc.gnu.org/), [Clang](https://clang.llvm.org/), and MSVC implement the standard |
| Typical uses | Game engines, browsers, databases, trading, embedded, tooling |
| Governance/standard | ISO/IEC 14882, via ISO JTC1/SC22/WG21 |

Related: [C](/languages/c.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

C++ began as a set of additions to C that brought classes and object orientation to systems programming. It was first standardized as C++98, then revised by C++03. C++11 was a large revision that added `auto` type deduction, lambdas, move semantics, `std::unique_ptr` and `std::shared_ptr`, range-based `for`, and a threading library. Later standards continued on a three-year cadence: C++14, C++17 (structured bindings, `std::optional`, `std::variant`, filesystem), C++20 (concepts, ranges, coroutines, modules), and C++23.

The standard is maintained by ISO working group WG21, with proposals discussed openly on the isocpp.org site. GCC, Clang, and MSVC are the main implementations, and each tracks the standard closely.

## Paradigm and type system

C++ supports procedural, object-oriented, and generic code in one program. Classes carry constructors and destructors; templates provide compile-time generics; and since C++20, concepts constrain template parameters with readable error messages. Typing is static, and many conversions are implicit, though `explicit` constructors and `static_cast` make intent clear.

```cpp
#include <concepts>

template <std::integral T>
constexpr T clamp_nonneg(T value) {
    return value < 0 ? T{0} : value;
}
```

Resource Acquisition Is Initialization (RAII) ties a resource's lifetime to an object's scope, so destructors release memory, files, and locks deterministically when an object goes out of scope.

## Toolchain and ecosystem

- Compilers: `g++`, `clang++`, and `cl.exe` (MSVC).
- Build systems: [CMake](https://cmake.org/) is the de facto standard; [Meson](https://mesonbuild.com/) and [Bazel](https://bazel.build/) are also used.
- Package managers: [vcpkg](https://vcpkg.io/) and [Conan](https://conan.io/) fetch and build dependencies.
- Debuggers and analyzers: [GDB](https://www.sourceware.org/gdb/), [LLDB](https://lldb.llvm.org/), the sanitizers, and [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) for static checks.

```bash
clang++ -std=c++20 -Wall -Wextra -fsanitize=address,undefined main.cpp -o app
./app
```

## Syntax tour

```cpp
#include <iostream>
#include <memory>
#include <string>
#include <vector>

struct Shape {
    virtual double area() const = 0;
    virtual ~Shape() = default;
};

struct Circle : Shape {
    double r;
    explicit Circle(double radius) : r(radius) {}
    double area() const override { return 3.14159265 * r * r; }
};

int main() {
    std::vector<std::unique_ptr<Shape>> shapes;
    shapes.push_back(std::make_unique<Circle>(2.0));

    double total = 0.0;
    for (const auto &shape : shapes) {
        total += shape->area();            // dynamic dispatch
    }
    std::cout << "total area: " << total << '\n';
    return 0;                              // unique_ptr frees automatically
}
```

## Idioms and different approaches

- Prefer RAII and smart pointers (`std::unique_ptr`, `std::shared_ptr`) over raw `new` and `delete`.
- Follow the rule of zero: let the compiler generate special members when a class holds only RAII members.
- Pass large objects by `const` reference; use move semantics (`std::move`) to transfer ownership cheaply.
- Use the standard algorithms (`std::sort`, `std::transform`, ranges) rather than hand-written loops.
- Mark overriding functions `override` and non-modifying methods `const`.

## Design principles

C++ follows the principle that you do not pay for what you do not use: abstractions such as templates and RAII compile down to code no slower than a hand-written equivalent. The language favors compile-time resolution, giving zero-overhead abstractions where possible, while leaving the programmer in control of memory layout and lifetime.

## Standard library and notable libraries

The standard library provides containers (`std::vector`, `std::map`, `std::unordered_map`), algorithms, strings, `std::optional` and `std::variant`, smart pointers, threads and atomics, and since C++20 ranges and coroutines. Widely used third-party libraries include [Boost](https://www.boost.org/) for utilities that often precede standardization, [Qt](https://www.qt.io/) for graphical applications, [Eigen](https://eigen.tuxfamily.org/) for linear algebra, and [{fmt}](https://fmt.dev/) for formatting.

## Testing and packaging

Common test frameworks include [GoogleTest](https://github.com/google/googletest), [Catch2](https://github.com/catchorg/Catch2), and [doctest](https://github.com/doctest/doctest). Packaging typically combines CMake with vcpkg or Conan; there is no single standard package format.

```cpp
#include <catch2/catch_test_macros.hpp>

int add(int a, int b) { return a + b; }

TEST_CASE("add sums two integers") {
    REQUIRE(add(2, 3) == 5);
}
```

## Performance and concurrency

C++ compiles to native code and gives direct control over memory layout, which suits latency-sensitive work. The standard library offers `std::thread`, `std::async`, `std::mutex`, `std::atomic`, and, since C++20, `std::jthread` and coroutines. The C++ memory model defines how atomics order operations across threads. Data races are undefined behavior, so synchronization must be explicit; ThreadSanitizer helps find races.

## Common pitfalls

- Dangling references and pointers to objects that have gone out of scope.
- Use-after-free and double-free when mixing raw `new`/`delete` with smart pointers.
- Object slicing when a derived object is copied into a base-class value.
- Iterator invalidation after a container is resized or modified.
- Undefined behavior from signed overflow, out-of-bounds access, or reading uninitialized memory.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Out-of-bounds access: use `std::vector` with `.at()` for checked indexing where appropriate, `std::span` for bounded views, and avoid raw pointer arithmetic. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and [CWE-125](https://cwe.mitre.org/data/definitions/125.html).
- Use-after-free: express ownership with `std::unique_ptr` and `std::shared_ptr` rather than raw owning pointers. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow in allocation sizes: validate arithmetic before sizing buffers. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: avoid `std::system` on assembled strings; use process APIs with argument vectors, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: enable `-Wall -Wextra`, AddressSanitizer and UndefinedBehaviorSanitizer, [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) with the C++ Core Guidelines checks, and follow the [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- cppreference.com, the detailed language and library reference.
- isocpp.org and the [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines).
- *The C++ Programming Language* by Bjarne Stroustrup, the author's reference text.

## Related pages

- [C](/languages/c.md)
- [Rust](/languages/rust.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
