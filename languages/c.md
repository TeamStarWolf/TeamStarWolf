# C

C is a statically typed, compiled, imperative language created by Dennis Ritchie at Bell Labs in the early 1970s. It provides low-level access to memory, a small set of keywords, and direct mapping to machine operations, which is why operating systems, device drivers, embedded firmware, and language runtimes are commonly written in it. The language is defined by an ISO standard, and many compilers implement it, with GCC and Clang the most widely used.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural |
| Typing | Static, weak, with explicit conversions |
| First appeared | 1972 (ANSI C in 1989) |
| Memory model | Manual: the programmer allocates and frees |
| Reference compiler | No single reference; [GCC](https://gcc.gnu.org/) and [Clang](https://clang.llvm.org/) are dominant |
| Typical uses | Operating systems, embedded firmware, drivers, runtimes, tooling |
| Governance/standard | [ISO/IEC 9899](https://www.iso.org/standard/82075.html), via ISO JTC1/SC22/WG14 |

Related: [C++](/languages/cpp.md), [Rust](/languages/rust.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

C grew out of Ken Thompson's B language and was used to rewrite the Unix kernel, which tied the language to systems programming from the start. The 1978 book *The C Programming Language* by Brian Kernighan and Dennis Ritchie documented the early dialect, often called K&R C. The language was first standardized as ANSI C89, adopted by ISO as C90, and revised several times since: C99 added variable-length arrays, `//` comments, and fixed-width integer types; C11 added atomics, threads, and `_Generic`; C17 was a bug-fix release; and C23 added `nullptr`, `constexpr`, and `_BitInt`.

No single implementation is the reference. GCC and Clang target most platforms, MSVC serves Windows, and many embedded toolchains ship vendor compilers. The standard defines behavior that all conforming implementations share, along with implementation-defined, unspecified, and undefined behavior.

## Paradigm and type system

C is procedural: programs are functions that operate on data, with no built-in classes or generics before C11's limited `_Generic`. Typing is static but weak, so many conversions happen implicitly, and a cast can reinterpret one type as another. The language distinguishes integer and floating types, pointers, arrays, structures, unions, and enumerations.

```c
#include <stdint.h>

typedef struct {
    int32_t x;
    int32_t y;
} Point;

int32_t manhattan(Point a, Point b) {
    int32_t dx = a.x > b.x ? a.x - b.x : b.x - a.x;
    int32_t dy = a.y > b.y ? a.y - b.y : b.y - a.y;
    return dx + dy;
}
```

Undefined behavior is a defining property: signed integer overflow, out-of-bounds access, and use of an uninitialized value are not diagnosed by the language and may do anything at run time.

## Toolchain and ecosystem

- Compilers: `gcc` and `clang` compile and link; `cc` is the conventional name.
- Build systems: [Make](https://www.gnu.org/software/make/), [CMake](https://cmake.org/), and [Meson](https://mesonbuild.com/) are common; there is no standard package manager.
- Debuggers and analyzers: [GDB](https://www.sourceware.org/gdb/) and [LLDB](https://lldb.llvm.org/) debug; [Valgrind](https://valgrind.org/) and the compiler sanitizers (AddressSanitizer, UndefinedBehaviorSanitizer) find memory and behavior errors at run time.

```bash
cc -std=c17 -Wall -Wextra -fsanitize=address,undefined main.c -o app
./app
```

## Syntax tour

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A fixed-size stack of integers
typedef struct {
    int *data;
    size_t len;
    size_t cap;
} Stack;

int stack_push(Stack *s, int value) {
    if (s->len == s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 4;
        int *grown = realloc(s->data, new_cap * sizeof *grown);
        if (!grown) return -1;            // caller checks the error
        s->data = grown;
        s->cap = new_cap;
    }
    s->data[s->len++] = value;
    return 0;
}

int main(void) {
    Stack s = {0};
    for (int i = 0; i < 5; i++) {
        if (stack_push(&s, i * i) != 0) {
            fprintf(stderr, "out of memory\n");
            return EXIT_FAILURE;
        }
    }
    for (size_t i = 0; i < s.len; i++) {
        printf("%d\n", s.data[i]);
    }
    free(s.data);
    return EXIT_SUCCESS;
}
```

## Idioms and different approaches

- Return an error code and write results through pointer parameters, rather than relying on exceptions, which C does not have.
- Pair every allocation with a single owner responsible for freeing it; document who frees what.
- Use `sizeof *pointer` in allocations so the size tracks the type automatically.
- Prefer fixed-width types from `<stdint.h>` (`int32_t`, `uint8_t`) when the exact width matters.
- Guard headers with include guards or `#pragma once` to avoid duplicate definitions.

## Design principles

C aims to stay close to the machine while remaining portable across machines. It trusts the programmer: the language offers few run-time checks, assuming the author knows the invariants. This gives predictable performance and small binaries, at the cost of safety that the programmer must supply by hand.

## Standard library and notable libraries

The standard library is small: `<stdio.h>` for input and output, `<stdlib.h>` for allocation and conversion, `<string.h>` for memory and string routines, `<math.h>` for floating-point functions, and C11's `<threads.h>` for threads. Widely used third-party libraries include [zlib](https://www.zlib.net/) for compression, [OpenSSL](https://www.openssl.org/) for cryptography and TLS, [SQLite](https://www.sqlite.org/) for an embedded database, and [libcurl](https://curl.se/libcurl/) for network transfers.

## Testing and packaging

C has no standard test framework. Common choices include [Unity](https://github.com/ThrowTheSwitch/Unity), [Check](https://libcheck.github.io/check/), and [Criterion](https://github.com/Snaipe/Criterion). Packaging is platform-specific: libraries ship as source, as system packages, or through [vcpkg](https://vcpkg.io/) and [Conan](https://conan.io/).

```c
#include <assert.h>

int add(int a, int b) { return a + b; }

int main(void) {
    assert(add(2, 3) == 5);
    return 0;
}
```

## Performance and concurrency

Compiled C maps closely to the hardware, so it is often the baseline against which other languages measure speed. Concurrency uses operating-system threads (POSIX `pthreads` or the C11 `<threads.h>` interface) with explicit synchronization through mutexes and condition variables. C11 added `<stdatomic.h>` for lock-free atomic operations. The programmer is responsible for data-race freedom; the sanitizers' ThreadSanitizer helps detect races at run time.

## Common pitfalls

- Buffer overflows from writing past an array's bounds, which the language does not check.
- Use-after-free and double-free from manual memory management.
- Reading uninitialized memory, which yields indeterminate values.
- Integer overflow and signed/unsigned confusion in size calculations.
- Relying on undefined behavior that an optimizing compiler may exploit in surprising ways.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Out-of-bounds writes: validate every index and length before access, and prefer bounded functions (`snprintf`, `memcpy` with a checked length) over unbounded ones like `gets` and `strcpy`. This is [CWE-787](https://cwe.mitre.org/data/definitions/787.html).
- Use-after-free and double-free: set pointers to `NULL` after freeing, and keep a single clear owner for each allocation. This is [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
- Integer overflow in size math: check for overflow before multiplying sizes for allocation. This is [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- OS command injection: avoid `system()` on assembled strings; use `exec`-family calls with an argument vector instead, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Tooling: compile with `-Wall -Wextra` and the AddressSanitizer and UndefinedBehaviorSanitizer; run [Valgrind](https://valgrind.org/) for memory errors, and [Clang Static Analyzer](https://clang-analyzer.llvm.org/) or [Cppcheck](https://cppcheck.sourceforge.io/) for static analysis. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [The C Programming Language](https://en.wikipedia.org/wiki/The_C_Programming_Language) by Kernighan and Ritchie, the original reference text.
- [cppreference's C section](https://en.cppreference.com/w/c), a detailed standard-library and language reference.
- SEI CERT C Coding Standard, rules for safe and portable C.

## Related pages

- [C++](/languages/cpp.md)
- [Rust](/languages/rust.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
