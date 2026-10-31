# Go

Go is a statically typed, compiled language designed at Google by Robert Griesemer, Rob Pike, and Ken Thompson, first released in 2009. It favors a small feature set, fast compilation, built-in concurrency through goroutines and channels, and a garbage collector. It is used for network services, command-line tools, cloud infrastructure, and container tooling, including Docker and Kubernetes.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, concurrent, with structural interfaces |
| Typing | Static, strong, with inference and generics |
| First appeared | 2009 (1.0 in 2012) |
| Memory model | Automatic: concurrent garbage collector |
| Reference compiler | [gc](https://go.dev/dl/), the official toolchain (also gccgo) |
| Typical uses | Network services, cloud infrastructure, CLI tools, container tooling |
| Governance/standard | [Go proposal process](https://go.dev/s/proposal) under Google and the Go team |

Related: [Rust](/languages/rust.md), [C](/languages/c.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Go was created to address slow builds and complex dependency graphs in large codebases, and to make concurrency ordinary rather than specialized. The language reached 1.0 in 2012 with a compatibility promise: code that compiles under Go 1 should keep compiling across later 1.x releases. Modules, introduced in 2018 and default since Go 1.16, handle versioned dependencies. Generics arrived in Go 1.18 (2022) with type parameters.

The official toolchain, historically called `gc`, is the reference implementation; `gccgo` is an alternative front end for GCC. Development follows an open proposal process on the Go issue tracker.

## Paradigm and type system

Go is statically typed with type inference for local variables. Interfaces are satisfied structurally: a type implements an interface simply by having the required methods, with no explicit declaration. The language has no classes or inheritance; it composes behavior through embedding and interfaces. Errors are ordinary values of the `error` interface, returned alongside results rather than thrown.

```go
type Stringer interface {
    String() string
}

func describe(s Stringer) string {
    return "value: " + s.String()
}
```

Since Go 1.18, functions and types can take type parameters constrained by interfaces.

## Toolchain and ecosystem

- The `go` command builds, tests, formats, and manages modules in one tool.
- Dependencies are declared in `go.mod` and resolved from module proxies; the default is [proxy.golang.org](https://proxy.golang.org/).
- Formatting is standardized by `gofmt`; `go vet` reports suspicious constructs, and [staticcheck](https://staticcheck.dev/) adds deeper analysis.

```bash
go mod init example.com/app
go get github.com/google/uuid
go build ./...
```

## Syntax tour

```go
package main

import (
    "fmt"
    "sort"
)

type Shape interface {
    Area() float64
}

type Circle struct{ R float64 }

func (c Circle) Area() float64 { return 3.14159265 * c.R * c.R }

func main() {
    shapes := []Shape{Circle{R: 2}, Circle{R: 3}}
    total := 0.0
    for _, s := range shapes {
        total += s.Area()
    }
    fmt.Printf("total area: %.2f\n", total)

    nums := []int{3, 1, 2}
    sort.Ints(nums)
    fmt.Println(nums)

    // The multiple-return error idiom
    if _, err := divide(1, 0); err != nil {
        fmt.Println("error:", err)
    }
}

func divide(a, b int) (int, error) {
    if b == 0 {
        return 0, fmt.Errorf("division by zero")
    }
    return a / b, nil
}
```

## Idioms and different approaches

- Return `(result, error)` and check `if err != nil` at each step; wrap errors with `fmt.Errorf("...: %w", err)` to preserve the chain.
- Use `defer` to release resources (close files, unlock mutexes) at the end of a function.
- Keep interfaces small and define them where they are used, not where types are declared.
- Prefer communicating over shared channels to sharing memory, per the language's concurrency guidance.
- Accept interfaces and return concrete types where it clarifies the API.

## Design principles

Go values simplicity and readability over feature breadth: the language is small enough to hold in one's head, formatting is standardized so teams do not argue about style, and compilation is fast. The design deliberately omitted features such as exceptions and, until 2022, generics, to keep the language and its tooling simple.

## Standard library and notable packages

The standard library covers HTTP servers and clients (`net/http`), encoding (`encoding/json`, `encoding/xml`), input and output (`io`, `bufio`), concurrency (`sync`, `context`), and testing (`testing`). Widely used third-party packages include [gin](https://github.com/gin-gonic/gin) and [chi](https://github.com/go-chi/chi) for web routing, [cobra](https://github.com/spf13/cobra) for command-line interfaces, and [sqlc](https://github.com/sqlc-dev/sqlc) for database access.

## Testing and packaging

Testing is built in: files ending `_test.go` with functions named `TestXxx(t *testing.T)` run under `go test`. The toolchain also supports benchmarks, fuzzing, and example tests. A module is published simply by tagging a version in its version-control repository; consumers fetch it through the module system.

```go
package math

import "testing"

func Add(a, b int) int { return a + b }

func TestAdd(t *testing.T) {
    if got := Add(2, 3); got != 5 {
        t.Errorf("Add(2, 3) = %d, want 5", got)
    }
}
```

## Performance and concurrency

Go compiles to native binaries with a concurrent, low-latency garbage collector. Concurrency is built into the language: `go f()` starts a goroutine, a lightweight thread multiplexed onto operating-system threads, and channels pass values between them. The `sync` package provides mutexes and wait groups, and `context` carries cancellation and deadlines. The race detector (`go test -race`) finds data races at run time.

## Common pitfalls

- Ignoring returned errors, which hides failures.
- Capturing a loop variable in a goroutine; before Go 1.22 the variable was shared, so take a copy.
- Leaking goroutines that block forever on a channel with no sender or receiver.
- Nil interface values that are non-nil when they hold a nil concrete pointer.
- Unsynchronized access to shared maps, which panics or corrupts data under concurrency.

## Secure coding

Go's garbage collection removes most memory-safety bugs, but risks remain:

- OS command injection: pass arguments to `exec.Command` as separate parameters, never a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- SQL injection: use parameterized queries with `database/sql` placeholders rather than string concatenation, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Path traversal: validate and clean user-supplied paths with `filepath.Clean` and confirm they stay within an intended root, which maps to [CWE-22](https://cwe.mitre.org/data/definitions/22.html).
- Integer overflow and conversions: check bounds when converting between integer widths, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).

Tooling: run `go vet`, [staticcheck](https://staticcheck.dev/), and [govulncheck](https://go.dev/blog/govulncheck) to scan for known vulnerabilities in dependencies. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [A Tour of Go](https://go.dev/tour/) and the [official documentation](https://go.dev/doc/).
- [Effective Go](https://go.dev/doc/effective_go), a guide to idiomatic style.
- [The Go Blog](https://go.dev/blog/), for design notes and feature introductions.

## Related pages

- [Rust](/languages/rust.md)
- [C](/languages/c.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
