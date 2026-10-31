# Racket

Racket is a dynamically typed, multi-paradigm descendant of Scheme, built for language-oriented programming: it lets programmers define new languages and dialects as readily as libraries. It began as PLT Scheme in the 1990s and was renamed Racket in 2010. It ships a batteries-included standard library, the DrRacket development environment, and a module system in which each file can declare the language it is written in. It is used in teaching, language research, scripting, and application development.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: functional, imperative, object-oriented, language-oriented |
| Typing | Dynamic by default; static via the Typed Racket dialect |
| First appeared | 1995 as PLT Scheme; renamed Racket in 2010 |
| Memory model | Automatic: garbage collection |
| Reference implementation | [Racket](https://github.com/racket/racket) (the Racket CS runtime on Chez Scheme) |
| Typical uses | Teaching, language research, scripting, application development |
| Governance | [Racket](https://racket-lang.org/) maintained by the Racket community and PLT |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Scheme](/languages/scheme.md), [languages index](/languages/README.md).

## Overview and history

Racket grew out of PLT Scheme, a project started in the mid-1990s to support programming-language education and research. In 2010 the project renamed the language Racket to signal that it had moved beyond standard Scheme into its own design, centered on building languages. Since around 2019 the main runtime, Racket CS, is implemented on top of Chez Scheme, which improved performance and maintainability.

The defining idea is language-oriented programming: the `#lang` line at the top of a file selects the language that file is written in, and that language can be one Racket provides (such as `racket`, `racket/base`, or `typed/racket`) or one a library defines. This makes domain-specific languages first-class artifacts rather than string-embedded interpreters.

## Paradigm and type system

Racket is dynamically typed by default and primarily functional, with full support for imperative and object-oriented styles. Its macro system, built on Scheme's hygienic macros and extended with phase separation and syntax objects, lets libraries add syntax that integrates with the module system. [Typed Racket](https://docs.racket-lang.org/ts-guide/) is a statically typed dialect, selected with `#lang typed/racket`, that adds a type system able to express many idioms of untyped Racket and to interoperate with untyped modules through contracts.

```racket
#lang typed/racket

(: area (-> Symbol Real Real Real))
(define (area shape a b)
  (cond
    [(eq? shape 'circle) (* pi a a)]
    [(eq? shape 'rect)   (* a b)]
    [else 0]))
```

Contracts enforce agreements between modules at run time: a module can attach a contract to an exported function, and violations are blamed on the party that broke the agreement.

## Toolchain and ecosystem

- Runtime and tools: `racket` runs programs and a REPL; [DrRacket](https://docs.racket-lang.org/drracket/) is the bundled development environment with a stepper and Check Syntax.
- Command-line tool: `raco` builds, tests, documents, and manages packages.
- Package manager: `raco pkg` installs from the [Racket package catalog](https://pkgs.racket-lang.org/).
- Documentation: [Scribble](https://docs.racket-lang.org/scribble/) is Racket's documentation language, used for the manuals and for library docs.

```bash
raco pkg install threading-lib
raco test my-module.rkt
racket my-program.rkt
```

## Syntax tour

```racket
#lang racket

;; Structs and pattern matching
(struct node (left value right))

(define (insert x tree)
  (match tree
    [#f (node #f x #f)]
    [(node l v r)
     (cond
       [(< x v) (node (insert x l) v r)]
       [(> x v) (node l v (insert x r))]
       [else tree])]))

(define (to-list tree)
  (match tree
    [#f '()]
    [(node l v r) (append (to-list l) (list v) (to-list r))]))

;; Comprehensions and higher-order functions
(define (sum-of-squares xs)
  (for/sum ([n (in-list xs)]) (* n n)))

(to-list (foldl insert #f '(5 3 8 1 4)))  ; '(1 3 4 5 8)
```

## Idioms and different approaches

- Reach for `match` and structs to destructure data by shape, and use `for` comprehensions (`for/list`, `for/sum`, `for/fold`) for iteration that produces a value.
- Define a domain-specific language with `#lang` and macros when a problem has its own natural notation; this is the design Racket is built to support.
- Attach contracts to module boundaries so that misuse is reported precisely, with blame assigned to the offending module.
- Choose the dialect per file: `racket/base` for a small footprint, `racket` for the full library, and `typed/racket` where static checking pays off.

## Design principles

Racket treats languages as the unit of abstraction: rather than fit every problem into one fixed syntax, a programmer can build the language that fits the problem and have it participate fully in the module system, documentation tools, and editor support. Hygienic macros with phase separation make this safe, and contracts give dynamically typed modules a precise interface discipline. The project's roots in education show in DrRacket and in teaching languages that grow in capability as a course progresses.

## Standard library and notable packages

Racket ships an extensive standard library covering data structures, I/O, networking, a web server, a GUI toolkit, and the `racket/match`, `racket/contract`, and `racket/class` modules for matching, contracts, and objects. The package catalog adds more: [threading](https://pkgs.racket-lang.org/package/threading) for pipeline macros, [rackunit](https://docs.racket-lang.org/rackunit/) for testing (bundled), web frameworks, and bindings to external libraries. Scribble, Typed Racket, and the teaching languages are themselves libraries built on the same mechanisms.

## Testing and packaging

[RackUnit](https://docs.racket-lang.org/rackunit/) is the standard test framework, run with `raco test`.

```racket
#lang racket
(require rackunit)

(check-equal? (+ 2 3) 5 "addition")
```

A package is a directory with an `info.rkt` metadata file; `raco pkg` installs it, and publishing registers it with the package catalog so others can install it by name.

## Performance and concurrency

The Racket CS runtime, built on Chez Scheme, compiles to native code and gives Racket solid performance for a dynamically typed language. Concurrency comes in two forms: green threads scheduled by the runtime for concurrent I/O and coordination, and places, which run on separate operating-system threads with their own heaps and communicate by message passing for parallelism across cores. Futures offer a lighter form of parallelism for computations that avoid certain runtime interactions. Because green threads share one core, CPU-bound parallelism uses places or futures rather than threads.

## Common pitfalls

- Mixing typed and untyped modules adds contract checks at the boundary, which can cost performance; keep hot paths within one world or profile the boundary.
- `racket` loads a large library and starts more slowly than `racket/base`; use `racket/base` with explicit requires for small scripts and libraries.
- Macro phase levels (`require` for-syntax versus run time) confuse newcomers; a binding needed at compile time must be required at the right phase.
- Mutable pairs (`mcons`) are separate from the default immutable pairs, so code ported from other Lisps that mutates lists needs adjustment.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Evaluating untrusted code: Racket can run code dynamically with `eval`, and running attacker-controlled code outside a sandbox is a code-injection risk. Use the [`racket/sandbox`](https://docs.racket-lang.org/reference/Sandboxed_Evaluation.html) library, which limits memory, time, and filesystem and network access, when you must evaluate untrusted programs. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Unsafe reading and deserialization: using `read` on attacker-controlled input can construct unexpected values, and reader extensions can broaden what reading does; validate input and prefer a format-specific parser such as `read-json`. This relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Input validation at the boundary: dynamic typing leaves external data unchecked; validate with contracts or explicit checks, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Resource exhaustion: recursion or allocation sized by untrusted input can exhaust memory; bound sizes, and use sandbox limits for untrusted computations, to address [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Dependency supply chain: pin package versions and review packages from the catalog, which is community-contributed; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: DrRacket's Check Syntax statically analyzes binding structure and reports unbound and unused identifiers; the [`racket/contract`](https://docs.racket-lang.org/reference/contracts.html) system enforces interface agreements at run time with blame; and Typed Racket adds static type checking to modules that opt in.

## Learning resources

- [The Racket Guide](https://docs.racket-lang.org/guide/), the introductory manual.
- [The Racket Reference](https://docs.racket-lang.org/reference/), the full language and library reference.
- [How to Design Programs](https://htdp.org/), a teaching text using Racket's student languages.

## Related pages

- [Scheme](/languages/scheme.md)
- [Common Lisp](/languages/common-lisp.md)
- [Haskell](/languages/haskell.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
