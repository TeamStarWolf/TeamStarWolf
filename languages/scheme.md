# Scheme

Scheme is a minimalist dialect of Lisp, first described in 1975 by Gerald Sussman and Guy Steele, built around a small core of orthogonal features: lexical scope, first-class functions, proper tail calls, and first-class continuations. A series of standards (the Revised Reports and the R7RS) keep the core small while allowing implementations to extend it. It is used in teaching, language research, scripting, and as an embedded extension language.

| Attribute | Value |
|---|---|
| Paradigm | Functional, multi-paradigm, metaprogramming |
| Typing | Dynamic, strong |
| First appeared | 1975 |
| Memory model | Automatic: garbage collection |
| Reference implementation | No single reference; many conforming implementations (Chez, Guile, Chicken, Gambit, Racket) |
| Typical uses | Teaching, language research, scripting, embedded extension language |
| Governance | [R7RS](https://standards.scheme.org/) and earlier Revised Reports; community standards process |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Racket](/languages/racket.md), [languages index](/languages/README.md).

## Overview and history

Scheme began as an experiment in applying the actor model and lexical scope to Lisp, and it became influential for its small, carefully specified core. Its evolution is recorded in the Revised Reports, informally the RnRS series: R5RS (1998) is a compact and widely implemented standard, R6RS (2007) added a larger library and a module system and was more contentious, and R7RS (2013) split the language into a small language and a larger standard library to serve both teaching and application needs.

There is no single reference implementation; the standard is the authority and many implementations conform to it. Common ones include [Chez Scheme](https://cisco.github.io/ChezScheme/) (a fast native compiler), [Guile](https://www.gnu.org/software/guile/) (the GNU extension language), [Chicken](https://www.call-cc.org/) (compiles through C), and [Gambit](https://gambitscheme.org/). Racket began as a Scheme and is now a separate language documented on its own page.

## Paradigm and type system

Scheme is dynamically typed with strong typing and is primarily functional, though it provides assignment (`set!`) and mutable data for imperative code. Its design values a few general mechanisms over many special cases: lexical scoping, functions as first-class values, proper tail-call optimization that makes iteration expressible as recursion without growing the stack, and first-class continuations (`call/cc`) that capture the rest of a computation as a value.

```scheme
;; First-class functions and lexical closures
(define (make-adder n)
  (lambda (x) (+ x n)))

(define add5 (make-adder 5))
(add5 10)  ; 15
```

Macros transform code before evaluation. R5RS and later define `syntax-rules`, a hygienic pattern-based macro system that avoids accidental variable capture, in contrast with the manual hygiene of older Lisps.

## Toolchain and ecosystem

- Implementations: each provides its own compiler or interpreter and REPL; `chez`, `guile`, `csi` (Chicken), and others start interactive sessions.
- Libraries: R7RS defines a library (module) system; implementations add package managers, for example Chicken's `chicken-install` eggs and Guile's module and channel tooling.
- Portability: the [Scheme Requests for Implementation (SRFI)](https://srfi.schemers.org/) process standardizes libraries across implementations so portable code can rely on them.
- Editor support: Scheme integrates with Emacs (Geiser) and other editors through each implementation's REPL.

```bash
# Chicken Scheme
csc program.scm      # compile to a native executable
./program

# Guile
guile program.scm    # run a script
```

## Syntax tour

```scheme
;; Binary search tree over nested lists
(define (insert x tree)
  (if (null? tree)
      (list '() x '())
      (let ((left (car tree))
            (value (cadr tree))
            (right (caddr tree)))
        (cond ((< x value) (list (insert x left) value right))
              ((> x value) (list left value (insert x right)))
              (else tree)))))

(define (to-list tree)
  (if (null? tree)
      '()
      (append (to-list (car tree))
              (list (cadr tree))
              (to-list (caddr tree)))))

;; Tail-recursive accumulation; the stack does not grow
(define (sum-list xs acc)
  (if (null? xs)
      acc
      (sum-list (cdr xs) (+ acc (car xs)))))

(display (to-list (fold-left (lambda (t x) (insert x t)) '() '(5 3 8 1 4))))
(newline)
```

## Idioms and different approaches

- Write iteration as tail recursion; proper tail calls guarantee it runs in constant stack space, so an explicit loop construct is unnecessary.
- Define hygienic macros with `syntax-rules` for new syntactic forms; reach for lower-level macro systems only when pattern rules are not enough.
- Pass behavior as functions and use closures to capture state, rather than building classes; many object systems in Scheme are libraries, not language features.
- Depend on SRFIs for portable utilities so code moves between implementations.

## Design principles

The guiding principle, stated in the reports, is to remove weaknesses and restrictions that make additional features appear necessary rather than to pile features on. The result is a small language whose pieces compose: lexical scope, first-class functions, tail calls, and continuations together express a wide range of control and data abstractions. Hygienic macros extend the language without the variable-capture hazards of unhygienic systems. This minimalism is why Scheme is a common teaching and research vehicle.

## Standard library and notable packages

R7RS-small specifies base facilities (lists, numbers, characters, strings, vectors, basic I/O) in a set of standard libraries, and R7RS-large and the SRFIs extend this with hash tables, additional list and string operations, and more. Because portable libraries are distributed as SRFIs, a Scheme program that stays within R7RS plus chosen SRFIs runs across conforming implementations. Implementation-specific ecosystems add more: Chicken has its egg repository, and Guile ships extensive modules for its role as an extension language.

## Testing and packaging

Testing is commonly done with SRFI-64, a standard test API, or with an implementation's own framework; implementations supply the runner.

```scheme
(import (srfi 64))

(test-begin "math")
(test-equal 5 (+ 2 3))
(test-end "math")
```

Packaging depends on the implementation: Chicken distributes eggs installed with `chicken-install`, Guile uses its module system and distribution channels, and portable code is published as SRFIs or source libraries that target R7RS.

## Performance and concurrency

Performance varies widely by implementation. Chez Scheme compiles to native code and is fast; interpreters favor startup time and simplicity over throughput. Proper tail calls make recursive loops efficient in stack use across all conforming implementations. The core standard does not define a threading or concurrency model, so parallelism and threads are implementation-specific; some implementations provide native threads, SRFI-18 defines a portable threading API that several support, and first-class continuations can express coroutines and other control structures within a single thread.

## Common pitfalls

- Using `set!` and mutation defeats the reasoning benefits of functional code; prefer returning new values unless mutation is clearly needed.
- Portability gaps: code that relies on one implementation's extensions will not run on another; stay within R7RS and declared SRFIs for portable programs.
- First-class continuations captured with `call/cc` are general but can produce control flow that is hard to follow; use them deliberately and document the intent.
- `eq?`, `eqv?`, and `equal?` test identity, equivalence, and structural equality respectively; choosing the wrong one causes subtle bugs.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Dynamic evaluation: `eval` applied to data built from untrusted input executes arbitrary code; do not evaluate external data, and parse it with a dedicated reader for the expected format instead. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Unsafe reading and deserialization: using the Scheme reader on attacker-controlled text to reconstruct data can create unexpected structures and, in some implementations with reader extensions, trigger evaluation; validate and bound what you read. This relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Input validation at the boundary: dynamic typing leaves external data unchecked until you check it; validate structure and ranges explicitly, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Resource exhaustion: recursion or allocation sized by untrusted input can exhaust memory; proper tail calls bound stack growth for tail recursion, but non-tail recursion and unbounded data still need size limits, which addresses [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Dependency supply chain: pin SRFI and library versions and review implementation-specific packages; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: static analysis is implementation-specific. Chez Scheme and other compilers emit warnings for unbound references and arity mistakes, and when Scheme code runs under Racket, DrRacket's Check Syntax reports binding and scope errors statically. Enable and act on these diagnostics.

## Learning resources

- [Revised Reports and R7RS](https://standards.scheme.org/), the language standards.
- Structure and Interpretation of Computer Programs, the classic text that uses Scheme.
- [SRFI index](https://srfi.schemers.org/), the portable library specifications.

## Related pages

- [Racket](/languages/racket.md)
- [Common Lisp](/languages/common-lisp.md)
- [Standard ML](/languages/standard-ml.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
