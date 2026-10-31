# Clojure

Clojure is a dynamically typed dialect of Lisp created by Rich Hickey and first released in 2007. It runs on the Java Virtual Machine, compiles to JavaScript through ClojureScript, and emphasizes immutable data and functional programming. It is used for back-end services, data processing, and web applications where a functional style and Java interoperability are both wanted.

| Attribute | Value |
|---|---|
| Paradigm | Functional, with Lisp macros and controlled state |
| Typing | Dynamic, strong |
| First appeared | 2007 |
| Memory model | Garbage collected on the JVM |
| Reference implementation | [Clojure](https://github.com/clojure/clojure) |
| Typical uses | Back-end services, data processing, web applications |
| Governance | Core team led by Rich Hickey, stewarded by [Nubank](https://clojure.org/) |

Related: [Java](/languages/java.md), [Scala](/languages/scala.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Overview and history

Rich Hickey designed Clojure to bring a practical Lisp to the JVM with a strong stance on immutability and a clear model for managed state, releasing it in 2007. The language is hosted: it compiles to JVM bytecode and calls Java libraries directly. [ClojureScript](https://clojurescript.org/) compiles the same language to JavaScript, and [ClojureCLR](https://github.com/clojure/clojure-clr) targets the .NET runtime.

Clojure development is led by a core team around Hickey; the company Nubank now stewards the project. Changes are deliberate and backward-compatible, and the language is documented at [clojure.org](https://clojure.org/).

## Paradigm and type system

Clojure is a functional Lisp: code is written as data (s-expressions), functions are first class, and the core data structures (lists, vectors, maps, sets) are immutable and persistent, sharing structure to make updates cheap. Typing is dynamic and strong. State changes are explicit through reference types (atoms, refs, agents, vars) with defined concurrency semantics rather than unrestricted mutation.

```clojure
(defn total [prices tax]
  (* (reduce + prices) (+ 1 tax)))

(def counter (atom 0))
(swap! counter inc)
```

Optional runtime specification of data shapes is available through [clojure.spec](https://clojure.org/guides/spec), which validates and generates data without a static type system.

## Toolchain and ecosystem

- Runtime and REPL: Clojure runs on the JVM; the read-eval-print loop is central to the workflow.
- Build and dependencies: the official [Clojure CLI with tools.deps](https://clojure.org/guides/deps_and_cli) resolves dependencies from Maven Central and [Clojars](https://clojars.org/); [Leiningen](https://leiningen.org/) is an older build tool still in wide use.
- Formatting and linting: [cljfmt](https://github.com/weavejester/cljfmt) formats code, and [clj-kondo](https://github.com/clj-kondo/clj-kondo) is a static linter.

```bash
clojure -M -e '(println "hello, world")'
clj   # start a REPL
```

## Syntax tour

```clojure
;; Everything is a parenthesized form: (operator operands...)
(println "hello," "world")

;; Immutable collections
(def squares (mapv #(* % %) (range 5)))   ; vector [0 1 4 9 16]
(def lookup {:a 1 :b 2})                   ; map

;; Functions and higher-order functions
(defn greet
  ([who] (greet who false))
  ([who excited?]
   (str "hi " who (if excited? "!" "."))))

;; Destructuring
(let [{:keys [a b]} lookup]
  (+ a b))

;; Threading macro for readable pipelines
(->> (range 10)
     (filter even?)
     (map inc)
     (reduce +))

;; Java interop
(.toUpperCase "hello")
```

## Idioms and different approaches

- Model data with plain maps and vectors and keep it immutable; transform data with pure functions rather than mutating objects.
- Use the threading macros `->` and `->>` to write data pipelines left to right instead of nesting calls.
- Reach for `atom` for independent synchronous state, `ref` with `dosync` for coordinated state, and `agent` for asynchronous updates.
- Keep side effects at the edges and keep the core logic pure, which makes functions easy to test.
- Use macros only when a function cannot express the pattern, because macros run at compile time and are harder to compose.

## Design principles

Clojure's design centers on immutability, a separation of identity from state, and treating data as the primary interface rather than classes. Rich Hickey's talks ("Simple Made Easy" among them) argue for simplicity in the sense of un-braided concerns. The language favors a small set of data structures manipulated by many generic functions over many bespoke types, which shapes how programs are built.

## Standard library and notable libraries

The core library provides a large set of functions over sequences and collections, plus namespaces for strings (`clojure.string`), I/O, and specification (`clojure.spec`). Notable libraries include [Ring](https://github.com/ring-clojure/ring) for HTTP, [Reitit](https://github.com/metosin/reitit) for routing, [next.jdbc](https://github.com/seancorfield/next-jdbc) for databases, [core.async](https://github.com/clojure/core.async) for channel-based concurrency, and [Reagent](https://reagent-project.github.io/) and [re-frame](https://day8.github.io/re-frame/) for ClojureScript user interfaces.

## Testing and packaging

The built-in `clojure.test` library is the standard test framework.

```clojure
(ns calculator-test
  (:require [clojure.test :refer [deftest is]]))

(deftest adds-two-numbers
  (is (= 5 (+ 2 3))))
```

Libraries package as JAR files and publish to [Clojars](https://clojars.org/) or Maven Central. Applications build an uberjar (a JAR with all dependencies) for deployment.

## Performance and concurrency

Clojure runs on the JVM and benefits from the just-in-time compiler and garbage collectors. Persistent data structures add some overhead compared with mutable arrays, which transients (`transient`/`persistent!`) reduce for local hot paths, and type hints avoid reflection on interop calls. Concurrency is a strength of the design:

- Atoms provide lock-free compare-and-swap updates for independent state.
- Refs with software transactional memory coordinate changes across several references atomically.
- Agents apply updates asynchronously, and `core.async` provides channels and go blocks modeled on communicating sequential processes.

## Common pitfalls

- Lazy sequences defer work, so side effects inside a lazy pipeline may not run when expected; force realization with `doall` or use eager functions.
- Holding the head of a large lazy sequence prevents garbage collection and can exhaust memory.
- Unhinted Java interop uses reflection, which is slow; add type hints on hot paths.
- Overusing macros where functions would do makes code harder to read and compose.
- Deeply nested anonymous functions reduce readability; name intermediate steps.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Dynamic evaluation: `eval` and `read-string` on untrusted input can execute arbitrary code; use `clojure.edn/read-string`, which does not evaluate code, for untrusted data. This maps to [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Deserialization: JVM `ObjectInputStream` reconstructs arbitrary objects; prefer EDN or JSON with validation for untrusted data, addressing [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: use parameterized queries with `next.jdbc` placeholders, not string assembly, to avoid [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Command injection: pass arguments as a vector to `ProcessBuilder` or `clojure.java.shell/sh` rather than a shell string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Dependency supply chain: pin dependencies and scan them, including transitive JVM libraries; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [clj-kondo](https://github.com/clj-kondo/clj-kondo) flags suspicious code, and [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) scans the dependency graph. See the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [clojure.org](https://clojure.org/) guides and reference, the primary source.
- [ClojureDocs](https://clojuredocs.org/) for examples of core functions.
- [Clojure for the Brave and True](https://www.braveclojure.com/) for a book-length introduction.

## Related pages

- [Java](/languages/java.md)
- [Scala](/languages/scala.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
