# Programming paradigms

In-depth reference pages for the ways programs are organized. A paradigm is not a language: it is a model for what the units of code are, how they hold state, and how control moves between them. Most languages support several paradigms, and a paradigm is often defined as much by what it forbids as by what it allows, so pure functional programming is known for disallowing side effects and structured programming for disallowing unrestricted jumps.

Each page defines one paradigm, shows how it works with runnable examples, gives its strengths and trade-offs, names the languages and tools that use it, covers its secure-coding failure modes, and ends with a curated bibliography of the seminal works. These pages are the concept behind the per-language pages: each [language page](/languages/README.md) names the paradigms it supports, and these pages define them.

The highest-level split is between imperative code, which states the order of operations and changes state directly, and declarative code, which describes the result and lets the execution model choose the steps. The split is a guide, not a rule: many languages combine features from several paradigms, and classification is usually done after the fact. Treat the names as a vocabulary for design choices, not as boxes a language sits in.

Related: [All languages](/languages/README.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Application Security](/disciplines/application-security.md), [Reference Index](/INDEX.md).

---

## Imperative paradigms

Code states the order of operations and changes program state directly.

| Paradigm | Summary |
|---|---|
| [Imperative programming](/paradigms/imperative.md) | The umbrella model: statements that change state in order, built on the von Neumann machine |
| [Procedural programming](/paradigms/procedural.md) | Code organized into procedures that call each other and operate on shared or passed data |
| [Structured programming](/paradigms/structured.md) | Sequence, selection, and iteration without unrestricted jumps; a discipline within imperative code |
| [Object-oriented programming](/paradigms/object-oriented.md) | Data and behavior bundled into objects: encapsulation, inheritance, polymorphism, and abstraction |

## Declarative paradigms

Code describes the result; the execution model chooses the steps.

| Paradigm | Summary |
|---|---|
| [Declarative programming](/paradigms/declarative.md) | The umbrella model: state what is wanted, not how to compute it; the basis of query and configuration languages |
| [Functional programming](/paradigms/functional.md) | Programs as function evaluation: pure functions, immutability, higher-order functions, and pattern matching |
| [Logic programming](/paradigms/logic.md) | Facts and rules queried by automated reasoning, through unification and backtracking |
| [Constraint programming](/paradigms/constraint.md) | Relations stated as constraints that a solver satisfies; constraint satisfaction, propagation, and search |
| [Symbolic programming](/paradigms/symbolic.md) | Programs that manipulate symbolic expressions and code as data; the Lisp and Prolog tradition |

## Concurrency, events, and streams

Structuring programs that do several things at once or react to inputs over time.

| Paradigm | Summary |
|---|---|
| [Concurrent programming](/paradigms/concurrent.md) | Multiple threads of control making progress together: synchronization, data races, and memory models |
| [The actor model](/paradigms/actor-model.md) | Actors with private state that communicate only by asynchronous messages; supervision and let-it-crash |
| [Reactive programming](/paradigms/reactive.md) | Asynchronous data streams with automatic propagation of change; observables and backpressure |
| [Dataflow programming](/paradigms/dataflow.md) | A graph of operations where data flows along edges and a node fires when its inputs are ready |
| [Event-driven programming](/paradigms/event-driven.md) | Control flow driven by events and handlers around an event loop; callbacks, promises, and pub-sub |

## Cross-cutting and specialized

Models that layer onto others or fit a particular class of problem.

| Paradigm | Summary |
|---|---|
| [Generic programming](/paradigms/generic.md) | Algorithms and data structures written over types supplied later: templates, generics, and the STL |
| [Metaprogramming](/paradigms/metaprogramming.md) | Programs that generate or transform programs: macros, templates, reflection, and the metaobject protocol |
| [Aspect-oriented programming](/paradigms/aspect-oriented.md) | Cross-cutting concerns such as logging and security separated into aspects and woven in |
| [Array-oriented programming](/paradigms/array-oriented.md) | Operating on whole arrays at once with implicit iteration; the APL, J, and K lineage |
| [Stack-oriented programming](/paradigms/stack-oriented.md) | Computation by pushing and popping an operand stack; postfix evaluation and concatenative composition |
| [Data-oriented design](/paradigms/data-oriented.md) | Organizing code around data layout and memory access for the hardware, not around objects |

## Paradigms and secure coding

Each paradigm carries its own failure modes, and the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) is where the defenses live. Imperative and object-oriented code shares mutable state, so data races and broken invariants are the risks. Object graphs rebuilt from untrusted input are the deserialization risk (CWE-502). Declarative and query languages move the injection risk to where the query or model is built (CWE-89, CWE-94). Functional code reduces shared-state bugs but still has to validate input and handle errors explicitly. Each paradigm page has a secure-coding section with the specifics.
