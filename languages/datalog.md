# Datalog

Datalog is a declarative logic-programming and query language that grew out of database theory and logic programming in the late 1970s and 1980s. A program is a set of facts and rules; a query asks what follows from them. Datalog is a restricted form of Prolog, without function symbols in the usual case and with a guarantee that evaluation terminates, which makes it suitable as a query language for deductive databases and for program analysis. It has no single standard; several dialects and engines implement it.

| Attribute | Value |
|---|---|
| Paradigm | Declarative logic programming; rules over relations (Horn clauses) |
| Typing | Dialect-dependent: untyped terms, or typed relations in engines such as Soufflé |
| First appeared | Early 1980s (roots in late-1970s deductive-database research) |
| Memory model | Managed by the engine; relations are materialized during evaluation |
| Reference implementation | No single standard; [Soufflé](https://souffle-lang.github.io/) and others implement dialects |
| Typical uses | Deductive databases, static program analysis, access-control policy, graph queries |
| Governance | No central standard; defined by academic literature and per-engine dialects |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [SPARQL](/languages/sparql.md), [languages index](/languages/README.md).

## Overview and history

Datalog emerged from research on deductive databases, where the goal was to extend relational queries with recursion and inference while keeping strong guarantees. By restricting Prolog, removing arbitrary function symbols and requiring rules to be range-restricted, Datalog gains a property Prolog lacks: a program over a finite set of facts has a finite result and terminates. That guarantee is why it is used where predictability matters.

Datalog had a long academic life before a practical resurgence. It now appears in static analysis frameworks (for example [Soufflé](https://souffle-lang.github.io/), used for points-to and security analyses), in the query language of [Datomic](https://www.datomic.com/), in network and access-control policy engines, and in incremental systems such as [Differential Datalog](https://github.com/vmware/differential-datalog). Because there is no single standard, dialects differ in syntax, typing, negation, and arithmetic.

## Paradigm and type system

A Datalog program is a set of Horn clauses. A fact asserts a tuple in a relation; a rule derives new tuples from existing ones. A rule head holds when its body (a conjunction of relation atoms) can be satisfied by some binding of its variables.

```prolog
% Facts: the edge relation of a graph
edge(a, b).
edge(b, c).

% Rule: reachability is the transitive closure of edge
reachable(X, Y) :- edge(X, Y).
reachable(X, Y) :- edge(X, Z), reachable(Z, Y).
```

Classic Datalog is untyped: terms are constants and variables. Engines aimed at analysis, such as Soufflé, add a static type system for relations (numbers, symbols, records) to catch errors and speed evaluation. Variables are logical, not assignable: the same variable in the body and head must take the same value.

## Toolchain and ecosystem

- Engines: [Soufflé](https://souffle-lang.github.io/) compiles Datalog to parallel C++ for analysis workloads; [Datomic](https://www.datomic.com/) embeds a Datalog dialect as its query language; teaching and research engines include DES and the LogicBlox lineage.
- Embedding: several libraries embed Datalog in a host language (for example in Clojure through Datomic and in Python and Rust through various crates and packages), so queries run against in-memory relations.
- Evaluation: engines use bottom-up methods (semi-naive evaluation) and optimizations such as magic sets; some compile rules to native code.
- Because dialects differ, a program is usually written for one engine; there is no portable toolchain across all of them.

```bash
# Run a Soufflé program that reads and writes relation files
souffle -F facts/ -D out/ analysis.dl
```

## Syntax tour

```prolog
% Facts populate base ("extensional") relations
parent(alice, bob).
parent(bob, carol).

% Rules define derived ("intensional") relations
ancestor(X, Y) :- parent(X, Y).
ancestor(X, Y) :- parent(X, Z), ancestor(Z, Y).

% A query asks for bindings that satisfy a goal
% ?- ancestor(alice, Who).     % Who = bob; Who = carol

% Stratified negation: a person with no recorded parent
has_parent(X) :- parent(X, _).
root(X) :- parent(X, _), not has_parent(X).

% Engines such as Soufflé add typed relations and declarations
% .decl edge(x:number, y:number)
% .decl reachable(x:number, y:number)
```

## Idioms and different approaches

- Separate base relations (facts loaded as input, the "extensional" database) from derived relations (computed by rules, the "intensional" database); this split clarifies what is data and what is inference.
- Express recursion directly: transitive closure, reachability, and ancestry are a rule plus its recursive case, where SQL would need a recursive common table expression.
- Keep rules range-restricted: every variable in a rule head must appear in a positive body atom, which is what guarantees finite results.
- Use negation only in a stratified way (no relation depends negatively on itself), so the program has a well-defined meaning; many engines reject non-stratified negation.
- For analysis problems (points-to, taint, dependency), model the program's facts as relations and the analysis as rules; this is how Datalog is used in static analysis.

## Design principles

Datalog's defining trade-off is to give up some of Prolog's expressiveness in exchange for guarantees: termination, a declarative meaning independent of rule order, and set-oriented evaluation. Rules are read as logical implications, not procedures, so the engine, not the author, chooses an evaluation order, typically bottom-up from the facts. The restrictions (range restriction, stratified negation, limited or no function symbols) exist precisely to keep the language decidable and its results finite, which is what lets it serve as a predictable query and analysis language.

## Standard features and extensions

Pure Datalog is small: relations, rules, conjunction, and queries. Practical dialects extend it. Stratified negation adds `not`; arithmetic and comparison add built-in predicates; aggregation (counts, sums, minimums) summarizes derived relations; and some engines add arithmetic over numbers, strings, and records with a type system. Soufflé adds components, user-defined functors, and compilation to parallel code. Datomic's dialect adds built-in predicates and integration with its database. Because these features are per-engine, a program's "standard library" is whatever its engine documents.

## Testing and tooling

Datalog programs are tested by supplying input relations and checking the derived relations against expected tuples; engines that read and write relation files make this a matter of comparing output files.

```prolog
% Given input edge/2, assert the expected reachable/2 tuples
% Expected: reachable(a, b), reachable(a, c), reachable(b, c)
reachable(X, Y) :- edge(X, Y).
reachable(X, Y) :- edge(X, Z), reachable(Z, Y).
```

Soufflé can emit relations to files for a test harness to diff, and its type checker catches malformed rules before evaluation. For embedded dialects such as Datomic's, queries are tested within the host language's test framework against a known database value.

## Performance and query execution

Datalog engines evaluate bottom-up, deriving all consequences of the rules, and use semi-naive evaluation to avoid recomputing tuples already known, plus techniques such as magic sets to focus work on what a query needs. Performance depends on relation sizes and rule structure; a recursive rule over a dense relation can materialize large intermediate results, so indexing and rule ordering matter even though the language is declarative.

Some engines exploit the set-oriented, order-independent semantics to parallelize: Soufflé compiles to parallel C++ and evaluates independent rule firings across threads, and differential or incremental engines recompute only what changed when input relations are updated. Concurrency is therefore an engine feature enabled by the language's declarative meaning, not something the program expresses.

## Common pitfalls

- Non-stratified negation: a relation defined in terms of its own negation has no clear meaning, and engines either reject it or give surprising results; keep negation stratified.
- Range restriction violations: a variable in a rule head that does not appear in a positive body atom can make a relation infinite or be rejected by the engine.
- Dialect assumptions: syntax, typing, negation, and arithmetic differ between engines, so a program written for one (Soufflé) will not run unchanged on another (Datomic).
- Recursion cost: a recursive rule over a large or dense relation can materialize very large intermediate relations; watch relation sizes and add constraints.
- Confusing Datalog with Prolog: Prolog's order-sensitive, top-down evaluation and function symbols do not carry over, and relying on them produces wrong expectations.

## Secure coding

When an application generates Datalog rules or queries from untrusted input, the central risk is injection into the generated program:

- Datalog injection: concatenating untrusted input into a rule or query lets an attacker add or alter clauses, which can expand what the query returns or, in a policy engine, change the decision. Build queries through an engine API that binds values as terms rather than assembling program text from strings; this is the Datalog case of query injection, related to [CWE-943](https://cwe.mitre.org/data/definitions/943.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Policy-engine correctness: when Datalog expresses access-control or authorization policy, a crafted input that changes the derived relation can grant or deny access incorrectly; validate inputs and treat them as data to match against, never as rules. Authorization errors map to [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
- Resource exhaustion: a query or added rule that triggers large recursive derivations can exhaust memory and time; bound relation sizes, constrain recursion, and apply limits when evaluating untrusted queries, which addresses uncontrolled resource consumption, [CWE-770](https://cwe.mitre.org/data/definitions/770.html).
- Trusting derived facts: if base facts come from untrusted sources, every derived relation inherits that trust problem; validate and scope input relations before loading them, and keep analysis results separate from trusted data.

Tooling: prefer engine query APIs that parameterize over hand-built program text; where an engine offers a type checker (as Soufflé does), use it to reject malformed rules before evaluation. See also [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) for the engines and libraries a program depends on.

## Learning resources

- [Soufflé documentation](https://souffle-lang.github.io/), a practical guide to a typed, compiled Datalog used for analysis.
- [Datomic query documentation](https://docs.datomic.com/query/query-data-reference.html), a widely used embedded Datalog dialect.
- ["What You Always Wanted to Know About Datalog (And Never Dared to Ask)"](https://ieeexplore.ieee.org/document/43410), the Ceri, Gottlob, and Tanca survey of the theory.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [SPARQL](/languages/sparql.md)
- [All languages](/languages/README.md)
