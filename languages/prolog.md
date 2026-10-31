# Prolog

Prolog (Programming in Logic) is a declarative logic-programming language first implemented in 1972 by Alain Colmerauer's group, with theoretical grounding from Robert Kowalski. A program is a set of facts and rules; computation is a query that the system answers by searching for proofs through unification and backtracking. It is used for artificial intelligence, natural-language processing, theorem proving, constraint solving, and expert systems.

| Attribute | Value |
|---|---|
| Paradigm | Logic, declarative |
| Typing | Dynamic, untyped (values are terms) |
| First appeared | 1972 |
| Memory model | Automatic: garbage-collected heap plus a backtracking trail |
| Reference implementation | No single reference; [SWI-Prolog](https://www.swi-prolog.org/) is widely used, [GNU Prolog](http://www.gprolog.org/) and SICStus are others |
| Typical uses | AI, natural-language processing, theorem proving, constraint solving, expert systems |
| Governance/standard | [ISO/IEC 13211](https://www.iso.org/standard/21413.html) (Prolog) |

Related: [Smalltalk](/languages/smalltalk.md), [Logo](/languages/logo.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Prolog emerged from work on automated theorem proving and natural-language processing in Marseille in the early 1970s. Its execution model is resolution over Horn clauses: given facts and rules, the system tries to satisfy a goal by unifying it with clause heads and recursively satisfying the bodies, backtracking when a path fails. The language gained prominence through the 1980s, including Japan's Fifth Generation Computer project, which used it as a base.

ISO/IEC 13211 standardizes the core language. There is no single reference implementation: SWI-Prolog is a widely used open-source system with many libraries and a development environment; GNU Prolog compiles to native code and includes a constraint solver; SICStus Prolog is a long-standing commercial implementation. Dialects differ in built-in predicates and libraries beyond the ISO core.

## Paradigm and type system

Prolog is declarative: a programmer states relationships rather than steps. The data model is the term: atoms, numbers, variables (capitalized), and compound terms. There is no static type system; unification matches terms structurally and binds variables. Control comes from clause order and backtracking, with the cut (`!`) pruning the search.

```prolog
% A relation, not a function: parent/2 facts and an ancestor/2 rule
parent(tom, bob).
parent(bob, ann).

ancestor(X, Y) :- parent(X, Y).
ancestor(X, Y) :- parent(X, Z), ancestor(Z, Y).
```

Because predicates are relations, many can run in more than one direction: the same `append/3` both concatenates lists and splits a list into parts.

## Toolchain and ecosystem

- Interpreter and compiler: SWI-Prolog provides an interactive top level, a compiler, and a library collection; GNU Prolog compiles to standalone native executables.
- Package manager: SWI-Prolog distributes add-on packs through [its pack system](https://www.swi-prolog.org/pack/list).
- Tooling: SWI-Prolog ships a graphical debugger, a built-in HTTP server library, and editor integrations.

```bash
# SWI-Prolog, load a file and query
swipl family.pl
?- ancestor(tom, ann).
```

## Syntax tour

```prolog
% Facts
color(sky, blue).
color(grass, green).

% A rule with a list and recursion
list_length([], 0).
list_length([_ | Tail], N) :-
    list_length(Tail, N0),
    N is N0 + 1.

% Arithmetic is explicit with is/2; = is unification, not assignment
double(X, Y) :- Y is X * 2.

% Query at the top level:
% ?- list_length([a, b, c], N).
% N = 3.
```

## Idioms and different approaches

- Write predicates as relations that work in multiple modes where it makes sense, rather than one-directional functions.
- Use pattern matching in clause heads to dispatch on the shape of terms instead of conditionals in the body.
- Use the cut (`!`) deliberately to commit to a choice and prune backtracking, but sparingly, since overuse hides logic.
- Prefer library predicates such as `findall/3`, `bagof/3`, and `maplist/3` over hand-written recursion where they fit.
- Separate pure logical relations from side-effecting predicates (I/O, assertion) to keep reasoning clear.

## Design principles

Prolog embodies the idea that a program can be a logical specification that a general proof procedure executes. The programmer declares what is true and what follows from what, and the system searches for answers. In practice, procedural concerns (clause order, the cut, and side effects) intrude on the pure declarative ideal, so effective Prolog balances logical clarity against control of the search.

## Standard library and notable packages

The ISO standard defines core built-in predicates for unification, arithmetic (`is/2`), control, term inspection, and I/O. Implementations add large libraries: SWI-Prolog includes lists and association lists, constraint solving over finite domains (`library(clpfd)`), an HTTP server and client, RDF and semantic-web support, and interfaces to C and other languages. Constraint Logic Programming (CLP) extends the search with domain-specific solvers.

## Testing and packaging

SWI-Prolog includes a unit-test framework, `library(plunit)`, that runs test blocks embedded in source files. Libraries are packaged and shared as packs installed through the implementation's pack manager.

```prolog
:- begin_tests(lengths).
test(three) :- list_length([a, b, c], 3).
:- end_tests(lengths).
```

## Performance and concurrency

Performance depends on the implementation and on how well the search is constrained: indexing on the first argument, careful clause ordering, and cuts reduce backtracking. Native-compiling systems such as GNU Prolog run faster than interpreted ones for suitable programs. Concurrency is implementation-specific: SWI-Prolog provides threads (`library(thread)`) with message queues, and shared data is coordinated through those primitives or through the dynamic database with explicit synchronization. The core logical model itself is sequential.

## Common pitfalls

- Confusing unification (`=`) with arithmetic evaluation (`is/2`); `X = 1 + 2` binds `X` to the term `1+2`, not `3`.
- Left recursion without a base case or bound, causing infinite search.
- Overusing the cut, which can make a predicate give wrong answers when called in an unintended mode.
- Relying on clause order and side effects in ways that break the declarative reading.
- Building goals from strings or terms and calling them, which is both error-prone and a security risk (see below).

## Secure coding

Prolog's main language-specific risk is executing goals assembled from untrusted input, plus the usual input-handling concerns:

- Goal injection: constructing a term from external text (for example with `term_to_atom/2` or `read_term/2`) and then running it with `call/1` lets an attacker execute arbitrary predicates, including file and process operations. Do not build goals from untrusted input; parse the input into a fixed data structure and dispatch explicitly. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Input validation: terms read from external sources are unchecked until validated; check structure and bounds before use, which maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Resource exhaustion: unbounded search or recursion driven by untrusted input can consume stack and heap; bound depth and input size, which maps to [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- Dangerous built-ins: predicates that run shell commands or open files should not take untrusted arguments, which relates to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).

Dedicated security tooling is scarce. SWI-Prolog offers `library(check)` and cross-referencing for static checks of undefined and singleton issues; security review of any `call/1` on constructed goals is the main control. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [SWI-Prolog documentation](https://www.swi-prolog.org/pldoc/doc_for?object=manual), the reference manual and library index.
- [Learn Prolog Now](https://www.let.rug.nl/bos/lpn//index.php), a free online textbook.
- [The Power of Prolog](https://www.metalevel.at/prolog), lessons on writing clear, declarative Prolog.

## Related pages

- [Smalltalk](/languages/smalltalk.md)
- [Logo](/languages/logo.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
