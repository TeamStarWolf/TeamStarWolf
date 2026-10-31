# Logic Programming

Logic programming expresses computation as a set of facts and rules in formal logic, then answers queries by automated deduction. It is declarative: you describe what relations hold, not the control flow that computes them. The runtime searches for proofs, so one program can run forwards, backwards, and in many directions.

## Core idea

A logic program is a knowledge base of clauses. A fact asserts that a relation holds. A rule asserts that a relation holds when some other relations hold. A query asks whether a goal can be proven from the knowledge base, and if so under which variable bindings.

The programmer supplies the logic; the system supplies the control. This split traces back to Robert Kowalski's reading of an algorithm as logic plus control. Because clauses are relations rather than functions, the same predicate can check a fact or generate solutions, depending on which arguments are bound.

The dominant form restricts clauses to Horn clauses: at most one positive literal per clause. Horn clauses keep proof search tractable and give a clean operational reading. Prolog is the canonical general-purpose logic language; Datalog is a decidable subset tuned for databases and static analysis.

## How it works

Three mechanisms drive execution: unification, resolution, and backtracking. Unification matches two terms by finding a substitution that makes them identical. Variables bind to terms, and the binding propagates through the rest of the proof. Unification is the only parameter-passing and pattern-matching mechanism in the language.

Resolution derives new goals from a goal and a matching clause. Prolog uses SLD resolution: Selective Linear resolution for Definite clauses. The engine picks the leftmost goal, finds a clause whose head unifies with it, and replaces the goal with that clause's body. It repeats until no goals remain, which means the original query is proven.

```prolog
% facts
parent(tom, bob).
parent(bob, ann).
parent(bob, pat).

% rules
grandparent(X, Z) :- parent(X, Y), parent(Y, Z).
ancestor(X, Y)    :- parent(X, Y).
ancestor(X, Y)    :- parent(X, Z), ancestor(Z, Y).

% query: ?- grandparent(tom, Who).
% Who = ann ; Who = pat.
```

When a goal fails, or when the user asks for another solution, the engine backtracks. It undoes the most recent binding, returns to the last choice point, and tries the next matching clause. This depth-first search with backtracking enumerates every proof the program allows. Clause order and goal order therefore affect performance and termination, even though they do not change the logical meaning.

Negation needs care. Pure Horn clauses have no negation, so most systems add negation as failure: a goal `\+ G` succeeds when `G` cannot be proven. This rests on the closed-world assumption, which treats anything not derivable as false. The assumption is sound only when the knowledge base is complete for the relation in question, so missing facts read as false statements.

Datalog keeps the declarative core but drops function symbols and restricts recursion. The result is guaranteed termination and set-at-a-time evaluation, often bottom-up rather than Prolog's top-down search. These properties make Datalog a fit for query engines, access-control rules, and program analysis, where predictable evaluation matters more than general computation.

## Strengths and trade-offs

The model shines when a problem is naturally relational: family trees, graph reachability, parsing, type inference, and rule-heavy business logic. One concise rule set can replace a large body of imperative traversal code. Reversible predicates let a single definition serve as both a checker and a generator.

The trade-offs are real. Depth-first search can loop forever on left-recursive rules or explore huge spaces without pruning. Control constructs such as the cut (`!`) prune the search but entangle logic with control and break the pure reading. Negation as failure and the closed-world assumption surprise programmers who expect classical logic. Debugging a failed proof means reasoning about the search tree, which is less direct than stepping through statements.

## Languages and tools

Prolog is the general-purpose standard, with mature systems such as SWI-Prolog and SICStus. See [Prolog](/languages/prolog.md). Datalog powers deductive databases and static-analysis frameworks; see [Datalog](/languages/datalog.md). Answer-set programming systems such as `clingo` extend the ideas to combinatorial search. Many general languages embed a logic engine through libraries, for example `core.logic` in Clojure.

## Secure-coding considerations

Logic programs that accept external terms can be attacked like any interpreter. Building a goal from untrusted input and calling it with `call/1` is injection: see [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and CWE-94, Improper Control of Generation of Code. Validate or whitelist predicate names, never let user data name the predicate to invoke, and keep queried data separate from program clauses.

The closed-world assumption is a frequent source of silent authorization bugs. A rule that grants access when `\+ denied(User)` treats an incomplete deny list as a grant, so a missing fact becomes a permission. Default to explicit allow rules, and treat unknown as deny in security contexts. Watch resource use too: unbounded search on hostile input is a denial-of-service vector (CWE-400, Uncontrolled Resource Consumption), so bound depth or impose timeouts.

## Resources

- Leon Sterling and Ehud Shapiro, *The Art of Prolog*, 1994, MIT Press
- William F. Clocksin and Christopher S. Mellish, *Programming in Prolog*, 2003, Springer
- Ivan Bratko, *Prolog Programming for Artificial Intelligence*, 2011, Addison-Wesley
- Robert Kowalski, *Logic for Problem Solving*, 1979, North-Holland
- John W. Lloyd, *Foundations of Logic Programming*, 1987, Springer

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Declarative programming](/paradigms/declarative.md)
- [Constraint programming](/paradigms/constraint.md)
- [Symbolic programming](/paradigms/symbolic.md)
- [Functional programming](/paradigms/functional.md)
