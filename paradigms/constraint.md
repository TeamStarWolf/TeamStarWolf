# Constraint Programming

Constraint programming states a problem as variables, their domains, and relations that must hold among them, then hands the whole thing to a solver that searches for assignments satisfying every relation. It is declarative: you model the rules, not the algorithm that satisfies them. The paradigm suits scheduling, planning, configuration, and other combinatorial problems.

## Core idea

A constraint satisfaction problem (CSP) has three parts. Variables name the unknowns. Each variable has a domain, the finite or interval set of values it may take. Constraints are relations that restrict which combinations of values are allowed, such as `all different` or `x + y =< 10`.

A solution is an assignment of one domain value to each variable that violates no constraint. Some problems add an objective to minimize or maximize, turning satisfaction into optimization. The programmer's job is modeling: choosing variables, domains, and constraints that capture the problem faithfully and prune well.

The key separation is between stating constraints and solving them. You never write the search. The solver combines two engines, propagation and search, to explore the space efficiently. This frees the model from control detail and lets one declarative statement drive different solving strategies.

## How it works

Propagation removes values that cannot appear in any solution. Each constraint acts as a filter: given the current domains, it narrows the domains of the variables it mentions. A change to one domain can wake other constraints that share a variable, so filtering cascades until the domains reach a fixpoint. This process is called constraint propagation, and achieving arc consistency is its common standard.

Propagation alone rarely fixes every variable, so the solver interleaves it with search. It picks a variable, splits its domain (often by trying one value), and propagates the consequences. If a domain empties, the current branch has no solution, so the solver backtracks and tries another choice. Good variable-ordering and value-ordering heuristics, such as choosing the most constrained variable first, cut the search tree sharply.

```minizinc
% MiniZinc: place N queens so none attack another
int: n = 8;
array[1..n] of var 1..n: q;   % q[i] = row of the queen in column i

constraint alldifferent(q);
constraint alldifferent([q[i] + i | i in 1..n]);
constraint alldifferent([q[i] - i | i in 1..n]);

solve satisfy;
```

Constraint logic programming (CLP) grafts this machinery onto logic programming. A CLP system replaces syntactic unification with constraint solving over a domain, such as `CLP(FD)` for finite domains or `CLP(R)` for reals. Goals accumulate constraints in a store, and the solver checks the store for satisfiability as execution proceeds. Prolog systems ship these libraries, so a logic program can post arithmetic and combinatorial constraints directly.

Different domains need different solvers. Finite-domain solvers handle integers and the combinatorial `alldifferent` style constraints. Linear and mixed-integer programming handles continuous optimization under linear relations. Boolean satisfiability (SAT) solvers decide propositional formulas, and SMT solvers such as Z3 extend SAT with theories for arithmetic, arrays, and bit-vectors. Modeling tools such as MiniZinc let you write one model and dispatch it to several back-end solvers.

## Strengths and trade-offs

The payoff is expressiveness with strong pruning. Global constraints such as `alldifferent` encode a whole pattern and bring specialized filtering that a hand-written loop would miss. Models stay close to the problem statement, so they are easier to change than bespoke search code. For many scheduling and configuration problems, a short model solves instances that would take serious effort to attack imperatively.

The costs follow from the underlying hardness. These problems are NP-hard in general, so a poor model or weak heuristics can blow up the search. Performance is sensitive to formulation: the choice of variables, the strength of each constraint's propagation, and search order can change runtime by orders of magnitude. Solvers can also feel like black boxes, which makes diagnosing a slow or unsatisfiable model a skill of its own.

## Languages and tools

Dedicated modeling languages include MiniZinc and the solver-independent constraint libraries built on Prolog's `CLP(FD)`. See [Prolog](/languages/prolog.md) for CLP support and [Datalog](/languages/datalog.md) for related rule-based evaluation. General solvers include Gecode and OR-Tools for finite domains, and the SMT solver Z3 for theory-backed problems. Many mainstream languages call these engines through bindings rather than embedding a solver natively.

## Secure-coding considerations

Treat a solver as code that runs on your inputs. Building a model or constraint string from untrusted data risks injection into the modeling language; see [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and CWE-94, Improper Control of Generation of Code. Construct models from parameterized data, not from concatenated user strings, and validate domains before posting them.

Solving is the larger operational risk. An attacker who controls variable count, domain sizes, or constraint structure can force worst-case search and exhaust CPU or memory (CWE-400, Uncontrolled Resource Consumption). Bound problem size, set solver timeouts and memory limits, and reject models that exceed them before the search starts. When a solver result feeds an authorization or safety decision, confirm the model encodes the full policy, since a missing constraint silently widens the set of accepted solutions.

## Resources

- Krzysztof Apt, *Principles of Constraint Programming*, 2003, Cambridge University Press
- Francesca Rossi, Peter van Beek, and Toby Walsh (eds.), *Handbook of Constraint Programming*, 2006, Elsevier
- Kim Marriott and Peter J. Stuckey, *Programming with Constraints: An Introduction*, 1998, MIT Press

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Logic programming](/paradigms/logic.md)
- [Declarative programming](/paradigms/declarative.md)
- [Symbolic programming](/paradigms/symbolic.md)
- [Dataflow programming](/paradigms/dataflow.md)
