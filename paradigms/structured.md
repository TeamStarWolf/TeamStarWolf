# Structured Programming

Structured programming builds programs from three control structures, sequence, selection, and iteration, and avoids unrestricted `goto`. It is a discipline within imperative programming, a set of rules about control flow rather than a separate model of computation. It matters because it made imperative code readable and analyzable, and its conventions are now so standard that most programmers follow them without naming them.

## Core idea

The defining idea is that any computation can be expressed by composing three patterns: run statements in order (sequence), choose between alternatives (selection, such as `if` and `switch`), and repeat a block (iteration, such as `while` and `for`). The Bohm-Jacopini result showed that these three suffice to express any computable control flow, so unrestricted jumps are never strictly necessary.

The motivation was Edsger Dijkstra's observation that arbitrary `goto` makes a program hard to understand, because the set of ways control can reach a given statement grows without bound. Each control structure, by contrast, has one entry and one exit. This lets a reader treat a whole block as a single unit with a clear before-state and after-state, and lets a tool reason about it the same way.

Single-entry, single-exit is the structural rule that makes this work. When every construct is entered only at the top and left only at the bottom, blocks nest cleanly and you can reason about them compositionally. This distinguishes structured code from spaghetti code, where jumps cross block boundaries and no local reasoning is possible.

## How it works

The constructs nest. A loop body contains conditionals, which contain sequences, which may contain more loops. Because each piece has one entry and one exit, the control-flow graph is reducible: it can be collapsed, one nested region at a time, to a single node. Reducible graphs are what compilers and analyzers depend on for optimization and for proving properties about code.

Structured programming pairs with stepwise refinement, Niklaus Wirth's method for writing programs. You start with a high-level statement of the task, then replace each abstract step with more detailed structured code, refining until every step is a concrete statement. The structure of the finished program mirrors the structure of the problem decomposition.

Here is binary search written in structured style. It uses sequence, one selection with three arms, and one loop, with no jumps out of the middle.

```c
#include <stddef.h>

/* returns index of key, or -1 if absent */
long bsearch_int(const int *a, size_t n, int key) {
    size_t lo = 0, hi = n;          /* sequence */
    while (lo < hi) {               /* iteration */
        size_t mid = lo + (hi - lo) / 2;
        if (a[mid] == key) {        /* selection */
            return (long)mid;
        } else if (a[mid] < key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return -1;
}
```

The loop has one condition that governs entry and exit, and each branch assigns and falls through to the loop test. A reader can state a loop invariant (the key, if present, lies in `a[lo..hi)`) and check that every path preserves it. That kind of local reasoning is exactly what structure buys.

Modern languages soften the strict single-exit rule in practice. Early `return`, `break`, `continue`, and exceptions are controlled, structured jumps: each targets a well-defined point (the end of the enclosing routine, loop, or handler) rather than an arbitrary label, so they keep most of the reasoning benefit. The behavior Dijkstra warned against is the unrestricted `goto` that lands anywhere, which almost no current language encourages. Guard clauses that `return` early are widely accepted today because they reduce nesting while keeping each exit explicit.

## Strengths and trade-offs

Structured code is readable, testable, and analyzable. Reducible control flow lets compilers optimize and lets static analyzers compute reaching definitions, live variables, and loop invariants. Reviewers can follow a single path of control instead of chasing labels. For almost all application and systems code, this discipline is simply the default and the right choice.

The trade-offs are narrow. A few patterns are more awkward under strict single-exit: breaking out of deeply nested loops, centralizing cleanup on error paths in C, and some state machines. Disciplined use of `break`, a single early `return`, or a `goto cleanup` idiom in C (a controlled forward jump to one cleanup block) handles these without abandoning structure. Forcing strict single-exit everywhere can add flag variables and nesting that hurt readability more than they help, so the goal is clear control flow, not dogma.

## Languages and tools

Representative languages that embody structured control flow include [C](/languages/c.md), [Pascal](/languages/pascal.md), and [Ada](/languages/ada.md). Pascal was designed by Wirth as a teaching vehicle for structured programming and stepwise refinement. Ada enforces strong structure for high-integrity and safety-critical systems. C provides the structured constructs and also retains `goto`, which disciplined code confines to local cleanup. Essentially every mainstream language since has adopted block-structured control flow as the norm.

Tools that rely on structure include optimizing compilers, control-flow and data-flow analyzers, cyclomatic-complexity metrics that count independent paths, and coverage tools that check each branch and loop has been exercised.

## Secure-coding considerations

Control-flow discipline is itself a security control, because unanalyzable flow hides bugs. Tangled branching leads to unreachable code and to missing paths, including the classic missing `default` in a `switch` or an unhandled `else`, which maps to CWE-478 (missing default case in a switch). Make every selection total: handle the else and the default, even if only to fail safe.

Error-path and cleanup handling is where structure matters most for safety. In languages with manual resource management, an unstructured jump that skips a `free`, an `unlock`, or a `close` causes leaks and use-after-free; a single structured cleanup path prevents it. Loops with unclear exit conditions cause off-by-one and out-of-bounds access (CWE-125 and CWE-787); stating and preserving a loop invariant is the structured defense. Keep cyclomatic complexity low so that every path, including every error path, can be read and tested. See `/SECURE_CODING_REFERENCE.md` for the input-validation and resource-handling rules that these structured control patterns enforce in practice.

## Resources

- Edsger W. Dijkstra, *Go To Statement Considered Harmful*, 1968, CACM
- Ole-Johan Dahl, Edsger W. Dijkstra, and C. A. R. Hoare, *Structured Programming*, 1972, Academic Press
- Niklaus Wirth, *Program Development by Stepwise Refinement*, 1971, CACM
- Edsger W. Dijkstra, *A Discipline of Programming*, 1976, Prentice Hall

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Imperative programming](/paradigms/imperative.md)
- [Procedural programming](/paradigms/procedural.md)
- [Object-oriented programming](/paradigms/object-oriented.md)
- [Functional programming](/paradigms/functional.md)
