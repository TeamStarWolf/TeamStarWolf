# Procedural Programming

Procedural programming organizes imperative code into procedures (also called functions, routines, or subroutines) that call one another and operate on data passed as arguments or held in shared storage. It is a style within the imperative family, concerned with decomposition rather than with how state changes. It matters because the procedure call is the oldest and most durable unit of reuse and abstraction in software.

## Core idea

The defining concept is the procedure: a named block of statements with a parameter list and, usually, a return value. A procedure is a contract. Callers supply inputs, the procedure runs its steps, and control returns to the point just after the call. The caller does not need to know how the work is done, only what the procedure promises.

This is decomposition by action. A large task is split into smaller named steps, each a procedure, and those steps are composed by calling one from another. The organizing question is "what are the operations," which distinguishes procedural code from object-oriented code, where the organizing question is "what are the things and what can they do." Procedural design groups routines around tasks and lets data flow between them.

Procedures existed before objects and gave structured imperative programs their first real modularity. A well-factored procedural program reads as a tree of calls: a top-level routine coordinates mid-level routines, which call leaf routines that touch the data directly.

## How it works

The runtime mechanism is the call stack. Each call pushes a stack frame holding the procedure's parameters, local variables, and the return address. When the procedure returns, its frame is popped and control resumes at the return address. This discipline gives recursion for free, because each recursive call gets its own frame with its own locals.

Parameters are the main channel for data. Pass-by-value copies the argument into the frame, so the callee cannot change the caller's variable. Pass-by-reference (or passing a pointer) gives the callee a handle to the caller's storage, so writes are visible after the call returns. Return values carry results back out. Procedures can also read and write shared state (globals, or a struct threaded through calls), which couples them more tightly and should be used sparingly.

Here is a small procedural program in C. Each routine does one task, and `main` composes them by calling in sequence.

```c
#include <stdio.h>

static int is_even(int n) {        /* leaf procedure, pure */
    return n % 2 == 0;
}

static int count_even(const int *a, int n) {
    int c = 0;
    for (int i = 0; i < n; i++) {
        if (is_even(a[i])) c++;    /* compose by calling */
    }
    return c;
}

int main(void) {
    int data[] = {1, 2, 3, 4, 6};
    printf("%d\n", count_even(data, 5));   /* -> 3 */
    return 0;
}
```

The data (`data`) is passed into `count_even`, which passes each element to `is_even`. Nothing is hidden inside an object; the routines are grouped by what they do, and the array travels explicitly between them. This explicit flow is the signature of procedural design.

Modularity grows by grouping related procedures into translation units, modules, or libraries, and by exposing a narrow public interface while keeping helper routines private (`static` in C). Good procedural design keeps each routine short, gives it one clear job, limits its parameters, and minimizes its reliance on global state. Fortran, Cobol, Pascal, and PL/I all built large systems this way long before objects were common, which is why so much long-lived infrastructure is procedural.

## Strengths and trade-offs

Procedural code is the right tool when the problem is a pipeline of operations over plain data: parsers, compilers front-ends, numerical kernels, batch jobs, and most of the C standard library. The call tree is easy to read, easy to test one routine at a time, and cheap at runtime because a call is just a jump plus a frame.

It also keeps data and code separate, which is a benefit when many operations act on one simple data layout. You can add a new routine without touching the data definition.

The trade-offs appear as programs grow. When many procedures share mutable global state, changing that state's shape ripples through every routine that reads it, and reasoning about who writes what becomes hard. There is no built-in mechanism to bundle invariants with the data they protect, so an invalid combination of fields can be produced by any routine. Object-oriented and abstract-data-type styles address this by hiding data behind the operations allowed on it. Procedural code can approximate that with opaque structs and disciplined interfaces, but the language does not enforce it.

## Languages and tools

Representative procedural languages include [C](/languages/c.md), [Fortran](/languages/fortran.md), [Cobol](/languages/cobol.md), [Pascal](/languages/pascal.md), and [PL/I](/languages/pli.md). Fortran pioneered the subroutine and function for scientific computing. Cobol structured business batch processing into paragraphs and sections. Pascal, designed for teaching, made clean procedure and parameter rules central. PL/I combined scientific and business features in one procedural language. C refined the model to a small, portable core that still underlies operating systems and runtimes today.

Supporting tools include step debuggers that walk the call stack, profilers that attribute time to individual procedures, and static analyzers that trace data flow across calls to find unused results or uninitialized reads.

## Secure-coding considerations

The paradigm-specific risks center on the procedure boundary and on shared data. A procedure that trusts its parameters without validation is a classic injection and overflow point: passing an unchecked length or buffer into a routine is how many memory-corruption bugs begin (CWE-20, improper input validation). Validate inputs at the boundary of every routine that can be called with external data, not only at the program edge.

Return-value handling is a frequent failure. Ignoring an error code returned by a procedure (CWE-252, unchecked return value) lets the program continue on a false assumption, for example proceeding after a failed allocation or a failed authorization check. Check and handle every meaningful return.

Shared global state across procedures invites order-dependent bugs and makes concurrent use unsafe. Prefer passing state explicitly, keep routines free of hidden side effects where you can, and document which globals a routine touches. For buffer handling inside routines, follow the memory-safety rules in `/SECURE_CODING_REFERENCE.md`, which also covers input validation and error-handling discipline that map directly onto procedure boundaries.

## Resources

- Brian W. Kernighan and Dennis M. Ritchie, *The C Programming Language*, 1988, Prentice Hall
- Niklaus Wirth, *Algorithms + Data Structures = Programs*, 1976, Prentice Hall
- Brian W. Kernighan and Rob Pike, *The Practice of Programming*, 1999, Addison-Wesley
- David Gries, *The Science of Programming*, 1981, Springer

## Related pages

- [Programming paradigms](/paradigms/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Imperative programming](/paradigms/imperative.md)
- [Structured programming](/paradigms/structured.md)
- [Object-oriented programming](/paradigms/object-oriented.md)
- [Functional programming](/paradigms/functional.md)
