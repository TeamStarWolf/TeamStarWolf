# Eiffel

Eiffel is a statically typed, compiled, object-oriented language created by Bertrand Meyer and first released in 1986. Its defining idea is Design by Contract: classes state preconditions, postconditions, and invariants that are part of the source and are checked at run time. Eiffel aims for correctness and clarity in object-oriented software, and it is used in business and mission-critical systems and in teaching object-oriented design.

| Attribute | Value |
|---|---|
| Paradigm | Object-oriented (pure, class-based), with Design by Contract |
| Typing | Static, strong |
| First appeared | 1986 |
| Memory model | Automatic: garbage-collected |
| Reference compiler | No single reference; [EiffelStudio](https://www.eiffel.org/) from Eiffel Software is the main implementation, Liberty Eiffel and Gobo are open-source |
| Typical uses | Business and mission-critical systems, teaching object-oriented design |
| Governance/standard | [ISO/IEC 25436:2006](https://www.iso.org/standard/42924.html) and [ECMA-367](https://ecma-international.org/publications-and-standards/standards/ecma-367/) |

Related: [Smalltalk](/languages/smalltalk.md), [Delphi (Object Pascal)](/languages/delphi.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Bertrand Meyer designed Eiffel to put object-oriented software construction on a firm, verifiable footing, and set out its principles in the book Object-Oriented Software Construction. Design by Contract, the central contribution, treats the relationship between a method and its callers as a contract: the caller must meet the precondition, and the method guarantees the postcondition, with class invariants holding between calls. These assertions are written in the code and can be checked while the program runs, turning specification into executable checks.

The language is standardized as ECMA-367 and the identical ISO/IEC 25436:2006. EiffelStudio, from Eiffel Software, is the primary implementation and development environment; Liberty Eiffel (a GNU project) and the Gobo libraries and tools are open-source. Eiffel also introduced ideas such as command-query separation and a specific model of multiple inheritance with feature renaming and selection.

## Paradigm and type system

Eiffel is purely object-oriented and statically, strongly typed. Programs are built from classes; a class defines features (attributes and routines). The type system supports multiple inheritance with explicit control over inherited features (renaming, redefinition, and selection), generics, and, in later versions, void safety that prevents null-reference errors at compile time. Contracts are written with `require` (preconditions), `ensure` (postconditions), and class `invariant`.

```eiffel
class ACCOUNT
feature
    balance: INTEGER

    deposit (amount: INTEGER)
        require
            positive: amount > 0
        do
            balance := balance + amount
        ensure
            increased: balance = old balance + amount
        end
invariant
    non_negative: balance >= 0
end
```

The `old` keyword in a postcondition refers to a value as it was on entry, so a contract can relate the result to the prior state.

## Toolchain and ecosystem

- Compiler and IDE: [EiffelStudio](https://www.eiffel.org/) compiles Eiffel (through C or directly) and provides an environment with contract checking, debugging, and diagram tools.
- Open-source implementations: Liberty Eiffel and the Gobo project provide compilers and libraries.
- Build and libraries: projects are described by system and configuration files (`.ecf`); libraries are distributed as source clusters rather than through a central registry.

```bash
# EiffelStudio command-line compiler
ec -config project.ecf -target app
```

## Syntax tour

```eiffel
class
    APPLICATION
create
    make
feature
    make
        local
            a: ACCOUNT
        do
            create a
            a.deposit (100)
            print ("balance: " + a.balance.out + "%N")
        end
end
```

## Idioms and different approaches

- Write contracts first: state each routine's `require` and `ensure` and the class `invariant`, so the specification travels with the code and is checked as it runs.
- Follow command-query separation: a feature either changes state (a command, returning nothing) or returns a value without side effects (a query), not both.
- Use multiple inheritance deliberately, with renaming and selection to resolve name clashes, rather than avoiding it.
- Enable void safety so the compiler rules out null-reference failures instead of leaving them to run time.
- Keep classes cohesive and let inheritance express genuine specialization, supported by the contracts.

## Design principles

Eiffel's guiding principle is correctness by construction through Design by Contract: a program's obligations are explicit, checkable, and inherited along with the classes that declare them. Command-query separation and uniform access (a client cannot tell whether a feature is stored or computed) support reasoning about objects. The language and its method are presented as one: the style of small, contracted features and clear inheritance is part of the design rather than a convention layered on top.

## Standard library and notable packages

EiffelBase provides the core data structures (lists, tables, sets, and iteration), and other bundled libraries cover concurrency (SCOOP), networking, databases, and graphical interfaces (EiffelVision). The Gobo project supplies additional open-source libraries, including parsing and XML tools. Libraries are distributed as source clusters referenced from a project's configuration file rather than through a package registry, consistent with Eiffel's whole-system compilation model.

## Testing and packaging

Design by Contract reduces some testing by turning specifications into run-time checks, but Eiffel also has test tooling: AutoTest, integrated with EiffelStudio, can generate and run tests against contracts, and unit tests can be written as ordinary classes. Projects are built as whole systems from configuration files; reusable code is packaged as libraries (clusters) referenced by other projects.

```eiffel
test_deposit
    local
        a: ACCOUNT
    do
        create a
        a.deposit (100)
        assert ("balance_100", a.balance = 100)
    end
```

## Performance and concurrency

Eiffel compiles to native code (historically through C), so compute-bound code performs comparably to other compiled object-oriented languages; contract checking adds run-time cost and is typically enabled during development and reduced in production builds. For concurrency, Eiffel offers SCOOP (Simple Concurrent Object-Oriented Programming), a model that extends Design by Contract to concurrent execution so that a separate object's preconditions become wait conditions, aiming to make concurrent code reason like sequential code. Garbage collection manages memory automatically.

## Common pitfalls

- Disabling contract checking everywhere for performance, which removes the correctness guarantees that are the point of the language.
- Writing weak contracts (trivial or missing preconditions and postconditions) so the assertions do not actually constrain behavior.
- Multiple-inheritance name clashes that need explicit renaming or selection; ignoring them causes compile errors or wrong feature resolution.
- Violating command-query separation, so queries have side effects that break reasoning about calls.
- Ignoring void-safety warnings in code written before void safety, leaving null-reference risks.

## Secure coding

Eiffel's contracts and void safety eliminate several defect classes by default, but assertions and type checks are not a substitute for validating untrusted input, and interfacing to other languages bypasses the checks:

- Input validation: contracts express the obligations between parts of the program, but data crossing into the program from files, networks, or users must still be validated explicitly before it is trusted; do not rely on a precondition to sanitize external input. This maps to [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Contract checking disabled in production: if assertions are turned off in release builds, precondition checks no longer run, so input that would have been rejected may flow through; keep boundary validation in ordinary code, not only in contracts.
- Integer overflow: fixed-size integer arithmetic can overflow; bound values driven by untrusted input, which maps to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- External interface risk: data crossing to and from C or other external code bypasses Eiffel's type and contract checks, so validate at that boundary, which can involve [CWE-78](https://cwe.mitre.org/data/definitions/78.html) when launching processes.

Dedicated security tooling is scarce. The contract system and EiffelStudio's AutoTest catch many logic errors, and research work on static verification of Eiffel contracts (AutoProof) exists; manual review of input handling and external interfaces remains the main control. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Eiffel documentation](https://www.eiffel.org/doc/), guides and the language reference.
- [ECMA-367 Eiffel standard](https://ecma-international.org/publications-and-standards/standards/ecma-367/), the formal language definition.
- Bertrand Meyer, "Object-Oriented Software Construction", the book presenting Eiffel and Design by Contract.

## Related pages

- [Smalltalk](/languages/smalltalk.md)
- [Delphi (Object Pascal)](/languages/delphi.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
