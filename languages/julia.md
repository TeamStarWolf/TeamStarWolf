# Julia

Julia is a dynamically typed, garbage-collected language for technical and numerical computing, first released in 2012 by Jeff Bezanson, Stefan Karpinski, Viral B. Shah, and Alan Edelman. It compiles to native code through LLVM just before execution, and its defining feature is multiple dispatch: functions select a method based on the run-time types of all their arguments. It is used for scientific computing, numerical modeling, machine learning, optimization, and data analysis.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: multiple dispatch, functional, imperative |
| Typing | Dynamic, with an expressive optional type-annotation system |
| First appeared | 2012 |
| Memory model | Automatic: tracing garbage collector |
| Reference implementation | [julia](https://github.com/JuliaLang/julia) |
| Typical uses | Scientific computing, numerical modeling, machine learning, optimization |
| Governance | [JuliaLang](https://julialang.org/) community with the Julia GitHub process |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [R](/languages/r.md), [languages index](/languages/README.md).

## Overview and history

Julia was announced in 2012 with a stated goal of combining the convenience of a dynamic language with the speed of a compiled one, so that numerical code would not need to be prototyped in one language and rewritten in another. Version 1.0 arrived in 2018 and stabilized the language and standard library, and releases since then follow semantic versioning with a commitment to source compatibility within the 1.x line.

The reference implementation compiles each method to native code the first time it is called with a given set of argument types, using type inference to generate specialized machine code. The design draws on Lisp (its metaprogramming and homoiconic expressions), on array languages for its numeric syntax, and on languages with parametric types for its type system.

## Paradigm and type system

Julia is dynamically typed, but its type system is central to how code specializes. Types form a hierarchy of abstract and concrete types; values have concrete types, and variables can carry optional type annotations. Multiple dispatch means `f(x, y)` chooses a method from the combined types of `x` and `y`, which replaces much of the role that classes and inheritance play elsewhere. Parametric types such as `Array{Float64,2}` let code be generic yet compile to specialized machine code.

```julia
total(prices::Vector{<:Real}, tax::Real = 0.0) = sum(prices) * (1 + tax)
total([10, 20, 30], 0.1)
```

Type annotations are optional for correctness but guide the compiler toward fast, type-stable code.

## Toolchain and ecosystem

- Interpreter and compiler: the `julia` executable runs scripts and an interactive read-eval-print loop that compiles methods on first use.
- Packaging: the built-in [Pkg](https://pkgdocs.julialang.org/) manager installs packages from the [General registry](https://github.com/JuliaRegistries/General) and records exact versions in `Project.toml` and `Manifest.toml`.
- Environments: each project has its own activated environment, so dependency sets do not collide.
- Editing: the [Julia extension for VS Code](https://www.julia-vscode.org/) provides the common development environment.
- Formatting: [JuliaFormatter](https://github.com/domluna/JuliaFormatter.jl) applies a consistent layout.

```bash
julia -e 'println(sum(x^2 for x in 1:4))'
```

## Syntax tour

```julia
# Variables and string interpolation
name = "world"
println("hello, $name")

# Arrays are first-class and column-major
squares = [n^2 for n in 1:4]          # [1, 4, 9, 16]

# Tuples, named tuples, and dictionaries
point = (x = 1, y = 2)
lookup = Dict("a" => 1, "b" => 2)

# Functions and multiple dispatch
area(r::Real) = pi * r^2
area(w::Real, h::Real) = w * h

# Structs define new concrete types
struct Point
    x::Float64
    y::Float64
end

# Broadcasting applies a function elementwise with a dot
doubled = 2 .* [1, 2, 3]              # [2, 4, 6]

# Exception handling
value = try
    parse(Int, "not a number")
catch
    0
end
```

## Idioms and different approaches

- Write type-stable functions: a function whose return type is predictable from its argument types compiles to fast code. The `@code_warntype` macro highlights instability.
- Use broadcasting (the dot syntax `f.(x)`) to apply scalar functions elementwise rather than writing explicit loops, though plain loops are also fast in Julia.
- Add methods to existing functions for your own types rather than wrapping them in classes; multiple dispatch composes across packages.
- Use `@views` to avoid copying array slices, and column-major iteration order for cache-friendly loops.
- Reach for the macro system (`@macro`) for genuine code generation, not for ordinary control flow.

## Design principles

The language's central bet is that multiple dispatch plus a rich type system lets generic code compile to specialized native code, so one implementation serves many argument types at full speed. This reduces the "two-language problem" where a prototype in a dynamic language is rewritten in C for performance. Homoiconic expressions and hygienic macros make metaprogramming part of the language rather than a preprocessor, and the package manager's per-project manifests make numerical results reproducible.

## Standard library and notable packages

The standard library bundles `LinearAlgebra`, `Random`, `Statistics`, `Dates`, `Test`, and `Distributed`. Widely used packages include [DataFrames.jl](https://dataframes.juliadata.org/) for tabular data, [Plots.jl](https://docs.juliaplots.org/) and [Makie.jl](https://docs.makie.org/) for visualization, [DifferentialEquations.jl](https://docs.sciml.ai/DiffEqDocs/stable/) for numerical solvers, [JuMP.jl](https://jump.dev/) for mathematical optimization, and [Flux.jl](https://fluxml.ai/) for machine learning.

## Testing and packaging

The standard-library `Test` module provides the test macros, run through `Pkg.test`.

```julia
using Test

add(a, b) = a + b

@testset "addition" begin
    @test add(2, 3) == 5
end
```

A package is a directory with a `Project.toml` declaring its name, UUID, and dependencies, and source under `src/`; registering it with the General registry makes it installable by name.

## Performance and concurrency

Because methods compile to native code specialized on argument types, carefully written Julia runs close to C speed. The first call to a method pays a compilation cost (the "time to first plot" effect), which recent releases reduce through native-code caching in package images. Concurrency models:

- Coroutines (`Task`, `@async`, `Channel`) provide cooperative asynchronous programming for I/O.
- Multithreading (`Threads.@threads` and the task scheduler) runs work in parallel across cores within one process.
- Distributed computing (`Distributed`, `@spawnat`) spreads work across processes and machines.

Type instability is the usual performance problem: profile with `@code_warntype` and the `Profile` standard library before optimizing.

## Common pitfalls

- Type instability: a variable whose type the compiler cannot infer forces boxed values and slow code; keep functions type-stable.
- Global variables are slow because their type can change; put hot code inside functions where locals have inferred types.
- Arrays are column-major, so iterating rows in the inner loop thrashes the cache; iterate down columns.
- `1:n` is a range object, not an allocated array; `collect` it only when you truly need the materialized vector.
- Integer overflow is silent for the machine integer types; use `BigInt` or check ranges when values can grow.

## Secure coding

Julia is common in research and data pipelines that read external files and sometimes call out to the shell:

- Code injection: `eval` and `Meta.parse` on untrusted strings run arbitrary Julia; do not build code from input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Operating-system command injection: Julia builds commands as backtick objects and runs them with `run`; pass interpolated values as separate words (`` `grep $pattern file` `` interpolates safely) rather than concatenating a shell string, which avoids [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Insecure deserialization: the `Serialization` standard library is not a secure format and can execute code on load; use it only for trusted data, which maps to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Untrusted data files: validate the shape and ranges of parsed data before computing on it, and prefer well-defined formats read by a vetted parser.
- Dependency supply chain: commit `Manifest.toml` to pin exact versions and install from the General registry; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [JET.jl](https://github.com/aviatesk/JET.jl) performs static analysis of Julia code, reporting type errors and other issues before run time.

## Learning resources

- [The Julia Documentation](https://docs.julialang.org/), the official manual and standard-library reference.
- [Performance Tips](https://docs.julialang.org/en/v1/manual/performance-tips/), the canonical guidance on writing fast Julia.
- JuliaAcademy, free courses from the community.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [R](/languages/r.md)
- [MATLAB](/languages/matlab.md)
- [All languages](/languages/README.md)
