# GNU Octave

GNU Octave is a dynamically typed, garbage-collected language and environment for numerical computing, first released by John W. Eaton in 1993. It is free software under the GNU General Public License, and its language is largely compatible with MATLAB, so many scripts written for one run on the other. It is used for numerical linear algebra, teaching, signal processing, and batch numerical work where an open-source interpreter is preferred.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, array-oriented, with object-oriented features |
| Typing | Dynamic; every value is an array, double by default |
| First appeared | 1993 |
| Memory model | Automatic: reference counting with copy-on-write arrays |
| Reference implementation | [GNU Octave](https://octave.org/) |
| Typical uses | Numerical linear algebra, teaching, signal processing, batch computation |
| Governance | [GNU Project](https://www.gnu.org/software/octave/) maintainers |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [MATLAB](/languages/matlab.md), [languages index](/languages/README.md).

## Overview and history

Octave began as companion software for a chemical-reactor-design textbook, so that students could do numerical work without writing Fortran. Eaton grew it into a general numerical environment, and it became part of the GNU Project. Its language deliberately tracks MATLAB syntax and semantics so code can move between them, while adding some conveniences of its own such as C-style increment operators and block comments.

The reference implementation is an interpreter written in C++ that links the standard BLAS, LAPACK, and FFTW numerical libraries. A graphical interface shipped with version 4.0. Octave is maintained by a volunteer team under the GNU umbrella and released under the GPL.

## Paradigm and type system

Octave is dynamically typed, and, as in MATLAB, every value is an array with double-precision floating point as the default. Types include numeric arrays, `char` arrays and `string`, `logical`, `cell` arrays for mixed contents, and `struct` for named fields. Octave supports `classdef` object definitions for compatibility with MATLAB, alongside its older `@class` directory mechanism.

```octave
function t = total(prices, tax = 0)
    t = sum(prices) * (1 + tax);
endfunction
```

Octave accepts both MATLAB block terminators (`end`) and its own named ones (`endfunction`, `endif`, `endwhile`), and it allows default argument values in the signature.

## Toolchain and ecosystem

- Interpreter: `octave` runs an interactive prompt; `octave script.m` or `octave --eval` runs code non-interactively.
- Packages: the [Octave Forge](https://octave.sourceforge.io/) and the [Octave Packages](https://gnu-octave.github.io/packages/) index distribute add-on packages, installed with the `pkg install` command.
- Interface: a Qt-based graphical environment ships with Octave, with an editor and a variable browser.
- Interfacing: Octave calls C++ through `.oct` files and C through MEX-compatible files, easing reuse of MATLAB extensions.

```bash
octave --eval 'disp(sum((1:4).^2))'   # 30
```

## Syntax tour

```octave
% Variables and arrays
name = "world";
printf("hello, %s\n", name);

% Ranges and elementwise power
x = 1:4;                  % 1 2 3 4
squares = x.^2;           % 1 4 9 16

% Matrices and linear algebra
A = [1 2; 3 4];
b = A \ [1; 1];           % solve A*b = [1;1]

% Cell arrays and structs
c = {1, "two", [3 4]};
s.name = "Ada";

% Logical indexing
v = [5 2 8 1];
big = v(v > 3);           % 5 8

% C-style operators Octave adds beyond MATLAB
count = 0;
count += 1;

% Error handling
try
    n = str2double("x") + 1;
catch
    n = 0;
end_try_catch
```

## Idioms and different approaches

- Vectorize array operations rather than looping element by element, and preallocate arrays before filling them in a loop.
- For code meant to run on MATLAB too, stick to the shared subset: use `end` as the block terminator and avoid Octave-only operators such as `+=` and `++`.
- Use logical indexing to select elements instead of computing index positions by hand.
- Prefer the elementwise operators (`.*`, `./`, `.^`) when you mean per-element arithmetic and the plain operators for matrix algebra.
- Install numerical extensions through `pkg` and load them with `pkg load` at the top of a script.

## Design principles

Octave's guiding choice is compatibility: by matching MATLAB's language and library surface, it lets users run and share numerical code without a proprietary license. It links established numerical libraries rather than reimplementing them, so results match other tools that use the same BLAS and LAPACK. As GNU software it values free redistribution and source availability, and it adds quality-of-life syntax where doing so does not break MATLAB compatibility.

## Standard library and notable packages

The core provides linear algebra, statistics, polynomial and interpolation routines, fast Fourier transforms through FFTW, ordinary-differential-equation solvers, and 2-D and 3-D plotting. Add-on packages from the Octave Packages index cover domains such as signal processing, image processing, statistics, optimization, and control, mirroring many MATLAB toolboxes with open-source implementations.

## Testing and packaging

Octave supports tests embedded in source files as `%!test`, `%!assert`, and related blocks, run with the `test` command.

```octave
function y = add(a, b)
    y = a + b;
end
%!assert (add (2, 3), 5)
```

A distributable package is a tarball with a `DESCRIPTION` file, source under `inst/` and `src/`, and optional C++ code compiled at install time; `pkg install` builds and registers it.

## Performance and concurrency

Octave is an interpreter, so scalar loops are slower than vectorized array operations that dispatch to BLAS, LAPACK, and FFTW. Preallocation and vectorization are the main tuning steps, and hot routines can move into compiled `.oct` files. Octave does not provide MATLAB's `parfor` out of the box; the `parallel` package from Octave Forge offers process-based parallelism and cluster execution, and the linked numerical libraries may already use multiple threads internally.

## Common pitfalls

- MATLAB portability: Octave-only syntax such as `#` comments, `+=`, `++`, and `endfunction` will not run on MATLAB; keep to the shared subset when portability matters.
- Matrix versus elementwise operators: `*` is matrix multiplication and `.*` is elementwise, as in MATLAB.
- One-based indexing: arrays start at 1.
- Automatic broadcasting: operations on arrays of compatible but unequal shapes broadcast, which can mask a dimension mismatch.
- Floating-point default: numeric literals are doubles; compare computed values with a tolerance rather than `==`.

## Secure coding

Octave scripts frequently read external data and sometimes run external programs, which creates the main risks:

- Code injection: `eval`, `feval`, and `str2func` on untrusted strings run arbitrary Octave; avoid building code from input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Operating-system command injection: `system`, `unix`, `dos`, and the `!` shell escape run external programs; never assemble the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Untrusted data files: loading saved `.mat` or Octave data files restores arbitrary variables; only load files from trusted sources, which relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html). Validate the shape and range of imported data before computing on it.
- Dependency provenance: review third-party packages before installing, since `pkg install` compiles and runs code; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: Octave emits interpreter warnings for suspect constructs; external MATLAB and Octave linters such as MISS_HIT perform static analysis and style checks on `.m` files.

## Learning resources

- [GNU Octave Manual](https://docs.octave.org/latest/), the official reference.
- [Octave project site](https://octave.org/), with downloads and documentation.
- [Octave Packages](https://gnu-octave.github.io/packages/), the add-on package index.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [MATLAB](/languages/matlab.md)
- [R](/languages/r.md)
- [All languages](/languages/README.md)
