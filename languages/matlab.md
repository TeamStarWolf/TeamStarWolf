# MATLAB

MATLAB (matrix laboratory) is a dynamically typed, garbage-collected numerical computing language and environment developed by MathWorks, with origins in the late 1970s and a commercial release in 1984. Its basic data type is the matrix, and its syntax and libraries are built around linear algebra, array operations, and plotting. It is used for engineering, signal and image processing, control systems, numerical simulation, and prototyping of scientific algorithms.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, array-oriented, with object-oriented and functional features |
| Typing | Dynamic; every value is an array, double by default |
| First appeared | 1984 (commercial); late 1970s prototype |
| Memory model | Automatic: reference counting with copy-on-write arrays |
| Reference implementation | MATLAB (MathWorks, proprietary) |
| Typical uses | Engineering, signal and image processing, control systems, simulation |
| Governance | MathWorks, proprietary |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [GNU Octave](/languages/octave.md), [languages index](/languages/README.md).

## Overview and history

MATLAB began as a teaching tool written by Cleve Moler to give students access to the LINPACK and EISPACK matrix libraries without writing Fortran. Moler, Jack Little, and Steve Bangert rewrote it in C and founded MathWorks in 1984 to sell it commercially. The product has since grown an integrated development environment, a plotting system, a code generator, and a large set of paid add-on toolboxes for specific domains.

MATLAB is proprietary: the language, its interpreter, and its libraries are defined by MathWorks rather than by a public standard. Companion products include Simulink for model-based design and a code generator that emits C from a subset of the language.

## Paradigm and type system

MATLAB is dynamically typed, and every value is an array: a scalar is a 1-by-1 matrix, and the default numeric type is double-precision floating point. Other types include integers of fixed width, `char` arrays, `logical`, `cell` arrays for mixed contents, `struct` for named fields, and `string` objects introduced later. The language supports classes through `classdef`, with both value and handle (reference) semantics.

```matlab
function t = total(prices, tax)
    if nargin < 2, tax = 0; end
    t = sum(prices) * (1 + tax);
end
```

Operators are defined for whole arrays, so `A * B` is matrix multiplication and `A .* B` is elementwise, a distinction that runs through the language.

## Toolchain and ecosystem

- Environment: the MATLAB desktop bundles an editor, a workspace browser, a command window, and a debugger.
- Add-ons: domain toolboxes extend the base language; the Add-On Explorer and File Exchange distribute community code.
- Code analysis: the built-in Code Analyzer (historically `mlint`, now `checkcode`) reports errors, warnings, and style issues as you edit.
- Interfacing: MATLAB calls C, C++, Fortran, Java, and Python code, and MEX files wrap compiled routines.

```matlab
x = 1:4;
disp(sum(x.^2))   % 30
```

## Syntax tour

```matlab
% Variables and arrays; a trailing semicolon suppresses output
name = "world";
fprintf("hello, %s\n", name);

% Row and column vectors, ranges, and elementwise power
x = 1:4;                 % 1 2 3 4
squares = x.^2;          % 1 4 9 16

% Matrices and linear algebra
A = [1 2; 3 4];
b = A \ [1; 1];          % solve A*b = [1;1]

% Cell arrays hold mixed types; structs hold named fields
c = {1, "two", [3 4]};
s.name = "Ada";
s.born = 1815;

% Logical indexing selects elements
v = [5 2 8 1];
big = v(v > 3);          % 5 8

% Error handling
try
    n = str2double("x") + 1;
catch err
    n = 0;
end
```

## Idioms and different approaches

- Vectorize: express computations as whole-array operations rather than element-by-element loops, which is both clearer and faster in the interpreter.
- Preallocate arrays with `zeros` or `cell` before a loop that fills them; growing an array inside a loop reallocates on every step.
- Use logical indexing (`v(v > 3)`) instead of `find` plus indexing when you only need the selected values.
- Distinguish matrix operators (`*`, `/`, `^`) from their elementwise counterparts (`.*`, `./`, `.^`); mixing them up is a frequent source of wrong results.
- Keep functions in their own files or as local functions, and avoid scripts that depend on leftover workspace variables.

## Design principles

MATLAB optimizes for interactive numerical work by engineers and scientists: the matrix is the default object, array operations read like mathematical notation, and plotting is one command away. The environment favors exploration at the command window, immediate visualization, and a large catalog of ready-made numerical routines. Copy-on-write array semantics give values predictable behavior while avoiding needless copies, and the toolbox model lets MathWorks package domain expertise as libraries.

## Standard library and notable packages

The base product covers linear algebra, statistics, optimization basics, interpolation, fast Fourier transforms, and 2-D and 3-D graphics. Paid toolboxes extend it: the Signal Processing Toolbox, Image Processing Toolbox, Statistics and Machine Learning Toolbox, Control System Toolbox, and Deep Learning Toolbox, among many others. Community functions are distributed through File Exchange.

## Testing and packaging

The MATLAB unit testing framework (`matlab.unittest`) runs script-based, function-based, and class-based tests.

```matlab
function tests = addTest
    tests = functiontests(localfunctions);
end

function testAddition(testCase)
    verifyEqual(testCase, 2 + 3, 5)
end
```

Reusable code is packaged as a toolbox (`.mltbx`) with a project file, which bundles functions, documentation, and metadata for sharing or for the Add-On Explorer.

## Performance and concurrency

The MATLAB interpreter includes a just-in-time compiler that speeds scalar loops, but vectorized array operations that call the underlying BLAS/LAPACK libraries remain the fastest path for numerical work. Preallocation avoids repeated reallocation. Concurrency and acceleration are sold as add-ons: the Parallel Computing Toolbox provides `parfor` loops, `spmd` blocks, GPU arrays, and distribution across a cluster with MATLAB Parallel Server. Built-in functions are often already multithreaded internally.

## Common pitfalls

- Matrix versus elementwise operators: `A * B` and `A .* B` compute different things; using the wrong one is a common bug.
- One-based indexing: arrays start at index 1, which trips programmers coming from zero-based languages.
- Growing arrays in a loop reallocates memory each iteration; preallocate instead.
- Floating-point default: numeric literals are doubles, so integer-looking code still carries rounding; compare with a tolerance, not `==`.
- Function and variable name collisions: a variable can shadow a built-in function of the same name until it is cleared.

## Secure coding

MATLAB code in automation often ingests external data files and sometimes shells out, which creates the main risks:

- Code injection: `eval`, `evalin`, `feval`, and `str2func` on untrusted strings run arbitrary MATLAB; avoid constructing code from input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Operating-system command injection: the `system`, `dos`, and `unix` functions and the `!` shell escape run external programs; never build the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Untrusted data files: loading a `.mat` file restores arbitrary variables, and a MAT file can define objects whose constructors run on load; only load MAT files from trusted sources, which relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html). Validate the shape and range of imported data before use.
- SQL injection: when using the Database Toolbox, use parameterized queries rather than concatenating values into SQL, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Dependency provenance: review File Exchange and third-party code before running it, and pin toolbox versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the built-in Code Analyzer (`checkcode`) performs static analysis and flags error-prone constructs, including some unsafe uses of `eval`.

## Learning resources

- MATLAB Documentation, the official reference and user guides.
- [MATLAB Onramp](https://matlabacademy.mathworks.com/details/matlab-onramp/gettingstarted), a free introductory course from MathWorks.
- MATLAB Central, the community forum, answers, and File Exchange.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [GNU Octave](/languages/octave.md)
- [Julia](/languages/julia.md)
- [Fortran](/languages/fortran.md)
- [All languages](/languages/README.md)
