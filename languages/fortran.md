# Fortran

Fortran (formula translation) is a statically typed, compiled language created by a team at IBM led by John Backus and first released in 1957. It was the first widely used high-level language, and it remains in use for numerical and scientific computing because of its array handling and mature optimizing compilers. It is used for climate and weather modeling, computational fluid dynamics, physics and chemistry simulation, and other high-performance numerical workloads.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, array-oriented, with object-oriented features since 2003 |
| Typing | Static, strong, with explicit and implicit declaration modes |
| First appeared | 1957 |
| Memory model | Manual and automatic: static, stack, and allocatable arrays; no built-in garbage collector |
| Reference implementation | No single one; [GNU Fortran (gfortran)](https://gcc.gnu.org/fortran/) is a common free compiler |
| Typical uses | Climate modeling, computational fluid dynamics, physics simulation, HPC |
| Governance | [ISO/IEC JTC 1/SC 22/WG5](https://wg5-fortran.org/) standard committee |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [MATLAB](/languages/matlab.md), [languages index](/languages/README.md).

## Overview and history

Fortran was designed to let scientists and engineers write mathematical formulas directly rather than in assembly, and Backus's optimizing compiler proved that a high-level language could produce efficient machine code. The language has been standardized repeatedly: FORTRAN 66, FORTRAN 77, Fortran 90 (free-form source, array operations, modules, dynamic memory), Fortran 95, Fortran 2003 (object orientation, C interoperability), Fortran 2008 (coarrays), and Fortran 2018 and 2023.

There is no single reference implementation; the language is defined by the ISO/IEC 1539 standard and implemented by several compilers, including [GNU Fortran](https://gcc.gnu.org/fortran/), the Intel compilers (`ifx`), the [LLVM Flang](https://flang.llvm.org/) compiler, and vendor compilers for supercomputers. The decades of investment in these optimizing compilers are a large part of why numerical codebases stay in Fortran.

## Paradigm and type system

Fortran is statically and strongly typed. Intrinsic types are `integer`, `real`, `complex`, `logical`, and `character`, each with a `kind` parameter that selects precision. Arrays are a built-in type with whole-array operations, and modern Fortran adds derived types (records), allocatable and pointer arrays, and type-bound procedures for object orientation. The historical default of implicit typing (names starting with `i` through `n` are integers) is error-prone, so `implicit none` at the top of every unit forces explicit declaration.

```fortran
pure function total(prices, tax) result(t)
  real, intent(in) :: prices(:)
  real, intent(in) :: tax
  real :: t
  t = sum(prices) * (1.0 + tax)
end function total
```

Argument intents (`in`, `out`, `inout`) let the compiler check and optimize how data flows through procedures.

## Toolchain and ecosystem

- Compilers: [gfortran](https://gcc.gnu.org/fortran/) (GCC), Intel `ifx`, [LLVM Flang](https://flang.llvm.org/), and vendor HPC compilers.
- Build and packaging: the [Fortran Package Manager](https://fpm.fortran-lang.org/) (`fpm`) builds projects and resolves dependencies; large codes also use CMake and Make.
- Numerical libraries: BLAS, LAPACK, and FFTW are standard dependencies for dense linear algebra and transforms.
- Parallelism: MPI and OpenMP are the common libraries for distributed and shared-memory parallel runs.

```bash
gfortran -O2 -fimplicit-none program.f90 -o program
./program
```

## Syntax tour

```fortran
program tour
  implicit none
  integer :: i
  real :: x(4), squares(4)
  character(len=20) :: name

  name = "world"
  print *, "hello, ", trim(name)

  x = [1.0, 2.0, 3.0, 4.0]      ! array constructor
  squares = x**2                 ! whole-array operation

  ! Loops and conditionals
  do i = 1, size(x)
     if (x(i) > 2.0) print *, x(i)
  end do

  ! Allocatable arrays sized at run time
  block
    real, allocatable :: buf(:)
    allocate(buf(10))
    buf = 0.0
    deallocate(buf)
  end block
end program tour
```

## Idioms and different approaches

- Put `implicit none` at the top of every program, module, and procedure so every name must be declared.
- Use free-form source (`.f90` and later) and whole-array operations rather than fixed-form FORTRAN 77 and manual element loops.
- Group related procedures and data in `module` units and bring them in with `use`; modules give the compiler the interface information it needs to check calls.
- Declare argument `intent` so the compiler checks usage and can optimize.
- Use allocatable arrays rather than pointers where possible; allocatables are deallocated automatically and avoid aliasing surprises.

## Design principles

Fortran's purpose is numerical throughput: the array as a first-class type, aliasing rules that let compilers vectorize and reorder loops, and a standard stable enough that programs written decades ago still compile. Each revision has added modern features (modules, dynamic memory, object orientation, parallelism) while keeping older code valid, so the language accrues capability without discarding its base. The emphasis is on letting the compiler generate fast machine code from readable mathematical expressions.

## Standard library and notable packages

Fortran's intrinsic procedures cover array reductions (`sum`, `product`, `maxval`), mathematical functions, string handling, and, since Fortran 2008, a small set of intrinsic modules such as `iso_fortran_env` and `iso_c_binding`. Numerical work relies on external libraries rather than a large standard library: [LAPACK](https://www.netlib.org/lapack/) and BLAS for linear algebra, [FFTW](https://www.fftw.org/) for transforms, and [PETSc](https://petsc.org/) for large-scale solvers. The [stdlib](https://stdlib.fortran-lang.org/) community project adds general-purpose utilities.

## Testing and packaging

[pFUnit](https://github.com/Goddard-Fortran-Ecosystem/pFUnit) and [test-drive](https://github.com/fortran-lang/test-drive) are common unit-testing frameworks, and `fpm` runs a project's tests.

```fortran
program check
  implicit none
  if (add(2, 3) /= 5) error stop "addition failed"
contains
  integer function add(a, b)
    integer, intent(in) :: a, b
    add = a + b
  end function add
end program check
```

An `fpm` project declares its metadata in `fpm.toml` and keeps library source in `src/`, executables in `app/`, and tests in `test/`.

## Performance and concurrency

Fortran's aliasing rules (arguments are assumed not to overlap unless declared otherwise) let compilers vectorize and parallelize loops aggressively, which is why it holds its place in high-performance computing. Concurrency models:

- OpenMP directives parallelize loops and regions across threads in shared memory.
- MPI, a library rather than a language feature, distributes work across processes and nodes.
- Coarrays, part of the language since Fortran 2008, express a partitioned global address space in standard syntax (`a[image]`).
- `do concurrent` marks loops whose iterations are independent so the compiler may parallelize them.

## Common pitfalls

- Implicit typing: without `implicit none`, a misspelled name becomes a new undeclared variable, a classic source of silent bugs.
- Array bounds: out-of-bounds access is undefined behavior and is not checked unless you compile with a bounds-checking flag such as `-fcheck=bounds`.
- Uninitialized variables hold arbitrary values; initialize before use rather than relying on zeroing.
- Mixed precision: a literal like `1.0` is default real, so assigning it to a double-precision variable loses precision; use kind-qualified literals (`1.0_dp`).
- Fixed-form versus free-form source rules differ (column positions, continuation); keep a file in one form.

## Secure coding

Fortran is memory-unsafe in the C sense, so the main risks are memory errors and unchecked input in code that parses files or builds commands:

- Buffer overflow and out-of-bounds access: writing past an array or a fixed-length `character` variable corrupts memory, which maps to [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and reading past it to [CWE-125](https://cwe.mitre.org/data/definitions/125.html). Compile with bounds checking during development and validate sizes before indexing. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Operating-system command injection: the `execute_command_line` intrinsic and the common `system` extension run a shell command; never assemble the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Integer overflow: fixed-width integers wrap or trap depending on compiler settings; validate ranges before arithmetic that can overflow, which relates to [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Untrusted input parsing: list-directed and formatted reads of attacker-controlled files can misbehave on malformed input; check `iostat` and validate parsed values.
- Dependency provenance: pin external numerical libraries and build dependencies; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: compiler diagnostics (`-Wall -Wextra -fcheck=all` for gfortran) catch many issues, and [fortran-linter](https://github.com/cphyc/fortran-linter) performs static style and syntax checks.

## Learning resources

- [Fortran-lang documentation](https://fortran-lang.org/learn/), community learning materials and reference.
- [GNU Fortran manual](https://gcc.gnu.org/onlinedocs/gfortran/), the gfortran compiler reference.
- [WG5 standards page](https://wg5-fortran.org/), the committee home and standard drafts.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [MATLAB](/languages/matlab.md)
- [All languages](/languages/README.md)
