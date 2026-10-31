# R

R is a dynamically typed, garbage-collected language and environment for statistical computing and graphics, created by Ross Ihaka and Robert Gentleman at the University of Auckland and first released publicly in 1993. It is an open-source implementation of the S language, built around vectors as the primary data structure, and it ships an interactive interpreter with a plotting system. It is used for statistics, data analysis, bioinformatics, econometrics, reproducible research, and the exploratory stages of security data analysis.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: functional, imperative, object-oriented |
| Typing | Dynamic, with vectors and attributes rather than scalars |
| First appeared | 1993 |
| Memory model | Automatic: tracing garbage collector, copy-on-modify semantics |
| Reference implementation | [R (GNU project)](https://www.r-project.org/) |
| Typical uses | Statistics, data analysis, bioinformatics, visualization, research |
| Governance | [R Core Team](https://www.r-project.org/contributors.html) under the R Foundation |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Julia](/languages/julia.md), [languages index](/languages/README.md).

## Overview and history

R grew out of the S language designed by John Chambers and colleagues at Bell Labs in the 1970s and 1980s. Ihaka and Gentleman wrote a new interpreter with S-like syntax but a different internal design borrowed in part from Scheme, and released it under the GNU General Public License. The R Development Core Team formed in 1997, and [CRAN](https://cran.r-project.org/), the central archive network for R packages, became the main home for distributed code.

The language is defined by the [R Language Definition](https://cran.r-project.org/doc/manuals/r-release/R-lang.html) and evolved through regular releases from the R Foundation. Its design priority is interactive data analysis, so many operations that would be loops in other languages are expressed as whole-vector or whole-table transformations.

## Paradigm and type system

R is dynamically typed, and its basic values are vectors rather than scalars: a single number is a length-one numeric vector. Core types include logical, integer, double, character, list, and function. Objects carry attributes such as `names`, `dim`, and `class`, and the `class` attribute drives method dispatch. R offers several object systems: S3 (dispatch on the class attribute), S4 (formal classes with validity checks), and R5/reference classes, plus the newer [R6](https://r6.r-lib.org/) package for mutable objects.

```r
total <- function(prices, tax = 0) {
  sum(prices) * (1 + tax)
}
total(c(10, 20, 30), tax = 0.1)
```

Functions are first-class values, arguments are evaluated lazily (promises), and assignment copies on modify, so a function cannot silently mutate its caller's data.

## Toolchain and ecosystem

- Interpreter: `R` runs scripts and an interactive prompt; `Rscript` runs a file non-interactively.
- Packaging: packages publish to [CRAN](https://cran.r-project.org/) and to [Bioconductor](https://www.bioconductor.org/) for genomics; `install.packages()` installs them.
- Environments and dependencies: [renv](https://rstudio.github.io/renv/) records per-project package versions in a lockfile.
- Integrated development: [RStudio](https://posit.co/products/open-source/rstudio/) is the common editor; [Quarto](https://quarto.org/) and R Markdown produce reproducible documents.
- Linting and style: [lintr](https://lintr.r-lib.org/) checks style and common errors; [styler](https://styler.r-lib.org/) reformats code.

```bash
Rscript -e 'cat(mean(c(2, 4, 6)))'
```

## Syntax tour

```r
# Vectors are the basic unit; operations are vectorized
x <- c(1, 2, 3, 4)
squares <- x^2          # 1 4 9 16

# Named lists hold mixed types
person <- list(name = "Ada", born = 1815L)
person$name

# Data frames are column-oriented tables
df <- data.frame(id = 1:3, value = c(9.5, 3.2, 7.1))
df[df$value > 5, ]

# Functions and the pipe operator
scale01 <- function(v) (v - min(v)) / (max(v) - min(v))
c(10, 20, 30) |> scale01()

# Apply functions over structures instead of looping
sapply(1:3, function(n) n * n)   # 1 4 9

# Condition handling
result <- tryCatch(
  log(-1),
  warning = function(w) NA
)
```

## Idioms and different approaches

- Prefer vectorized operations and the `apply` family over explicit `for` loops; the vectorized form is clearer and usually faster.
- Two large ecosystems coexist: base R and the [tidyverse](https://www.tidyverse.org/), whose packages such as `dplyr` and `ggplot2` share a grammar built on the pipe. Teams usually pick one style and stay consistent.
- Use `vapply` rather than `sapply` when you want a checked return type, because `sapply` can silently return a different structure for edge cases.
- Represent missing data with `NA` and test for it with `is.na`; a comparison against `NA` yields `NA`, not `FALSE`.
- Keep side effects (reading files, plotting) separate from pure transformation functions so analysis steps stay reproducible.

## Design principles

R was built so that interactive statistical work reads naturally: whole datasets are first-class, missing values are part of the type system, and extending the language with domain methods through S3 or S4 is routine. Copy-on-modify semantics trade some memory traffic for predictable value behavior, which keeps analyses free of aliasing bugs. The language favors many small composable functions over large statements, and its formula notation (`y ~ x`) gives statistical models a compact, readable interface.

## Standard library and notable packages

Base R ships `stats` (distributions, models, tests), `utils`, `graphics` and `grDevices` for plotting, and `methods` for S4. Widely used packages include [ggplot2](https://ggplot2.tidyverse.org/) for visualization, [dplyr](https://dplyr.tidyverse.org/) and [tidyr](https://tidyr.tidyverse.org/) for data manipulation, [data.table](https://rdatatable.gitlab.io/data.table/) for fast in-memory tables, [shiny](https://shiny.posit.co/) for interactive web applications, and [Rcpp](https://www.rcpp.org/) for binding C++ code.

## Testing and packaging

[testthat](https://testthat.r-lib.org/) is the common testing framework, and [devtools](https://devtools.r-lib.org/) automates package development tasks.

```r
library(testthat)

add <- function(a, b) a + b

test_that("addition works", {
  expect_equal(add(2, 3), 5)
})
```

A distributable package carries a `DESCRIPTION` file with its metadata, a `NAMESPACE` listing exported functions, and code under `R/`; `R CMD check` validates it before submission to CRAN.

## Performance and concurrency

The R interpreter is single-threaded for ordinary code, and interpreted loops over scalars are slow, so hot paths move into vectorized primitives (written in C) or compiled extensions through Rcpp. For parallelism, the base `parallel` package forks or spawns worker processes, and the [future](https://future.futureverse.org/) framework provides a uniform interface over multicore, multisession, and cluster backends. Many numerical routines call an optimized BLAS/LAPACK, so linking a tuned BLAS speeds matrix work without code changes.

## Common pitfalls

- Default argument `stringsAsFactors` changed across versions; be explicit when reading data so strings are not silently converted to factors.
- `sapply` can return a vector, matrix, or list depending on input, which breaks downstream code; prefer `vapply` or the `purrr` map functions with a declared type.
- Integer versus double: a literal like `1` is a double; write `1L` for an integer when the distinction matters.
- Recycling: binary operations on vectors of unequal length recycle the shorter one, which can hide a length bug.
- Floating-point equality: use `all.equal` with a tolerance rather than `==` on computed doubles.

## Secure coding

R scripts routinely read external data files and sometimes shell out, which creates the main risks:

- Code injection: `eval(parse(text = ...))` on untrusted input runs arbitrary R code; avoid building code from strings, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Operating-system command injection: `system`, `system2`, and `shell` run external programs; never assemble the command line from untrusted input, and pass arguments as a vector rather than one string. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Insecure deserialization: `readRDS`, `load`, and `unserialize` can execute code through object attributes and reference objects; only load `.RData` and `.rds` files from trusted sources, which maps to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: when a script queries a database through `DBI`, use parameterized queries with `dbBind` rather than pasting values into SQL, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Dependency supply chain: pin package versions with renv and install from trusted mirrors; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [lintr](https://lintr.r-lib.org/) flags undesirable constructs during static analysis, including uses of `eval(parse(...))`.

## Learning resources

- [An Introduction to R](https://cran.r-project.org/doc/manuals/r-release/R-intro.html) and the [R Language Definition](https://cran.r-project.org/doc/manuals/r-release/R-lang.html), the primary manuals.
- [R for Data Science](https://r4ds.hadley.nz/), a free book covering the tidyverse workflow.
- [CRAN Task Views](https://cran.r-project.org/web/views/), curated package lists by subject.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Julia](/languages/julia.md)
- [GNU Octave](/languages/octave.md)
- [All languages](/languages/README.md)
