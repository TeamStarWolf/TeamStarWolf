# Nushell

Nushell (invoked as `nu`) is a command-line shell and scripting language first released in 2019 and written in Rust. It treats the output of commands as structured data, tables, records, and lists, rather than plain text, so pipelines filter and transform columns the way a query does. It is cross-platform, with a typed pipeline and its own command set, and it is used as an interactive shell and for data-oriented automation.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, data-flow pipeline scripting over structured values |
| Typing | Dynamic with gradual static checking; values carry types (int, string, list, record, table) |
| First appeared | 2019 |
| Memory model | Managed by the Rust runtime; values are immutable in the pipeline |
| Reference implementation | [Nushell](https://www.nushell.sh/) |
| Typical uses | Interactive shell, data wrangling, cross-platform automation |
| Governance | Nushell open-source project on GitHub |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [PowerShell](/languages/powershell.md), [Bash](/languages/bash.md), [languages index](/languages/README.md).

## Overview and history

Nushell started from an idea similar to PowerShell's, that a shell is more useful when pipelines carry structured data than when they carry text, but applied to a cross-platform, Rust-based implementation with a syntax of its own. Early releases moved quickly and broke compatibility often; the project has since stabilized its core commands and data model while still predating a 1.0 release, so scripts should note the version they target.

Nushell parses many common formats (JSON, YAML, TOML, CSV, and others) directly into its table model, so data from a file or an HTTP call arrives as rows and columns rather than text to be scraped. This makes it well suited to data wrangling tasks that are awkward in a text shell, at the cost of not being compatible with POSIX scripts.

## Paradigm and type system

Nushell pipelines pass typed values: integers, strings, booleans, dates, durations, file sizes, lists, records, and tables. Commands declare the types they accept and produce, and the parser performs gradual static checks before a pipeline runs, catching some errors early.

```nu
let count = 3                 # an int
let total = $count * 2        # 6
let fruits = [apple banana cherry]   # a list
ls | where size > 1kb | sort-by size   # a table, filtered and sorted
```

Values in the pipeline are immutable; a command produces a new value rather than mutating its input. Mutable variables exist with `mut` for local state, but pipeline data flows functionally.

## Toolchain and ecosystem

- Shell: `nu` runs an interactive session or a script file (`nu script.nu`).
- Configuration: `config.nu` and `env.nu` set up the environment and are managed through the `config` commands.
- Extensions: custom commands are defined in `.nu` files and loaded with `use` or `source`; plugins are separate binaries that register new commands over a defined protocol.
- Data formats: `from json`, `from csv`, `to yaml`, and similar commands convert between the table model and serialized formats.

```nu
nu --commands 'ls | length'    # run a one-off pipeline
use mymodule.nu                # load custom commands
```

## Syntax tour

```nu
# Variables are immutable by default; mut declares a mutable one
let name = "world"
print $"hello, ($name)"

# Pipelines operate on tables and records
ls
| where type == file
| sort-by modified
| first 3
| select name size

# Lists and iteration
let fruits = [apple banana cherry]
for fruit in $fruits {
    print $"fruit: ($fruit)"
}

# Conditionals are expressions
let label = if ($name == "world") { "matched" } else { "no match" }

# Custom commands with typed parameters
def greet [who: string] {
    $"hi ($who)"
}
greet "team"

# Parse structured data and query it
open data.json | get users | where active == true
```

## Idioms and different approaches

- Keep data in the table model and operate on it with `where`, `select`, `sort-by`, `group-by`, and `each`, rather than piping text through `grep` and `awk`.
- Use string interpolation `$"...($expr)..."` for building strings, and bare words for simple literals.
- Define reusable logic as custom commands with `def` and typed parameters so the parser can check calls.
- Convert external text output into structured data as early as possible with `from json`, `from csv`, or `detect columns`, then work with columns.
- Prefer immutable `let` bindings and pipeline transformations; reach for `mut` only when a loop genuinely needs accumulating state.

## Design principles

Nushell's organizing idea is that everything in a pipeline is structured data with a type, so commands compose like a series of typed transformations and the shell can check them before running. It favors explicit, discoverable commands over terse flags, and it parses the whole pipeline up front, which enables static checks and informative errors. The trade-off is deliberate incompatibility with POSIX: Nushell is not trying to run existing shell scripts, it is trying to be a better language for data.

## Standard library and notable commands

Nushell ships a large set of built-in commands grouped by purpose: filters (`where`, `select`, `sort-by`, `group-by`, `uniq`, `each`, `reduce`), data conversion (`from`/`to` for JSON, YAML, TOML, CSV, and more), file system (`ls`, `open`, `save`, `glob`), strings (`str` subcommands), and system (`ps`, `sys`, `http`). The `std` library, written in Nushell itself, adds helpers such as assertions and logging. Plugins distributed as separate binaries extend the command set for tasks such as querying databases or additional formats.

## Testing and packaging

Nushell code is distributed as `.nu` modules loaded with `use`; there is no compiled package artifact. The standard library provides assertions for testing.

```nu
use std assert

def add [a: int, b: int] { $a + $b }

assert equal (add 2 3) 5
```

Tests are commonly organized as commands in a module that call `assert`, run by a script that sources the module. Because the language predates a 1.0 release, pin the Nushell version a module is written for.

## Performance and concurrency

Nushell is compiled in Rust, and its built-in commands run in-process, so data operations that would spawn multiple Unix programs stay within one process and avoid repeated parsing. Working in the table model keeps bulk transformations in native code rather than shelling out per line.

For concurrency, the `par-each` filter runs a closure over pipeline rows in parallel across threads, which suits CPU-bound transformations over a table. External commands still run as separate processes. Because pipeline values are immutable, parallel row processing avoids shared-mutable-state hazards within a pipeline.

## Common pitfalls

- Version drift: Nushell has changed command names and behavior across releases, so a script from an older version may not run; check the version it targets.
- Not POSIX: Bash and `sh` syntax do not work, and external commands that expect text pipelines may need explicit conversion to and from structured data.
- Immutability surprises: a `let` binding cannot be reassigned; use `mut` when you intend to change a value, and remember pipeline data is replaced, not mutated.
- External command quoting: when calling non-Nushell programs, arguments are passed as structured values, so interpolating untrusted text still needs care (see Secure coding).

## Secure coding

Nushell's structured model removes some text-parsing hazards but does not remove command injection when it calls external programs:

- Operating-system command injection: when you run an external command built from untrusted input, treat the input as data, not as part of the command. Pass values as distinct arguments rather than interpolating them into a single command string, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Dynamic evaluation: constructing Nushell source from untrusted input and running it (for example through dynamic sourcing) executes arbitrary code, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html); build typed values and call commands directly instead.
- Untrusted data parsing: `open` and the `from` converters turn file and network content into structured values; validate the shape and ranges of parsed data before acting on it, rather than trusting fields such as paths or URLs.
- Configuration and plugin integrity: `config.nu`, `env.nu`, and plugin binaries run with your privileges; review plugins before registering them and pin their sources, as covered in [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: the parser's static checks catch some errors before execution; there is no dedicated security linter comparable to ShellCheck, so keep untrusted input out of external command construction and review each dynamic source.

## Learning resources

- [The Nushell Book](https://www.nushell.sh/book/), the official introduction and reference.
- [Nushell command reference](https://www.nushell.sh/commands/), documentation for every built-in command.
- [Nushell cookbook](https://www.nushell.sh/cookbook/), task-oriented examples.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [PowerShell](/languages/powershell.md)
- [Bash](/languages/bash.md)
- [All languages](/languages/README.md)
