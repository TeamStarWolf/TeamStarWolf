# Bash

Bash (the Bourne Again SHell) is a command-line interpreter and scripting language written by Brian Fox for the GNU Project and first released in 1989. It is a superset of the POSIX shell, used both interactively at a terminal and as the language for scripts that glue together programs, files, and processes. It is the default login shell on many Linux distributions and a common target for automation, build steps, and system administration.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, command-oriented scripting |
| Typing | Untyped: values are strings; arithmetic and arrays are contextual |
| First appeared | 1989 |
| Memory model | Managed by the interpreter; variables live in the shell process environment |
| Reference implementation | GNU Bash |
| Typical uses | System administration, automation, build and deploy scripts, CI pipelines |
| Governance | GNU Project; maintained by Chet Ramey |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Zsh](/languages/zsh.md), [POSIX AWK](/languages/awk.md), [languages index](/languages/README.md).

## Overview and history

Bash was written as a free-software replacement for the Bourne shell (`sh`) that shipped with Unix. It added features from the Korn shell and the C shell, such as command-line editing, command history, and job control, while staying compatible with existing Bourne scripts. Chet Ramey has maintained the project since the early 1990s.

Bash reads and executes commands from a terminal, a script file, or standard input. It has become the common denominator for shell scripts across Linux systems, which is both a convenience and a hazard: a script that uses Bash extensions (a "bashism") will fail under a stricter POSIX shell such as `dash`. The language is defined in practice by the GNU Bash manual and, for its common core, by the POSIX shell command language specification.

## Paradigm and type system

Bash is an untyped, command-oriented language. A script is a sequence of commands; each command is a word list where the first word names a builtin, a function, or an external program, and the rest are arguments. Values are strings. Bash adds indexed and associative arrays, and arithmetic contexts (`$(( ... ))` and `(( ... ))`) that interpret strings as integers.

```bash
count=3                 # a string that looks like a number
total=$(( count * 2 ))  # arithmetic context: total=6
declare -A color        # associative array
color[sky]=blue
```

The absence of types means almost any value is accepted; the cost is that word splitting and globbing silently transform unquoted values, which is the source of most shell bugs.

## Toolchain and ecosystem

- Interpreter: `bash` runs scripts and an interactive read-eval-print loop; `bash -n` parses without executing, and `bash -x` traces execution.
- Linting: [ShellCheck](https://www.shellcheck.net/) is a static analyzer that flags quoting, portability, and correctness problems and is the standard gate for shell code.
- Formatting: [shfmt](https://github.com/mvdan/sh) reformats scripts to a consistent style.
- Portability: set a `#!/usr/bin/env bash` shebang and test with ShellCheck's POSIX mode when a script must run under `sh`.

```bash
shellcheck deploy.sh      # report issues
shfmt -w deploy.sh        # format in place
```

## Syntax tour

```bash
#!/usr/bin/env bash
set -euo pipefail           # exit on error, unset var, and pipe failure

name="world"
echo "hello, ${name}"

# Command substitution and arithmetic
files=$(ls -1 | wc -l)
echo "there are $(( files )) entries"

# Arrays and loops
fruits=(apple banana cherry)
for fruit in "${fruits[@]}"; do
    echo "fruit: ${fruit}"
done

# Conditionals; [[ ... ]] is the Bash test
if [[ -f /etc/hostname ]]; then
    host=$(< /etc/hostname)
fi

# Functions
greet() {
    local who=$1
    printf 'hi %s\n' "${who}"
}
greet "team"
```

## Idioms and different approaches

- Start scripts with `set -euo pipefail` so that errors, unset variables, and failed pipeline stages stop the script instead of continuing silently.
- Quote every variable expansion (`"${var}"`) unless you specifically want word splitting or globbing; this one habit prevents a large class of defects.
- Prefer `[[ ... ]]` over the older `[ ... ]` test command in Bash scripts, because it does not word-split its operands and supports pattern matching.
- Use `$( ... )` command substitution rather than backticks, which nest poorly.
- Use `printf` rather than `echo` for anything beyond a fixed literal, because `echo` behavior varies with options and content.

## Design principles

Bash follows the Unix tradition of composing small programs with pipes and redirection, so the shell's job is to connect commands rather than to compute. Its design goal was POSIX conformance plus interactive convenience, which is why the language accumulates features (arrays, process substitution, extended globbing) while keeping backward compatibility with Bourne scripts. The result is expressive for orchestration and awkward for data manipulation, which is where a general-purpose language usually takes over.

## Standard library and notable builtins

Bash does not have a package library; its "standard library" is the set of builtins plus the external programs on the system. Builtins include `read`, `printf`, `declare`, `mapfile`, `test`/`[[`, and job-control commands. Common companions on a Unix system are `grep`, `sed`, `awk`, `find`, `xargs`, and `curl`. Shell functions and sourced files (`source file.sh`) provide reuse; frameworks such as [bats-core](https://github.com/bats-core/bats-core) add structure for testing.

## Testing and packaging

Shell code is usually distributed as plain scripts rather than packages; installation means copying a file onto `PATH` and making it executable.

```bash
# test.bats, run with: bats test.bats
@test "addition works" {
  result=$(( 2 + 3 ))
  [ "$result" -eq 5 ]
}
```

[bats-core](https://github.com/bats-core/bats-core) is a common test runner for Bash; `shellcheck` serves as the correctness gate in continuous integration.

## Performance and concurrency

Bash starts external processes for most real work, so performance is dominated by how many processes a script spawns. A loop that calls `grep` once per line is far slower than a single `grep`. Keep data in builtins (parameter expansion, arithmetic) when you can, and push bulk work into one call of a dedicated tool.

For concurrency, Bash runs commands in the background with `&` and waits with `wait`; `xargs -P` and GNU `parallel` distribute work across cores. There is no shared-memory threading model: parallelism means separate processes that communicate through files, pipes, or exit codes.

## Common pitfalls

- Unquoted expansions (`$var`) undergo word splitting and filename globbing, so a value with spaces or `*` breaks the command or matches unintended files.
- Parsing the output of `ls` is unreliable; iterate with a glob (`for f in ./*`) or `find -print0` with `read -d ''`.
- `set -e` does not catch every error (for example, a failure inside a command substitution or a function used in a condition); do not rely on it alone.
- A pipeline's exit status is that of the last stage unless `set -o pipefail` is active, so failures upstream can be hidden.

## Secure coding

The shell's central risk is injection, because the shell is in the business of building and running commands:

- Operating-system command injection: never build a command from untrusted input and hand it to the shell. Avoid `eval` on assembled strings, and pass data as arguments to a program rather than interpolating it into a command line. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Unquoted variables: an unquoted expansion is split on whitespace and expanded as a glob, so an attacker who controls a value can inject extra arguments or match files. Always quote expansions, which also maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- `eval` and dynamic code: `eval`, `source` on untrusted paths, and `sh -c "$var"` execute whatever the data contains, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). Prefer arrays to build argument lists safely.
- Insecure temporary files: create temporary files with `mktemp` rather than fixed names in `/tmp`, which maps to [CWE-377](https://cwe.mitre.org/data/definitions/377.html).
- Dependency and path integrity: set a known `PATH` and use full paths for sensitive commands so a planted binary earlier on `PATH` is not run; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [ShellCheck](https://www.shellcheck.net/) flags unquoted expansions, unsafe `eval`, and many injection-prone patterns, and should run on every script in continuous integration.

## Learning resources

- GNU Bash Manual, the reference for builtins and syntax.
- [The Bash Guide (mywiki.wooledge.org)](https://mywiki.wooledge.org/BashGuide) and its FAQ, a careful treatment of quoting and common mistakes.
- [ShellCheck](https://www.shellcheck.net/), which explains each warning with examples.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Zsh](/languages/zsh.md)
- [POSIX AWK](/languages/awk.md)
- [All languages](/languages/README.md)
