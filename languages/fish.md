# fish

fish (the friendly interactive shell) is a command-line interpreter and scripting language first released by Axel Liljencrantz in 2005. It aims for a pleasant interactive experience out of the box, with syntax highlighting, autosuggestions from history, and completions derived from man pages, and it deliberately departs from POSIX shell syntax where that helps clarity. It is used mainly as an interactive shell and for scripts that do not need to be portable to `sh`.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, command-oriented scripting |
| Typing | Untyped: all values are lists of strings |
| First appeared | 2005 |
| Memory model | Managed by the interpreter; variables have function, global, or universal scope |
| Reference implementation | [fish](https://fishshell.com/) |
| Typical uses | Interactive shell, personal automation scripts |
| Governance | fish-shell open-source project on GitHub |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Bash](/languages/bash.md), [Zsh](/languages/zsh.md), [languages index](/languages/README.md).

## Overview and history

fish was created to fix the parts of interactive shell use that its author found awkward, rather than to extend the Bourne lineage. It shipped syntax highlighting and history-based autosuggestions years before those became common elsewhere, and it generates tab completions by parsing the system's man pages. The project was long written in C++; it was rewritten in Rust, with that work landing in the 4.0 release in 2025.

fish chooses a cleaner syntax over POSIX compatibility. Scripts written for `sh` or Bash do not run under fish without translation, which is the main trade-off: the interactive experience is smoother, but a fish script is not a drop-in for the system shell. For that reason, fish is a common interactive login shell even among people who still write portable scripts in POSIX `sh`.

## Paradigm and type system

fish is untyped and command-oriented, like other shells, but with one clarifying decision: every variable is a list of strings, and there is no scalar-versus-array distinction. A "plain" variable is a list with one element. Variables carry a scope: `function`, `global`, or `universal` (persisted across sessions and shared between running shells).

```fish
set count 3                 # a one-element list
set total (math "$count * 2")  # command substitution with parentheses
set fruits apple banana cherry # a three-element list
echo $fruits[1]             # apple, 1-based indexing
```

Crucially, fish does not perform word splitting on variable expansion: `$var` expands to exactly its list elements, so a value containing spaces stays one element. This removes the single largest source of shell bugs.

## Toolchain and ecosystem

- Interpreter: `fish` runs an interactive session or a script; `fish --no-execute script.fish` checks syntax without running.
- Configuration: `fish_config` opens a browser-based settings tool; functions live as one-file-per-function under `~/.config/fish/functions`.
- Package managers: [Fisher](https://github.com/jorgebucaran/fisher) and [fundle](https://github.com/danhper/fundle) install community plugins and prompts such as [Tide](https://github.com/IlanCosman/tide).
- Formatting and linting: `fish_indent` reformats scripts to a consistent style and is bundled with fish.

```fish
fish_indent --write script.fish   # format in place
fish --no-execute script.fish     # syntax check
```

## Syntax tour

```fish
#!/usr/bin/env fish

set name world
echo "hello, $name"

# Command substitution uses parentheses, not backticks or $()
set entries (ls | count)
echo "there are $entries entries"

# Lists and loops; no word splitting on expansion
set fruits apple banana cherry
for fruit in $fruits
    echo "fruit: $fruit"
end

# Conditionals use command status, with test for comparisons
if test -f /etc/hostname
    set host (cat /etc/hostname)
end

# Functions are defined with function ... end
function greet
    set who $argv[1]
    printf 'hi %s\n' $who
end
greet team
```

## Idioms and different approaches

- Use parentheses `(command)` for command substitution; fish has no backticks and no `$()`.
- Do arithmetic with the `math` builtin rather than a `$(( ))` context, which fish does not have.
- Define functions in their own files under `~/.config/fish/functions` so they autoload on first use.
- Use `set -U` (universal) for values that should persist and be shared across shells, such as a preferred editor, instead of exporting in a startup file.
- Rely on the absence of word splitting: you rarely need to quote expansions to keep a value intact, though quoting is still clearer for literals with spaces.

## Design principles

fish values discoverability and sensible defaults over tradition and portability. The documented goal is a shell that is good to use interactively without configuration, so highlighting, suggestions, and completions work on first launch. The syntax is intentionally regular: blocks end with `end`, substitution is always parentheses, and expansion never splits, which trades the ability to run POSIX scripts for fewer surprises.

## Standard library and notable builtins

fish provides builtins for its own model: `set` for variables and scope, `math` for arithmetic, `string` for text operations (split, join, match, replace, trim) that replace much of the sed and awk plumbing, `count` for list length, and `argparse` for parsing function arguments. The `string` builtin in particular lets scripts manipulate text without spawning external filters. As with other shells, external Unix programs supply the rest.

## Testing and packaging

fish code is distributed as function files and plugins installed by a plugin manager; there is no compiled artifact.

```fish
# A simple assertion
function assert_eq
    test "$argv[1]" = "$argv[2]"; or echo "FAIL: $argv[1] != $argv[2]"
end
assert_eq (math "2 + 3") 5
```

The fish project itself uses a test harness in its source tree; for user code, [Fishtape](https://github.com/jorgebucaran/fishtape) provides a test runner that produces TAP output.

## Performance and concurrency

As with any shell, runtime cost is dominated by external process spawning. The `string` and `math` builtins reduce that cost by keeping text and arithmetic in-process rather than calling `sed`, `awk`, or `expr` in a loop. Interactive responsiveness was a design focus, and the Rust rewrite aimed to keep startup and redraw fast.

Concurrency uses background jobs with `&` and `wait`, and external tools such as `xargs -P` for parallel work. fish does not provide shared-memory threading; parallelism is separate processes communicating through pipes and files.

## Common pitfalls

- Portability: fish syntax is not POSIX, so a fish script cannot be run by `sh` or Bash, and copied snippets from Bash tutorials often fail; translate them.
- Command substitution syntax: writing `$(cmd)` or backticks does not work; use `(cmd)`.
- Expecting word splitting: because fish does not split, a Bash idiom that relied on splitting a string into arguments behaves differently; use `string split` to split explicitly.
- Universal variables persist and are shared between shells, so a stray `set -U` can surprise you later; prefer `set -g` or `set -l` unless persistence is intended.

## Secure coding

fish shares the shell family's injection risks, with its no-splitting default removing one of them:

- Operating-system command injection: do not build a command string from untrusted input and run it through `eval`; pass data as separate arguments. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- `eval` and dynamic code: fish has an `eval` builtin that executes its argument as a command; running untrusted data through it executes arbitrary code, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). Build an argument list and call the command directly instead.
- Expansion within commands: although fish does not word-split, interpolating untrusted values into a command still lets the values act as additional tokens in some contexts; validate inputs and prefer `string` operations to construct values. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Startup and plugin integrity: autoloaded functions and universal variables run on shell start; review plugins before installing and pin their sources, as covered in [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: fish's own parser reports syntax errors with `--no-execute`, and `fish_indent` normalizes style; for shell-agnostic checks, keep untrusted input out of command construction and review each `eval`.

## Learning resources

- [fish documentation](https://fishshell.com/docs/current/), the official tutorial and reference.
- [The fish tutorial](https://fishshell.com/docs/current/tutorial.html), a short introduction to the syntax.
- [fish FAQ](https://fishshell.com/docs/current/faq.html), which covers migration from Bash.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Bash](/languages/bash.md)
- [Zsh](/languages/zsh.md)
- [All languages](/languages/README.md)
