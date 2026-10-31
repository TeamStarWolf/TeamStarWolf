# Zsh

Zsh (the Z shell) is a command-line interpreter and scripting language written by Paul Falstad in 1990. It is largely compatible with the Bourne and POSIX shells while adding interactive features such as programmable completion, shared history, spelling correction, and themeable prompts. It became the default login shell on macOS in 2019 and is widely used interactively, with scripting that is close enough to Bash that the two share most idioms and risks.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, command-oriented scripting |
| Typing | Untyped: values are strings, with arrays and integer attributes |
| First appeared | 1990 |
| Memory model | Managed by the interpreter; variables live in the shell process environment |
| Reference implementation | [Zsh](https://www.zsh.org/) |
| Typical uses | Interactive shell, system administration, automation scripts |
| Governance | Zsh development group (`zsh-workers` mailing list) |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Bash](/languages/bash.md), [fish](/languages/fish.md), [languages index](/languages/README.md).

## Overview and history

Zsh was created by Paul Falstad while a student at Princeton, named after a teaching assistant's login, "zsh". It set out to be a better interactive shell than the shells of its day, borrowing completion and editing ideas from `tcsh` and `ksh`. Over time it gained a large completion system and an extension framework.

Zsh stayed niche for years until community configuration frameworks, especially [Oh My Zsh](https://ohmyz.sh/), made its interactive features easy to adopt. Apple switched the default shell on macOS from Bash to Zsh with macOS Catalina in 2019, partly because Bash on macOS had been frozen at an old version over licensing, which brought Zsh to a much wider audience.

## Paradigm and type system

Like other Unix shells, Zsh is untyped and command-oriented: values are strings, and a script is a sequence of commands whose first word selects a builtin, function, or program. Zsh adds integer and floating attributes through `typeset`, and its arrays are one-based by default, unlike the zero-based arrays in Bash.

```zsh
typeset -i count=3        # integer attribute
total=$(( count * 2 ))    # total=6
fruits=(apple banana)     # arrays are 1-based
print $fruits[1]          # apple
```

A notable default difference from Bash: Zsh does not word-split unquoted scalar variables, so `$var` with spaces stays a single word. This removes a common class of bug but means Bash scripts that rely on splitting behave differently.

## Toolchain and ecosystem

- Interpreter: `zsh` runs scripts and an interactive session; `zsh -n` checks syntax without running.
- Completion: the `compinit` system provides context-aware completion for hundreds of commands.
- Frameworks: [Oh My Zsh](https://ohmyz.sh/) and [Prezto](https://github.com/sorin-ionescu/prezto) bundle themes and plugins; plugin managers such as [zinit](https://github.com/zdharma-continuum/zinit) load components on demand.
- Linting: [ShellCheck](https://www.shellcheck.net/) supports a `zsh`-aware mode for many constructs, though its primary target is POSIX and Bash.

```zsh
zsh -n script.zsh          # syntax check
```

## Syntax tour

```zsh
#!/usr/bin/env zsh
emulate -L zsh              # use zsh options locally regardless of caller
setopt err_exit no_unset    # stop on error and on unset variables

name="world"
print "hello, ${name}"

# Arrays are 1-based; iterate directly
fruits=(apple banana cherry)
for fruit in $fruits; do
    print "fruit: ${fruit}"
done

# Globbing qualifiers: match only regular files, newest first
recent=( *(.om) )

# Conditionals
if [[ -f /etc/hostname ]]; then
    host="$(< /etc/hostname)"
fi

# Functions
greet() {
    local who=$1
    printf 'hi %s\n' "${who}"
}
greet "team"
```

## Idioms and different approaches

- Begin a script with `emulate -L zsh` so that option settings do not leak into or out of the caller's environment.
- Use glob qualifiers (`*(.)` for regular files, `*(/)` for directories, `*(.om)` for modification order) instead of piping `ls` into a filter.
- Rely on Zsh's lack of scalar word splitting, but still quote expansions when writing code that might run under Bash or `sh`.
- Use extended globbing (`setopt extended_glob`) for pattern negation and qualifiers rather than shelling out.
- Keep interactive configuration in `.zshrc` and login configuration in `.zprofile`, because they run in different sessions.

## Design principles

Zsh prioritizes the interactive user: completion, history, and prompt features are first-class, and defaults favor convenience. It is also configurable to a fault, with options (`setopt`) that change core behaviors such as globbing and splitting, so two users' shells can behave differently. For scripting, that configurability is a reason to set options explicitly rather than inherit them.

## Standard library and notable modules

Zsh ships loadable modules that extend the core: `zsh/mathfunc` for floating math, `zsh/datetime` for time, `zsh/stat` for file metadata without an external `stat`, `zsh/net/tcp` for sockets, and the `zsh/pcre` and `zsh/regex` modules for matching. The completion system and `zle` (the Zsh Line Editor) are the basis for its interactive extensions. As with Bash, external Unix programs provide most non-interactive functionality.

## Testing and packaging

Zsh code is distributed as scripts and plugin directories rather than packaged artifacts; a plugin is typically a directory with a `.plugin.zsh` entry point loaded by a framework.

```zsh
# A minimal assertion in a script
assert_eq() { [[ "$1" == "$2" ]] || { print "FAIL: $1 != $2"; return 1 } }
assert_eq $(( 2 + 3 )) 5
```

The [zunit](https://github.com/zunit-zsh/zunit) project provides a test runner for Zsh code; ShellCheck covers the POSIX and Bash-compatible parts.

## Performance and concurrency

As with any Unix shell, startup and throughput are dominated by how many external processes a script spawns. Zsh's loadable modules (`zsh/stat`, `zsh/datetime`, `zsh/mathfunc`) let scripts avoid calling out to separate programs for common tasks, which can noticeably speed up loops. Interactive startup time is often dominated by framework and plugin loading; lazy-loading plugins keeps shells responsive.

Concurrency uses the standard shell model: background jobs with `&`, `wait`, and external tools such as `xargs -P`. There is no shared-memory threading.

## Common pitfalls

- Assuming Bash behavior: Zsh does not word-split unquoted scalars by default and uses 1-based arrays, so a ported Bash script can silently do the wrong thing.
- Options inherited from the user's environment can change globbing and matching; set them explicitly in scripts with `emulate -L zsh`.
- Extended globbing is off by default, so patterns that work in one shell may be literal in another.
- Interactive-only configuration placed in the wrong startup file either does not run or runs in non-interactive scripts unexpectedly.

## Secure coding

Zsh shares the shell family's injection risks:

- Operating-system command injection: do not assemble commands from untrusted input or pass them through `eval`; pass data as arguments. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Quoting and expansion: although Zsh does not split unquoted scalars, arrays and command substitutions still expand, and glob qualifiers can match unexpected files; quote values and constrain patterns. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- `eval` and dynamic code: `eval` and sourcing untrusted files run arbitrary code, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). Build argument lists with arrays instead.
- Startup-file integrity: a writable `.zshrc` or a plugin pulled from an untrusted source runs on every shell start; review and pin plugin sources, as covered in [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [ShellCheck](https://www.shellcheck.net/) flags unsafe `eval` and quoting problems in the shell-compatible parts of a script, and should run in continuous integration alongside review of Zsh-specific constructs.

## Learning resources

- [Zsh Manual](https://zsh.sourceforge.io/Doc/), the reference for options, builtins, and modules.
- [A User's Guide to the Z-Shell](https://zsh.sourceforge.io/Guide/), an introductory guide.
- [The Zsh FAQ](https://zsh.sourceforge.io/FAQ/), which covers migration and common questions.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Bash](/languages/bash.md)
- [fish](/languages/fish.md)
- [All languages](/languages/README.md)
