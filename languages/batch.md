# Windows Batch (cmd)

Windows Batch is the scripting language of the Windows command interpreter, `cmd.exe`. A batch file (`.bat` or `.cmd`) is a text file of commands that `cmd.exe` runs line by line, descended from the MS-DOS `COMMAND.COM` batch language of the early 1980s. It remains present on every Windows system and is used for small automation tasks, installer and build glue, and startup scripts, though PowerShell has replaced it for most new administrative work.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, command-oriented scripting |
| Typing | Untyped: all values are strings; arithmetic is explicit via `set /a` |
| First appeared | 1981 (MS-DOS batch); `cmd.exe` with Windows NT in 1993 |
| Memory model | Managed by the interpreter; variables live in the process environment |
| Reference implementation | `cmd.exe`, the Windows command interpreter |
| Typical uses | Startup scripts, installer and build glue, small Windows automation |
| Governance | Microsoft; behavior is documented but not formally standardized |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [PowerShell](/languages/powershell.md), [languages index](/languages/README.md).

## Overview and history

The batch language began as a way to script `COMMAND.COM` under MS-DOS. Windows NT introduced `cmd.exe` in 1993 with a larger command set, delayed variable expansion, and better arithmetic, and that interpreter is what modern `.bat` and `.cmd` files target. The `.cmd` extension differs from `.bat` mainly in how it sets the error level for some built-in commands; otherwise they are the same language.

Batch was never designed as a general scripting language, and it shows: string handling, quoting, and control flow are awkward, and many tasks need external utilities. Microsoft's current direction is PowerShell, but batch persists because it needs no setup, runs everywhere Windows runs, and remains the simplest way to chain a few commands at boot or during installation.

## Paradigm and type system

Batch is untyped and command-oriented. Every value is a string stored in an environment variable; there are no arrays or structured types. Arithmetic requires the `/a` switch on `set`, which interprets its operands as integers.

```bat
set count=3
set /a total=count * 2      :: total=6, integer arithmetic
set greeting=hello world    :: a string value
echo %greeting%
```

Variable expansion has two forms: `%var%` is expanded when a line is parsed, while `!var!` (with delayed expansion enabled) is expanded when the line runs, which matters inside loops and blocks.

## Toolchain and ecosystem

- Interpreter: `cmd.exe` runs batch files and an interactive prompt; `cmd /c script.bat` runs a file and exits.
- There is no package manager or module system; reuse means calling other batch files with `call` or shipping helper executables alongside.
- Common companions are the built-in commands (`findstr`, `for`, `xcopy`, `robocopy`) and bundled tools; many scripts shell out to PowerShell for anything involved.
- Editing is plain text; there is no standard formatter or linter comparable to ShellCheck, so review and testing carry more weight.

```bat
cmd /c build.bat            :: run a batch file and return its exit code
```

## Syntax tour

```bat
@echo off
setlocal enabledelayedexpansion   :: scope variables; enable !var! expansion

set name=world
echo hello, %name%

:: Loop over a list; use !var! inside the block
set fruits=apple banana cherry
for %%f in (%fruits%) do (
    echo fruit: %%f
)

:: Conditionals and existence tests
if exist "%SystemRoot%\notepad.exe" (
    echo found notepad
) else (
    echo not found
)

:: Arithmetic
set /a squares=4 * 4

:: Call a labeled subroutine
call :greet team
goto :eof

:greet
echo hi %~1
exit /b 0
```

## Idioms and different approaches

- Begin scripts with `@echo off` to silence command echoing and `setlocal` so variable changes do not leak into the caller's environment.
- Enable `setlocal enabledelayedexpansion` and use `!var!` when reading a variable that changes inside a `for` loop or an `if` block; `%var%` is frozen at parse time.
- Quote paths that may contain spaces and use `%~1` to strip surrounding quotes from an argument; the `~` modifiers also extract drive, path, name, and extension.
- Check `%ERRORLEVEL%` or use `if errorlevel 1` after a command to detect failure, since batch does not stop on error by default.
- Reach for PowerShell when a task needs real string processing, structured data, or error handling; batch is best kept to short command sequences.

## Design principles

Batch exists to run commands in sequence with a little control flow, not to compute. Its guiding constraint is backward compatibility: scripts written decades ago still run, which freezes quirks such as two expansion phases and `errorlevel` semantics in place. The language assumes an interactive command interpreter underneath, so its features are extensions to that interpreter rather than a coherent language design, which is why non-trivial logic is painful and usually delegated.

## Standard library and notable commands

Batch has no library; its vocabulary is the set of `cmd.exe` internal commands plus external Windows utilities. Internal commands include `set`, `for`, `if`, `call`, `goto`, `echo`, and `setlocal`. External utilities commonly used from batch are `findstr` for pattern matching, `robocopy` and `xcopy` for file copying, `reg` for the registry, `schtasks` for scheduled tasks, and `powershell -Command` to run a snippet of PowerShell for anything batch cannot do cleanly.

## Testing and tooling

Batch has no test framework or packaging format; a script is distributed as a file and run directly. Testing is manual or driven by a wrapper script that runs the batch file and checks its exit code and output.

```bat
:: A crude assertion on an exit code
call build.bat
if %ERRORLEVEL% neq 0 (
    echo FAIL: build returned %ERRORLEVEL%
    exit /b 1
)
echo PASS
```

Because there is no linter, keep batch files short and move complex logic to PowerShell, where [Pester](https://pester.dev/) and [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) exist.

## Performance and execution

Each external command in a batch file launches a process, so, as with Unix shells, cost scales with how many programs the script starts. Internal commands and `for` loops run in the interpreter and are cheaper. There is no concurrency model built into the language: to run tasks in parallel you launch them with `start`, which opens separate command windows or processes, and then coordinate through files or exit codes. For any workload that needs real parallelism or throughput, a batch file typically calls PowerShell or a compiled tool.

## Common pitfalls

- Delayed expansion: reading `%var%` inside a loop gives the value from when the loop was parsed, not the current iteration; enable delayed expansion and use `!var!`.
- Quoting and special characters: `&`, `|`, `<`, `>`, `^`, and `%` have meaning to the interpreter, so unquoted or unescaped values with these characters break or redirect commands.
- `errorlevel` handling: batch continues after a failed command by default, and `if errorlevel 1` means "1 or greater", which trips up comparisons.
- `.bat` versus `.cmd` differences in how built-ins set the error level can change behavior subtly between the two extensions.

## Secure coding

Batch builds and runs commands from strings, so injection is the central risk, made worse by the interpreter's special characters:

- Operating-system command injection: never build a command from untrusted input (arguments, file contents, registry values) and run it, because characters such as `&` and `|` let an attacker append commands. Validate and quote inputs, and prefer calling a program with fixed arguments. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Argument and expansion abuse: an unquoted `%1` or an unescaped `%var%` containing metacharacters can inject tokens into the command line; quote arguments and use the `%~1` modifiers to normalize them. This also maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Untrusted search path: `cmd.exe` searches the current directory before `PATH` for some invocations, so a batch file run in an attacker-writable directory can execute a planted `program.exe`; call programs by full path and control the working directory, which relates to [CWE-426](https://cwe.mitre.org/data/definitions/426.html).
- Dynamic command construction: avoid assembling a command line from variables and running it, the batch equivalent of `eval`, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).

Tooling: there is no established batch linter, so the practical control is to keep scripts small, review them, and move anything that handles untrusted input into PowerShell, where [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) can inspect it.

## Learning resources

- [Windows Commands reference](https://learn.microsoft.com/windows-server/administration/windows-commands/windows-commands), the official documentation for `cmd.exe` commands.
- [cmd documentation](https://learn.microsoft.com/windows-server/administration/windows-commands/cmd), which describes the interpreter and its switches.
- [SS64 CMD reference](https://ss64.com/nt/), a widely used community reference for batch syntax.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [PowerShell](/languages/powershell.md)
- [All languages](/languages/README.md)
