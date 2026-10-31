# AWK

AWK is a text-processing language created by Alfred Aho, Peter Weinberger, and Brian Kernighan at Bell Labs in 1977, its name formed from their initials. A program is a set of pattern-action rules: for each input line, every pattern that matches runs its action. This model makes AWK concise for scanning text, extracting and reformatting fields, and computing simple aggregates, and it is a standard tool on every Unix-like system.

| Attribute | Value |
|---|---|
| Paradigm | Declarative pattern-action rules with imperative actions |
| Typing | Dynamic: values are strings and numbers, coerced by context |
| First appeared | 1977 (POSIX AWK in 1985; GNU `gawk` from 1986) |
| Memory model | Managed by the interpreter; associative arrays and scalars |
| Reference implementation | [The One True AWK (`onetrueawk`)](https://github.com/onetrueawk/awk) |
| Typical uses | Log and report processing, field extraction, text transformation in pipelines |
| Governance | POSIX specification; GNU `gawk` and BWK `awk` as implementations |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Bash](/languages/bash.md), [languages index](/languages/README.md).

## Overview and history

AWK was written to make short text-processing programs easy, replacing one-off C programs for tasks such as counting, summing, and reformatting columns. The 1985 book "The AWK Programming Language" by its three authors defined the language, and a revised edition appeared in 2023. POSIX standardized AWK, and several implementations exist: the original "one true awk" maintained by Kernighan, the GNU `gawk` with many extensions, `mawk` tuned for speed, and `busybox awk` for small systems.

AWK is most often used as one stage in a shell pipeline, reading from standard input or files and writing to standard output. It coexists with `grep` and `sed`: `grep` selects lines, `sed` edits streams, and AWK handles field-oriented logic and arithmetic.

## Paradigm and type system

An AWK program is a list of `pattern { action }` rules. For each input record (by default a line), AWK tests each pattern and runs the action of those that match. Fields are split automatically into `$1`, `$2`, and so on, with `$0` the whole record and `NF` the field count.

```awk
# Print the second field of lines longer than 10 characters
length($0) > 10 { print $2 }
```

Typing is dynamic: a value is a string or a number, and context decides which. `"10" + 5` is `15`; the same value used in a string context is text. Uninitialized variables are the empty string or zero as needed. Arrays are associative, indexed by string keys.

## Toolchain and ecosystem

- Interpreter: `awk 'program' file ...` runs an inline program; `awk -f prog.awk` runs one from a file.
- Implementations: gawk adds features such as true multidimensional arrays, networking, and a profiler; `mawk` and the original `awk` are smaller and faster for the POSIX subset.
- Variables: `-v name=value` sets a variable before execution; `-F sep` sets the field separator.
- There is no package ecosystem; AWK programs are distributed as scripts or embedded in shell scripts.

```bash
awk -F, '{ sum += $3 } END { print sum }' data.csv
gawk --lint -f report.awk input.txt   # gawk's built-in lint warnings
```

## Syntax tour

```awk
# BEGIN runs before input; END runs after all input
BEGIN { FS = ","; OFS = "\t" }   # input comma-separated, output tab

# A pattern with an action: accumulate a per-key total
{ total[$1] += $3 }

# A range pattern: act on lines from one match to another
/START/, /END/ { print "in range:", $0 }

# A function
function greet(who) {
    return "hi " who          # string concatenation is juxtaposition
}

END {
    for (key in total)
        print key, total[key]
    print greet("team")
}
```

## Idioms and different approaches

- Use `BEGIN` to set separators and initialize state, and `END` to print summaries after all input is read.
- Accumulate per-key aggregates in associative arrays (`count[$1]++`), which is AWK's strength over `grep` and `sed`.
- Set the field separator with `-F` or `FS` for delimited data; set `OFS` and `ORS` to control output formatting.
- Concatenate strings by writing them next to each other (`a b`), and build numbers by using values in arithmetic context.
- For one-line field extraction in a pipeline, inline the program with single quotes; move to a `-f` file once logic grows past a few rules.

## Design principles

AWK was designed so that a useful program could be a single line, which is why patterns and actions default to sensible behavior: records are lines, fields split on whitespace, and `print` with no arguments prints the whole record. The pattern-action model matches the shape of text-processing problems directly, so the common case needs little code. The language stays small and composes with other Unix tools rather than trying to replace them, which keeps it learnable and predictable.

## Standard library and built-in functions

AWK's "library" is its set of built-in functions and variables. String functions include `length`, `substr`, `index`, `split`, `sub`, `gsub`, `match`, and `sprintf`; arithmetic functions include `int`, `sqrt`, `sin`, `cos`, `exp`, and `log`. Built-in variables include `NR` (record number), `NF` (field count), `FS`/`OFS` (field separators), `RS`/`ORS` (record separators), and `FILENAME`. `gawk` adds functions for time (`systime`, `strftime`), bit operations, and arrays, plus extension support, but a program that stays within POSIX functions runs on every implementation.

## Testing and tooling

AWK programs are scripts, not packages; distribution is a `.awk` file or an inline program in a shell script. Testing is usually done by running the program on fixed input and comparing output.

```bash
# Compare program output against an expected file
awk -f report.awk sample.in > sample.out
diff -u expected.out sample.out && echo PASS
```

`gawk --lint` reports questionable constructs and portability problems, which serves as a lightweight check; otherwise, keeping programs small and testing them against sample inputs is the practical discipline.

## Performance and execution

AWK reads input one record at a time and runs in a single pass, so memory use is bounded unless the program accumulates large arrays. For field extraction and aggregation, a single AWK invocation usually outperforms a loop in the shell that spawns a process per line, because AWK does the whole job in one process. `mawk` is notably faster than other implementations for the POSIX subset, which matters on large inputs.

AWK has no concurrency model: it is a single-threaded, single-pass stream processor. Parallelism, when needed, comes from splitting input and running several AWK processes under a tool such as `xargs -P` or GNU `parallel`.

## Common pitfalls

- Field separator confusion: the default `FS` splits on runs of whitespace, but setting `FS=","` does not skip empty fields, so comma data with empty columns behaves differently; real CSV with quoted commas needs a proper parser, not plain `FS`.
- String-versus-number coercion: a value can compare as a string or a number depending on how it was produced, so `"10" < "9"` (string) differs from `10 < 9` (number); force a type with `+0` or concatenation when it matters.
- Uninitialized variables are silently empty or zero, so a typo in a variable name does not error, it just reads as blank.
- Implementation differences: programs that rely on `gawk` extensions (such as `gensub`, networking, or `PROCINFO`) do not run under the original `awk` or `mawk`.

## Secure coding

AWK can reach outside itself through the `system` function and command pipes, which is where injection risk lives:

- Operating-system command injection: `system(cmd)` and `print | "command"` or `"command" | getline` run a shell command. If any part of that command string comes from untrusted input (a field, a file name, an environment value), an attacker can inject additional commands. Do not build these strings from input; where a program must shell out, pass fixed commands and keep data out of the command line. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Untrusted program text: running an AWK program whose source is assembled from untrusted input (for example built in a shell script and passed to `awk`) executes that logic, the equivalent of evaluating code, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html); keep the program fixed and pass data as input, not as code.
- Output and format handling: when using `printf`/`sprintf`, keep the format string a literal and pass untrusted values as arguments, so that input cannot act as format directives.
- Input validation: treat fields from logs or network data as untrusted; validate ranges and shapes before using a field as a file name or in any constructed command.

Tooling: `gawk --lint` flags some unsafe and nonportable constructs; the main control is to avoid `system` and command pipes built from input, and to keep program text fixed. See also [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md) for the tools an AWK stage invokes.

## Learning resources

- The GNU Awk User's Guide, a thorough reference that notes POSIX versus `gawk` behavior.
- [The AWK Programming Language](https://awk.dev/), the authors' book, whose second edition appeared in 2023.
- [The one true awk source and manual](https://github.com/onetrueawk/awk), the reference implementation.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Bash](/languages/bash.md)
- [All languages](/languages/README.md)
