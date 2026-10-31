# Make

Make is a build-automation language and tool created by Stuart Feldman at Bell Labs in 1976. A makefile declares targets, their prerequisites, and the recipes that build them; Make reads the dependency graph, compares file timestamps, and runs only the recipes whose outputs are out of date. It is declarative about what depends on what and imperative inside each recipe, which is a sequence of shell commands, and it remains a common build driver across C, C++, and many other projects.

| Attribute | Value |
|---|---|
| Paradigm | Declarative dependency graph with imperative shell recipes |
| Typing | Untyped: variables hold strings; recipes are shell commands |
| First appeared | 1976 |
| Memory model | Managed by the tool; variables are string macros expanded on use |
| Reference implementation | GNU Make |
| Typical uses | Building software, task automation, reproducible command sequences |
| Governance | POSIX specification for `make`; GNU Make as the common implementation |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Bash](/languages/bash.md), [languages index](/languages/README.md).

## Overview and history

Make was written to solve a specific problem: rebuilding only the parts of a program whose sources had changed, instead of recompiling everything. The idea, a dependency graph plus timestamp comparison, proved general enough to drive almost any task that turns inputs into outputs. POSIX standardized a core `make`, and implementations diverged: GNU Make added pattern rules, functions, and conditionals; BSD Make took a different extension path.

Make is often generated or wrapped by other tools (Autotools, CMake, and others emit makefiles), and newer build systems (Ninja, Bazel) target the same job with different trade-offs. Make persists because it is present everywhere, needs no project setup beyond a text file, and expresses the common "build X from Y" relationship directly.

## Paradigm and type system

A makefile is a set of rules. Each rule names a target, its prerequisites, and a recipe:

```makefile
target: prerequisite1 prerequisite2
	recipe command        # note: a real tab, not spaces
```

Make is untyped; variables are string macros. The core logic is declarative: Make builds a directed graph of targets and prerequisites, then walks it, running a recipe only when a target is missing or older than a prerequisite. Recipes themselves are imperative shell commands. This split, declarative dependencies and imperative recipes, is the essence of the language.

## Toolchain and ecosystem

- Tool: `make` reads `Makefile` (or `-f file`); `make target` builds a specific target, and `make -n` prints commands without running them.
- Implementations: GNU Make is the common one on Linux; BSD Make and other variants differ in functions and conditionals.
- Generators: Autotools, [CMake](https://cmake.org/), and similar tools generate makefiles so authors do not write them by hand.
- Analysis: `make --warn-undefined-variables` surfaces typos; [checkmake](https://github.com/mrtazz/checkmake) is a linter for makefile style and common mistakes.

```bash
make -n install            # dry run: show commands, run nothing
make -j4                   # build with four parallel jobs
```

## Syntax tour

```makefile
# Variables; := expands immediately, = expands when used
CC := gcc
CFLAGS := -Wall -O2
SOURCES := main.c util.c
OBJECTS := $(SOURCES:.c=.o)   # substitution reference

# Phony targets are names, not files
.PHONY: all clean
all: program

# A rule: program depends on the object files
program: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^   # $@ = target, $^ = all prerequisites

# A pattern rule: how to build any .o from its .c
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@   # $< = first prerequisite

clean:
	rm -f $(OBJECTS) program
```

## Idioms and different approaches

- Declare targets that are not files (`all`, `clean`, `test`) as `.PHONY` so Make does not skip them when a file of that name exists.
- Use automatic variables (`$@` target, `$<` first prerequisite, `$^` all prerequisites) in recipes rather than repeating names.
- Prefer immediate assignment (`:=`) for most variables so expansion order is predictable; use deferred assignment (`=`) deliberately when you want late binding.
- Write pattern rules (`%.o: %.c`) instead of one rule per file, and let Make infer the graph.
- Remember that each recipe line runs in its own shell by default; to carry state (a `cd`, a variable) across lines, join them with `&&` and `\`, or enable `.ONESHELL` in GNU Make.

## Design principles

Make's design rests on one relationship: a target depends on prerequisites and is rebuilt when they are newer. Everything else, variables, functions, pattern rules, exists to express that graph with less repetition. The timestamp model is simple and language-agnostic, which is why Make drives builds in many languages, but it is also the source of its weaknesses: it reasons about file modification times, not file contents, so it can miss or overdo rebuilds when timestamps mislead.

## Standard features and functions

GNU Make provides built-in functions for text and files: `$(wildcard ...)` to expand globs, `$(patsubst ...)` and substitution references for renaming, `$(foreach ...)`, `$(filter ...)`, `$(shell ...)` to capture command output, and `$(call ...)` to invoke user-defined functions. Automatic variables and built-in implicit rules (for compiling C, for instance) cover common cases without explicit recipes. Conditionals (`ifeq`, `ifdef`) and `include` allow composing makefiles. BSD Make offers a different, incompatible function set, so portable makefiles stay close to POSIX.

## Testing and packaging

Make is not packaged; a makefile is distributed with its project. "Testing" a build system usually means running targets and checking results, often with `make -n` to inspect commands first and a clean rebuild to confirm the graph is correct.

```makefile
.PHONY: test
test: program
	./program --selftest        # exit status nonzero fails the build
```

A conventional makefile exposes standard targets (`all`, `install`, `clean`, `test`) so that users and continuous-integration systems can invoke it the same way across projects.

## Performance and concurrency

Make's incremental model is its performance story: by rebuilding only out-of-date targets, it avoids redundant work. Correct, fine-grained dependencies are what make this effective; missing dependencies cause stale builds, and overly broad ones cause unnecessary rebuilds.

Make runs recipes in parallel with `-j N`, scheduling independent targets across N jobs. Parallelism is only safe if the dependency graph is accurate: a target that uses an output it did not declare as a prerequisite can race against the job producing it. For large parallel builds, declare every real dependency, and be aware that recursive Make across subdirectories can hide dependencies and limit parallelism, a problem described in the paper "Recursive Make Considered Harmful".

## Common pitfalls

- Tabs versus spaces: recipe lines must begin with a real tab character; spaces produce a confusing "missing separator" error.
- Each recipe line runs in a separate shell, so a `cd` or a shell variable set on one line does not persist to the next unless the lines are joined or `.ONESHELL` is used.
- Incomplete dependencies cause stale results under incremental and parallel builds; the build looks correct until a change is silently missed.
- `=` versus `:=`: deferred expansion can pick up a later value than expected, and `$(shell ...)` in a deferred variable may run many times.
- Portability: GNU Make functions and pattern rules do not all work under BSD Make, so makefiles that must travel should stay within POSIX features.

## Secure coding

Make recipes are shell commands, and makefiles often expand variables and command output into those commands, so injection and integrity are the concerns:

- Operating-system command injection: variables, `$(shell ...)` results, and environment values are expanded into recipe command lines. If any of these carries untrusted content (a file name from a directory listing, an environment variable, a value from a generated fragment), it can inject shell commands. Quote expansions in recipes and do not build commands from untrusted input. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Untrusted included makefiles: `include` and generated makefile fragments execute as part of the build; a fragment from an untrusted source can run arbitrary recipes, the build-system equivalent of evaluating code, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). Treat downloaded or generated makefiles as code and review them.
- Build-time network fetches: a recipe that downloads and runs code (a `curl | sh` step) during the build pulls unverified input into execution; pin and verify what the build fetches, as covered in [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Search path and tool integrity: recipes invoke tools by name, so a `PATH` that includes an attacker-writable directory can substitute a build tool; control `PATH` and prefer known tool locations, which relates to [CWE-426](https://cwe.mitre.org/data/definitions/426.html).

Tooling: `make --warn-undefined-variables` catches a class of expansion bugs, and [checkmake](https://github.com/mrtazz/checkmake) flags style and structural issues; recipes that handle untrusted input deserve the same review as any shell script with [ShellCheck](https://www.shellcheck.net/).

## Learning resources

- GNU Make Manual, the reference for variables, functions, and rules.
- [POSIX make specification](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/make.html), the portable core.
- ["Recursive Make Considered Harmful"](https://aegis.sourceforge.net/auug97.pdf) by Peter Miller, on structuring large builds.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Bash](/languages/bash.md)
- [All languages](/languages/README.md)
