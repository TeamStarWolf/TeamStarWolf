# J

J is a dynamically typed, array-oriented language created by Kenneth E. Iverson and Roger Hui, first released in 1990. It is a successor to APL that uses only ASCII characters instead of special glyphs, and it extends APL's ideas with tacit (point-free) programming, where functions are built by combining other functions without naming arguments. It is used for mathematical and statistical computation, concise array programming, and research into notation.

| Attribute | Value |
|---|---|
| Paradigm | Array-oriented, functional, tacit (point-free), with imperative support |
| Typing | Dynamic; values are multidimensional arrays (nouns) |
| First appeared | 1990 |
| Memory model | Automatic garbage collection |
| Reference implementation | [J (Jsoftware)](https://www.jsoftware.com/) |
| Typical uses | Mathematical and statistical computation, array programming, teaching notation |
| Governance | [Jsoftware](https://www.jsoftware.com/), released under open source |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [APL](/languages/apl.md), [languages index](/languages/README.md).

## Overview and history

After APL, Iverson and Hui designed J to capture the same array ideas using a plain ASCII character set, so programs need no special keyboard. Primitives are spelled as a character or a character followed by `.` or `:` (such as `+/`, `i.`, and `|:`), which keeps the terse style while remaining typeable anywhere. J also made tacit programming central: functions (called verbs) combine into trains and forks that compute without explicitly mentioning their arguments.

The reference implementation is from Jsoftware and has been released under an open-source license. J runs as an interactive interpreter with an optional graphical environment, and it bundles numerical, statistical, and graphics libraries called addons.

## Paradigm and type system

J borrows a parts-of-speech vocabulary: nouns are data (arrays), verbs are functions on nouns, adverbs and conjunctions are higher-order operators that modify verbs, and the result of combining verbs is again a verb. Values are dynamically typed arrays of booleans, integers, floating-point or complex numbers, characters, or boxed elements (J's nested values). A verb has a monadic and a dyadic definition selected by whether a left argument is present, as in APL.

```j
total =: ] +/@:* 1 + [     NB. tacit: left arg tax, right arg prices
0.1 total 10 20 30         NB. 66
```

Explicit definitions use `x` and `y` for the left and right arguments; tacit definitions name no arguments at all.

## Toolchain and ecosystem

- Interpreter: the `jconsole` command-line interpreter and the `jqt` graphical environment from Jsoftware.
- Addons: numerical, statistical, graphics, and web libraries are installed through J's built-in package manager, run from the interpreter or the `jqt` environment.
- Input: ordinary ASCII, so any editor and terminal work without special fonts.
- Interfacing: J links to C through its foreign-conjunction facilities and embeds in host programs as a shared library.

```bash
echo '+/ (i. 4) ^ 2' | jconsole
```

## Syntax tour

```j
NB. Comments start with NB. Expressions run right to left.
name =: 'world'
'hello, ' , name

NB. i. generates indices (origin 0); ^ is power
i. 5                        NB. 0 1 2 3 4
squares =: (i. 4) ^ 2       NB. 0 1 4 9

NB. Insert adverb (/) reduces; $ reshapes
+/ 1 2 3 4                  NB. 10
3 3 $ i. 9                  NB. a 3-by-3 table

NB. Compress selects where a boolean is 1
v =: 5 2 8 1
(v > 3) # v                 NB. 5 8

NB. Explicit verb definition with x and y
mean =: 3 : '(+/ y) % # y'
mean 2 4 6                  NB. 4

NB. A fork: (f g h) y is (f y) g (h y); here mean as a fork
meanf =: +/ % #
meanf 2 4 6                 NB. 4

NB. Error handling with the :: adverse conjunction
safe =: (% :: 0:)
1 safe 0                    NB. 0 on error
```

## Idioms and different approaches

- Prefer tacit definitions (trains, forks, and hooks) for short verbs, and switch to explicit `3 : '...'` definitions when argument naming aids clarity.
- Use rank: the rank conjunction (`"`) controls the cells a verb applies to, which replaces many explicit loops over subarrays.
- Reduce and scan with the insert adverb (`/`) and prefix/suffix scans rather than iterating.
- Box heterogeneous data with `<` and open it with `>`; boxing is J's way of nesting arrays of differing shapes.
- Index origin is 0 in J (unlike default APL), so translate APL idioms with care.

## Design principles

J keeps APL's whole-array model but removes the dependence on a special character set, trading glyphs for short ASCII spellings. Tacit programming is promoted to a first-class style: by composing verbs into forks and hooks, programs describe computation as function combination rather than step-by-step assignment. The grammar's parts of speech give a consistent rule for how nouns, verbs, and modifiers combine, which makes the terse syntax systematic even though it is dense to read.

## Standard library and notable packages

J's primitives cover arithmetic, array reshaping and selection, sorting (`/:` grade), set operations, and linear algebra. The standard library and addons add formatting, dates and times, regular expressions, file and socket I/O, plotting, statistics, and a web server. Addons are distributed and updated through J's package manager rather than a separate third-party registry.

## Testing and packaging

J addons include test scripts, and a straightforward approach asserts expected results.

```j
add =: +
assert 5 = 2 add 3          NB. assert signals an error if false
```

Reusable code is organized into script files (`.ijs`) and addons with a manifest, installed and updated through J's package manager.

## Performance and concurrency

J primitives operate on whole arrays in the interpreter's compiled loops, and some verb-and-operator combinations are recognized as special code that runs without building intermediates, so idiomatic array code is fast. Using rank to apply verbs to cells, and keeping data in unboxed numeric arrays rather than deeply boxed structures, improves cache behavior and speed. J is primarily single-threaded; parallelism comes from calling multithreaded native libraries or running multiple interpreter tasks rather than from language-level threads.

## Common pitfalls

- Right-to-left evaluation with no function precedence: `2 * 3 + 4` is 14; parenthesize when you mean otherwise.
- Index origin 0 in J versus default origin 1 in APL: idioms do not transfer unchanged.
- Monadic versus dyadic verbs: the same spelling has two meanings selected by context, so a missing left argument changes the operation.
- Boxing: forgetting to open (`>`) a boxed value, or boxing when you meant a flat array, leads to shape and type errors.
- Readability: dense tacit trains are hard to maintain; comment their intent and decompose long ones.

## Secure coding

J is used in analytical tooling, so the main risks are executing untrusted input and host access:

- Code injection: the execute verbs `".` (do, which evaluates a string as a J sentence) and `128!:2` run code from text; never apply them to untrusted input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Operating-system command injection: the host foreign `2!:` (and `spawn`) runs shell commands; never assemble the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Untrusted data and script files: loading (`load`, `require`) a J script executes it, and reading foreign data with `1!:` file facilities trusts the file's contents; load scripts only from trusted sources and validate imported data, which relates to [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- SQL injection: when querying a database through a J interface, use parameterized statements rather than building SQL by catenation, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Dependency provenance: review addons before installing, since they run code, and pin versions; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: J has no widely adopted dedicated security linter, so review every use of `".`, `2!:`, and `load` on data paths by hand, keep untrusted input away from these verbs, and rely on code review and the interpreter's own error reporting.

## Learning resources

- [J documentation](https://www.jsoftware.com/help/), the official dictionary and user guides.
- [Learning J](https://www.jsoftware.com/help/learning/contents.htm), a free introductory book.
- J wiki, community reference and essays.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [APL](/languages/apl.md)
- [K and Q](/languages/k-q.md)
- [All languages](/languages/README.md)
