# Tcl

Tcl (Tool Command Language) is a dynamically typed, garbage-collected scripting language created by John Ousterhout in 1988. Its defining idea is that everything is a command and every value is a string, which makes the language small, embeddable, and easy to extend with new commands. It runs on an interpreter (the reference implementation is written in C) and is used for test automation, embedded scripting, network and electronic-design tooling, and graphical applications through its companion toolkit Tk.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, procedural, with command-based metaprogramming |
| Typing | Dynamic; values are strings with cached internal representations |
| First appeared | 1988 |
| Memory model | Automatic: reference counting on internal objects |
| Reference implementation | [Tcl (C)](https://www.tcl-lang.org/) |
| Typical uses | Test automation, embedded scripting, EDA tooling, GUIs with Tk |
| Governance | [Tcl Core Team](https://core.tcl-lang.org/) with the TIP proposal process |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Lua](/languages/lua.md), [languages index](/languages/README.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who write or maintain Tcl code, and the reviewers and security engineers who assess it

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,329 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are writing or reviewing Tcl code (typical uses: test automation, embedded scripting, EDA tooling, GUIs with Tk), you need its common pitfalls and secure-coding rules before a review, or you are choosing its toolchain, tests and packages

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax tour](#syntax-tour), [Common pitfalls](#common-pitfalls), [Secure coding](#secure-coding)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Lua](/languages/lua.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Tcl was created by John Ousterhout at the University of California, Berkeley, to give his electronic-design tools a common embeddable scripting language instead of each tool inventing its own. The companion [Tk](https://www.tcl-lang.org/) toolkit, released in 1991, added portable graphical widgets and made Tcl a popular choice for cross-platform GUIs. Tcl remains common in electronic-design automation (EDA) flows, network equipment, and test harnesses such as Expect, which automates interactive programs.

The reference implementation is a C library that embeds readily into host applications. The language evolves through Tcl Improvement Proposals (TIPs). Tcl 8.6 introduced coroutines and a built-in object system; the 9.0 line modernized the C interface and 64-bit handling.

## Paradigm and type system

Tcl's model is uniform: a script is a sequence of commands, each a list of words, where the first word names a command and the rest are arguments. Every value is, at the language level, a string, though the interpreter caches an internal representation (an integer, a list, a dictionary) for speed. There are no reserved keywords in the usual sense: control structures such as `if`, `while`, and `proc` are commands that happen to be built in, so you can define your own that behave the same way.

```tcl
# proc defines a command; everything is a command call
proc total {prices} {
    set sum 0
    foreach p $prices { set sum [expr {$sum + $p}] }
    return $sum
}
```

## Toolchain and ecosystem

- Interpreter: `tclsh` runs scripts and an interactive prompt; `wish` adds the Tk graphical toolkit.
- Packaging: the `package` command loads versioned modules; [Teapot](https://wiki.tcl-lang.org/page/Teapot) and distributions such as [ActiveTcl](https://www.activestate.com/products/tcl/) provide module repositories.
- Extension: the C API lets host programs register new commands, which is how Tcl embeds in larger tools.
- Linting: [nagelfar](https://nagelfar.sourceforge.net/) is a static syntax checker and style checker for Tcl.

```bash
echo 'puts [expr {2 + 3}]' | tclsh
```

## Syntax tour

```tcl
# Variables are set and dereferenced with $
set name "world"
puts "hello, $name"

# Command substitution with square brackets
set squares {}
foreach n {0 1 2 3 4} {
    lappend squares [expr {$n * $n}]   ;# {0 1 4 9 16}
}

# Lists and dictionaries
set lookup [dict create a 1 b 2]
puts [dict get $lookup a]

# Procedures
proc greet {who {excited 0}} {
    set tail [expr {$excited ? "." : "."}]
    return "hi $who$tail"
}

# Braces defer evaluation; expr should always brace its expression
if {$name eq "world"} {
    puts "matched"
}

# Error handling
if {[catch {expr {1 / 0}} result]} {
    set result 0
}
```

## Idioms and different approaches

- Always brace expressions passed to `expr` and conditionals (`if {...}`); an unbraced expression is substituted first, which is slower and can inject code.
- Use `{braces}` to defer evaluation and `"quotes"` to allow variable and command substitution; the distinction controls when words are expanded.
- Build lists with `lappend` and dictionaries with `dict`; both have an efficient internal representation.
- Use string comparison operators `eq` and `ne` for strings and numeric operators `==` and `!=` inside `expr` for numbers.
- The `uplevel` and `upvar` commands let a procedure run code or access variables in a caller's scope, the basis for writing control-flow commands.

## Design principles

Ousterhout designed Tcl around a single rule set so that the language core stays tiny and the real work happens in commands, which an application can supply. Because control structures are ordinary commands, the language is extensible from the inside: a user can add a looping construct that looks built in. The uniform string representation makes values easy to pass across the C boundary and to serialize, at some cost in numeric performance, which the cached internal representation recovers.

## Standard library and notable extensions

The core ships commands for strings, lists, dictionaries, files, and sockets, plus `clock` for time and `regexp`/`regsub` for regular expressions. Notable extensions include [Tk](https://www.tcl-lang.org/) for graphical interfaces, [Expect](https://core.tcl-lang.org/expect/) for automating interactive programs, [tcllib](https://core.tcl-lang.org/tcllib/) for a large set of pure-Tcl utility modules, and [TDBC](https://www.tcl-lang.org/man/tcl/TdbcCmd/tdbc.html) for database connectivity.

## Testing and packaging

The [tcltest](https://www.tcl-lang.org/man/tcl/TclCmd/tcltest.html) package ships with Tcl and drives most testing.

```tcl
package require tcltest
namespace import tcltest::*

test add-1 {addition works} -body {
    expr {2 + 3}
} -result 5

cleanupTests
```

A distributable module provides a `pkgIndex.tcl` so the `package require` command can find and load it by name and version.

## Performance and concurrency

Tcl compiles scripts to an internal bytecode and caches the typed representation of values, so repeated numeric and list operations avoid re-parsing strings. For throughput-sensitive code, brace `expr` expressions so the compiler can optimize them. Concurrency models:

- The event loop (`vwait`, `after`, and file events) drives single-threaded asynchronous I/O and is the basis for Tk and network servers.
- Coroutines (`coroutine`, `yield`), added in 8.6, provide cooperative multitasking.
- The optional threads extension gives each thread its own interpreter with no shared variables, so parallelism uses message passing rather than shared memory.

## Common pitfalls

- Leaving an `expr` expression unbraced causes a double round of substitution: it is slower and lets crafted input inject commands.
- Confusing quoting rules: `{...}` suppresses substitution while `"..."` allows it, so the wrong choice either fails to expand a variable or expands one you meant to keep literal.
- Numeric versus string comparison: using `==` on strings or `eq` on numbers inside `expr` can give the wrong answer; match the operator to the data.
- Everything-is-a-string means a value that looks numeric can still be treated as text; coerce explicitly when it matters.

## Security relevance

Tcl reaches security practitioners as an embedded and automation language: it scripts network devices and electronic-design tools, drives interactive programs through Expect, and runs inside host applications that may evaluate untrusted input. The defensive patterns that counter each weakness are in the Secure coding section that follows; this section is the threat-facing context.

### Where it appears

- Network and device scripting. Tcl is embedded in network equipment and electronic-design automation flows, so operational scripts that handle configuration and external data are often Tcl.
- Interactive automation. [Expect](https://core.tcl-lang.org/expect/) automates interactive programs such as login and device sessions, which appears in both administration and testing.
- Embedded host applications. The C API lets a host program register commands and evaluate scripts, so an application that runs user-supplied Tcl places that evaluation inside its trust boundary.

### Dominant weakness classes

Tcl is memory-safe: it is managed by reference counting and does not expose manual memory, so memory-corruption classes do not apply. Its command-oriented, string-everywhere model makes injection the central concern:

- Code injection. An unbraced `expr`, or `eval` and `subst` applied to data built from untrusted input, executes attacker-chosen commands. This is [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Operating-system command injection. `exec` and `open "|command"` run external programs, so a command assembled from untrusted input reaches the shell. This is [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- SQL injection. Building SQL by string substitution rather than using TDBC parameterized statements lets input change the query. This is [CWE-89](https://cwe.mitre.org/data/definitions/89.html).

### Why it matters

Reading Tcl lets a reviewer find unbraced expressions and `eval` of external data, the places input turns into commands, and judge whether untrusted scripts run inside a safe interpreter (`interp create -safe`) that hides file, socket, and process commands. The static checker [nagelfar](https://nagelfar.sourceforge.net/) flags unbraced expressions and other risky constructs, as the Secure coding section details.

## Secure coding

Tcl's command-oriented model makes injection the central concern:

- Command injection within Tcl: an unbraced `expr` or an `eval` of data built from untrusted input can execute attacker-chosen commands; always brace expressions and avoid `eval`/`subst` on untrusted strings. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Safe interpreters: Tcl provides `interp create -safe`, a restricted child interpreter that hides file, socket, and process commands. Run untrusted scripts inside a safe interpreter and expose only vetted aliases.
- Operating-system command injection: `exec` and `open "|command"` run external programs; never assemble the command from untrusted input, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- SQL injection: use TDBC parameterized statements rather than building SQL by string substitution, which maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
- Dependency supply chain: review extensions and pin versions through `package require`; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [nagelfar](https://nagelfar.sourceforge.net/) flags unbraced expressions and other unsafe or error-prone constructs during static analysis.

## Learning resources

- [Tcl/Tk documentation](https://www.tcl-lang.org/doc/), the official manual pages.
- [Tcl Developer Xchange](https://www.tcl-lang.org/), the project home with tutorials.
- [The Tcler's Wiki](https://wiki.tcl-lang.org/), a community reference with examples.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [Lua](/languages/lua.md)
- [All languages](/languages/README.md)
