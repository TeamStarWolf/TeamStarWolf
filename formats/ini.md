# INI

INI is an informal key-value and section configuration format named after the `.ini` file extension. It has no single formal standard, so its exact syntax depends on the parser that reads it. The core idea is simple: named values grouped under bracketed section headers. That simplicity is why it persists across decades of software.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers, engineers and analysts who read, write or parse INI

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (930 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are reading or writing INI by hand or in code, you want a worked example and the tools that handle it, or you are parsing untrusted input and need its security considerations

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax and structure](#syntax-and-structure), [A worked example](#a-worked-example), [Security considerations](#security-considerations)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [TOML](/formats/toml.md), [YAML](/formats/yaml.md), [CSV](/formats/csv.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it is used

An INI file stores settings as `key = value` lines, optionally grouped under `[section]` headers. It began on early Windows systems and spread to many languages and applications. You find it in application preferences, desktop entry files on Linux, Git configuration, and Python project tooling.

Because there is no governing specification, each ecosystem defines its own dialect. The format you write for one parser may behave differently in another. Treat INI as a family of related formats rather than one fixed grammar.

## Syntax and structure

A section header is a name inside square brackets. Keys below it belong to that section until the next header.

```ini
[database]
host = localhost
port = 5432
```

Keys and values are separated by `=` or, in some dialects, `:`. Leading and trailing whitespace is usually trimmed, though this is parser-dependent.

```ini
username = admin
password : secret
```

Comments begin with `;` or `#`. Some parsers accept only one of the two.

```ini
; this is a comment
# some parsers also accept this
level = info
```

Values are strings by default. There is no universal type system, so a parser or the application decides whether `true`, `1`, or `08` means a boolean, an integer, or text.

```ini
enabled = true
retries = 3
```

Dialects vary in important ways:

- Whether keys are case-sensitive.
- Whether duplicate keys are an error, the last value wins, or values accumulate.
- Whether a `DEFAULT` or global section exists.
- Whether values may span multiple lines or reference other values through interpolation.

```ini
[DEFAULT]
timeout = 30

[service]
# some parsers interpolate %(timeout)s or ${timeout} here
retry_after = 30
```

Quoting is not standardized. Some parsers strip surrounding quotes, others keep them as literal characters, which is a frequent source of confusion.

## A worked example

This example targets Python's `configparser`, a widely used reference dialect.

```ini
[DEFAULT]
timeout = 30
log_level = info

[web]
host = 0.0.0.0
port = 8080
workers = 4
log_level = debug

[database]
host = db.internal
port = 5432
name = billing
# credentials injected at runtime, not stored here

[features]
enable_cache = true
enable_metrics = false
```

With `configparser`, keys in `[DEFAULT]` apply to every other section unless overridden, so `[web]` inherits `timeout = 30` while setting its own `log_level`.

## Tooling

- Python ships `configparser` in the standard library, a common reference implementation.
- The Windows API exposes `GetPrivateProfileString` and related functions for `.ini` files.
- Node.js uses libraries such as `ini`.
- Go has `go-ini/ini`.
- Git reads its own INI-like config through `git config`, with its own rules for sections and subsections.

Choose a parser first, then write to that parser's dialect. Do not assume a file written for one tool will load unchanged in another.

## Security relevance

This section is the threat-facing view of INI: why the absence of a formal grammar is a security property and where that is abused. The parser-selection and validation controls that defend against these are in the "Security considerations" section that follows.

### Where it appears

- Application and service config. INI files drive preferences, service settings, and tool configuration that a process reads with elevated trust at startup.
- Attacker-influenced config. Uploaded profiles, multi-tenant settings, and files written from user input let an attacker shape values a parser later interprets.
- Mixed toolchains. A file written for one parser is often read by another, so behavior one stage relied on may not hold in the next.

### Dominant weakness classes

INI is text config with no single standard, so the risks are parser ambiguity and injection rather than memory corruption. Its offensive story is modest and depends mostly on how the surrounding application trusts the parsed values. The defensive steps for each are in the section below.

- Improper validation of syntactic correctness ([CWE-1286](https://cwe.mitre.org/data/definitions/1286.html)), where case handling, comment characters, quoting, and duplicate keys differ between dialects.
- Interpretation conflict ([CWE-436](https://cwe.mitre.org/data/definitions/436.html)), where a validator and a consumer parse the same file differently, so a check passes but the effective config differs.
- Improper input validation ([CWE-20](https://cwe.mitre.org/data/definitions/20.html)) when a newline, bracket, or interpolation token in a value breaks out of its key or triggers substitution.

### Why it matters

Recognizing INI config in a multi-parser pipeline tells an auditor to test for interpretation differences and duplicate-key overrides, where the file a validator approves is not the one the application acts on. See [the secure coding reference](/SECURE_CODING_REFERENCE.md) for the input-validation method that applies here.

## Security considerations

INI's lack of a formal standard is itself the root of most of its risks. Behavior you rely on may not hold in another parser.

- Parser-dependent behavior. Case sensitivity, comment characters, quoting, interpolation, and duplicate-key handling all differ between implementations. A file that is safe in one parser may be read differently in another. Validate against the exact parser you ship.
- Injection through unescaped or multi-line values (CWE-20, Improper Input Validation). A value that contains a newline, a bracket, or an interpolation token can break out of its intended key or trigger substitution. If values come from user input, reject or escape control characters before writing them.
- Duplicate keys. Some parsers raise an error, some keep the last value, some the first, and some collect all values. An attacker who can append a duplicate key may override an earlier setting. Prefer a parser that rejects duplicates for security-relevant config.
- Secrets in config files (CWE-312, Cleartext Storage of Sensitive Information). Passwords and keys written into `.ini` files land in backups and version history. Keep secrets in environment variables or a secret manager and reference them at runtime. See `/SECURE_CODING_REFERENCE.md`.
- Interpolation surprises. Dialects that expand `%(name)s` or `${name}` can produce unexpected values or recursion. Disable interpolation when you parse untrusted input.

## Resources

INI has no formal standard. For concrete behavior, cite platform and library documentation:

- The Windows INI file format, as described in Microsoft platform documentation.
- Python `configparser` module documentation.

## Related pages

- [Data formats and regular expressions](/formats/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [TOML](/formats/toml.md)
- [YAML](/formats/yaml.md)
- [CSV](/formats/csv.md)
