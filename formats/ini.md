# INI

INI is an informal key-value and section configuration format named after the `.ini` file extension. It has no single formal standard, so its exact syntax depends on the parser that reads it. The core idea is simple: named values grouped under bracketed section headers. That simplicity is why it persists across decades of software.

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

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /formats/toml.md
- /formats/yaml.md
- /formats/csv.md
