# TOML

TOML stands for Tom's Obvious Minimal Language. It is a configuration file format that maps to a hash table through key-value pairs, tables, and arrays. It aims to be easy to read and unambiguous to parse, with typed values that avoid the guesswork common to other config formats. Tooling in the Rust and Python ecosystems has made it a common choice for project metadata.

## What it is and where it is used

TOML describes configuration as named values grouped under tables. Each value carries an explicit type: string, integer, float, boolean, date, array, or inline table. The format targets humans who edit config by hand, so it favors clear line structure over nesting depth.

You see TOML in several ecosystems:

- `Cargo.toml` defines Rust package metadata and dependencies.
- `pyproject.toml` configures Python build systems, tools, and project metadata.
- Many Go, Rust, and Python applications read runtime settings from TOML.

The format is a configuration language, not a data interchange format for large payloads. Deep nesting and streaming are not its goals.

## Syntax and structure

A TOML file is a set of key-value pairs. Keys sit on the left of an `=`, values on the right. Whitespace around the `=` is ignored.

```toml
title = "Example"
port = 8080
enabled = true
```

Strings come in basic (double-quoted, with escapes) and literal (single-quoted, no escapes) forms. Multi-line variants use triple quotes.

```toml
path = "C:\\Users\\dev"
literal = 'C:\Users\dev'
multiline = """
line one
line two
"""
```

Values are typed. Integers, floats, booleans, and dates each have a defined form.

```toml
count = 42
ratio = 3.14
active = false
created = 2026-10-31T09:00:00Z
local_date = 2026-10-31
```

Tables group keys under a header in square brackets. Dotted keys and nested table headers express hierarchy.

```toml
[server]
host = "localhost"
port = 5432

[server.tls]
enabled = true
```

Arrays hold ordered values of a consistent kind. Arrays of tables use double brackets.

```toml
ports = [8000, 8001, 8002]

[[user]]
name = "ada"

[[user]]
name = "grace"
```

Inline tables pack a small table onto one line. Comments start with `#` and run to the end of the line.

```toml
point = { x = 1, y = 2 }  # an inline table
```

A key must not be defined twice. Parsers reject duplicate keys and most reject mixed-type arrays, which is part of the format's type strictness.

## A worked example

```toml
# service.toml
name = "billing-api"
version = "2.3.0"
debug = false

[database]
host = "db.internal"
port = 5432
pool_size = 10
timeout = 30.0

[database.credentials]
username = "svc_billing"
# secret supplied at runtime, not stored here

[[endpoint]]
path = "/invoices"
methods = ["GET", "POST"]

[[endpoint]]
path = "/payments"
methods = ["GET"]

[logging]
level = "info"
retain_days = 14
started = 2026-10-31T00:00:00Z
```

## Tooling

- Rust reads and writes TOML through the `toml` crate, often with `serde`.
- Python 3.11 and later include `tomllib` for reading; `tomli` and `tomli-w` cover earlier versions and writing.
- Go has `BurntSushi/toml` and `pelletier/go-toml`.
- JavaScript parsing uses libraries such as `@iarna/toml`.
- `taplo` provides a formatter, linter, and language server for editors.

Validate TOML against the current specification version, because older parsers may reject dates or inline table features added later.

## Security considerations

TOML is a configuration format, so its main risks come from what people store in config files rather than from the parsing itself.

- Secrets committed to config files (CWE-312, Cleartext Storage of Sensitive Information). API keys, passwords, and tokens placed in `Cargo.toml`, `pyproject.toml`, or application config end up in version history. Keep secrets in environment variables or a secret manager, and reference them at runtime. See `/SECURE_CODING_REFERENCE.md` for secret-handling guidance.
- Parser differences. Implementations target different specification versions. A value that one parser accepts (for example a date form or a multi-line array) may be rejected or read differently by another. Pin the specification version you depend on and test with the exact parser you ship.
- Type coercion is reduced, not removed. TOML's explicit types mean a parser will not silently turn `true` into a string or `08` into an octal number, which avoids a class of bug seen in untyped formats. Still confirm that your deserialization target matches the declared types.
- Untrusted input. TOML is meant for trusted local config. If you parse TOML from an untrusted source, apply the same input limits you would use for any external data, including size caps.

## Resources

- The TOML specification by Tom Preston-Werner.

## Related pages

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /formats/ini.md
- /formats/yaml.md
- /formats/json.md
