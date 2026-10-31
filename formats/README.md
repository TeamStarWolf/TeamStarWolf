# Data formats and regular expressions

Reference pages for the markup, data, and configuration formats that applications read and write, plus regular expressions. Each page covers what the format is and where it is used, its syntax and structure with worked examples, the tooling that parses and validates it, and the format-specific security pitfalls tied to the relevant CWE weaknesses.

These are the data layer between programs. For the languages that produce and consume them see [All languages](/languages/README.md); for the weaknesses the security sections reference see the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

Related: [All languages](/languages/README.md), [Software frameworks](/frameworks/README.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Reference Index](/INDEX.md).

---

## Markup

| Format | Summary |
|---|---|
| [HTML](/formats/html.md) | HyperText Markup Language: elements, attributes, forms, and the cross-site scripting boundary |
| [CSS](/formats/css.md) | Cascading Style Sheets: selectors, the cascade, layout, and style-based data exfiltration |
| [Markdown](/formats/markdown.md) | Lightweight markup, its flavors, and the embedded-HTML scripting risk |

## Data and configuration

| Format | Summary |
|---|---|
| [JSON](/formats/json.md) | JavaScript Object Notation: the data interchange format of the web, and prototype-pollution risk |
| [YAML](/formats/yaml.md) | Human-readable data and config, and the unsafe-deserialization and YAML-bomb risks |
| [XML](/formats/xml.md) | Extensible Markup Language, with XML external entity and entity-expansion risks |
| [TOML](/formats/toml.md) | A typed, minimal configuration format used by many toolchains |
| [INI](/formats/ini.md) | The informal key-value configuration format, and its parser differences |
| [CSV](/formats/csv.md) | Comma-separated values, with quoting rules and the spreadsheet formula-injection risk |
| [Protocol Buffers](/formats/protobuf.md) | Google's binary serialization format, its schema, and safe-parsing limits |

## Patterns

| Reference | Summary |
|---|---|
| [Regular expressions](/formats/regex.md) | Syntax, engines, and the regular-expression denial-of-service (ReDoS) risk |
