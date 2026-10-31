# JSON

JSON (JavaScript Object Notation) is a text format for structured data. It encodes objects, arrays, and primitive values in a syntax that is easy to read and easy to parse. It began as a subset of JavaScript and is now defined by its own standard. Most web APIs and many configuration files use it.

## What it is and where it is used

JSON carries structured data between systems as plain UTF-8 text. It is the default body format for REST and many RPC APIs, and the payload format for most webhooks.

Common uses include:

- Request and response bodies for HTTP APIs.
- Configuration files such as `package.json` and `tsconfig.json`.
- Log lines in structured logging, one JSON object per line.
- Message payloads in queues and event streams.
- Tokens and claims, for example the body of a JWT.

JSON describes data, not behavior. It has no comments, no functions, and no date type. Those gaps are deliberate and keep parsers simple.

## Syntax and structure

A JSON document is a single value. That value is one of six types: object, array, string, number, boolean, or `null`.

An object is an unordered set of key and value pairs inside braces. Keys are strings. A colon separates each key from its value, and commas separate pairs.

```json
{
  "id": 42,
  "active": true,
  "tags": ["admin", "beta"]
}
```

An array is an ordered list of values inside brackets.

```json
[1, 2, 3, "four", null]
```

Strings are double-quoted. The backslash escapes special characters, including `\"`, `\\`, `\n`, `\t`, and `\uXXXX` for a Unicode code point.

```json
{ "path": "C:\\Users\\dev", "quote": "She said \"hi\"" }
```

Numbers use decimal notation with an optional fraction and exponent. There is no separate integer type in the grammar, and `NaN`, `Infinity`, and leading zeros are not allowed.

```json
{ "count": 10, "ratio": 0.75, "scaled": 6.022e23 }
```

The literals `true`, `false`, and `null` are written without quotes. Whitespace between tokens is insignificant. Trailing commas and comments are not part of the grammar.

## A worked example

This document describes an API response with nested objects and an array.

```json
{
  "order": {
    "id": "A-10294",
    "placed": "2026-10-31T14:05:00Z",
    "total": 129.99,
    "paid": true,
    "items": [
      { "sku": "KB-01", "qty": 1, "price": 99.99 },
      { "sku": "CA-07", "qty": 2, "price": 15.00 }
    ],
    "coupon": null
  }
}
```

The date is a string because JSON has no date type. The `coupon` field is `null` to show a known-absent value. Numbers carry no currency or unit, so the consumer must know those from context.

## Tooling

- `jq` queries, filters, and reshapes JSON on the command line.
- Validators check documents against JSON Schema to enforce required keys and types.
- Formatters and linters such as Prettier normalize indentation and key spacing.
- Language libraries include `JSON.parse`/`JSON.stringify` in JavaScript, `json` in Python, and Jackson or Gson in Java.
- `JSONLines` tooling handles newline-delimited JSON for logs and streams.

Prefer a streaming parser for inputs that may be large, since loading a whole document into memory is a denial-of-service risk.

## Security considerations

JSON is data, but parsing and merging untrusted JSON carries real risk. See `/SECURE_CODING_REFERENCE.md` for input-handling guidance.

- Parsing untrusted input. Treat every externally supplied document as hostile. Set size and nesting-depth limits before parsing, because a deeply nested array can exhaust the stack. Never pass JSON text to `eval` or a language `eval`-like call; use a real parser. Reference CWE-20 (Improper Input Validation).
- Prototype pollution. In JavaScript, merging a parsed object into another with a naive deep-merge can let a `__proto__` or `constructor` key write onto `Object.prototype`. This corrupts unrelated objects and can lead to denial of service or remote code execution. Reject or strip `__proto__`, `constructor`, and `prototype` keys, or use `Map` and null-prototype objects. Reference CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes).
- Integer and precision limits. JSON numbers are arbitrary precision in the grammar, but most parsers map them to IEEE 754 doubles. Integers above 2^53 lose precision silently. Carry large identifiers as strings. Reference CWE-681 (Incorrect Conversion between Numeric Types).
- Duplicate keys. The specification does not define behavior when an object repeats a key. Parsers vary: some keep the first value, some the last. An attacker can exploit this when a validator and a consumer disagree. Reject duplicate keys where the parser allows it.
- JSON injection. Building JSON by string concatenation lets attacker-controlled text break out of a value and inject new keys or structure. Always serialize with a library that escapes values; never assemble JSON by hand from user input. Reference CWE-116 (Improper Encoding or Escaping of Output).

## Resources

- RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format.
- The json.org grammar.

## Related pages

- `/formats/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/formats/yaml.md`
- `/formats/xml.md`
- `/formats/toml.md`
