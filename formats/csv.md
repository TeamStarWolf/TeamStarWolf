# CSV

CSV stands for comma-separated values. It is a plain-text format for tabular data, where each line is a record and fields are separated by a delimiter. Its simplicity makes it common for exports, data exchange, and spreadsheet import. That same simplicity hides edge cases around quoting, delimiters, and encoding that cause real bugs.

## What it is and where it is used

A CSV file holds rows of records. Each record has the same sequence of fields, separated by a comma. An optional header row names the columns. The format predates any formal standard and was later described by RFC 4180.

CSV appears wherever tabular data moves between systems: database dumps, report exports, spreadsheet files, bulk uploads, and data pipelines. Nearly every spreadsheet program, database, and data tool can read and write it. That ubiquity is its strength and the reason its ambiguities matter.

## Syntax and structure

A record is a line of fields. Fields are separated by a delimiter, normally a comma. Records are separated by a line break.

```csv
id,name,role
1,Ada Lovelace,engineer
2,Grace Hopper,admiral
```

A field that contains the delimiter, a quote, or a line break must be enclosed in double quotes.

```csv
id,note
1,"Contains, a comma"
2,"Spans
two lines"
```

A literal double quote inside a quoted field is written as two double quotes.

```csv
id,quote
1,"She said ""hello"" twice"
```

The delimiter is not always a comma. Tab-separated and semicolon-separated files are common, the latter in locales where the comma is a decimal separator. Readers must be told which delimiter to expect.

```csv
id;amount;note
1;1.234,56;european decimal comma
```

The header row is a convention, not a requirement. Code that assumes a header when none exists will drop or misread the first record. RFC 4180 defines the comma delimiter, CRLF line endings, and double-quote escaping, but many files in the wild deviate from it.

## A worked example

This file follows RFC 4180: a header row, comma delimiter, and double-quote escaping for fields that need it.

```csv
order_id,customer,product,quantity,price,notes
1001,"Lee, Jordan","USB cable",3,5.99,"ships today"
1002,"Patel, Anjali","Monitor stand",1,42.50,"color: ""graphite"""
1003,"O'Brien, Sam","Keyboard",2,29.00,"left-handed layout
backorder until Friday"
1004,"Nguyen, Mai","Mouse",5,12.75,""
```

Row 1002 escapes an inner quote by doubling it. Row 1003 holds a line break inside a quoted field. Row 1004 shows an empty quoted field.

## Tooling

- Python ships the `csv` module, which handles quoting and delimiter dialects.
- Pandas reads and writes CSV through `read_csv` and `to_csv` for data analysis.
- Most databases support CSV import and export (for example `COPY` in PostgreSQL).
- Command-line tools such as `csvkit`, `xsv`, and `miller` inspect and transform CSV.
- Spreadsheet programs open CSV directly, which is where injection risk begins.

Set the delimiter, quoting, and encoding explicitly in your parser rather than relying on defaults.

## Security considerations

CSV looks inert, but how it is written and where it is opened create specific risks.

- CSV or formula injection (CWE-1236, Improper Neutralization of Formula Elements in a CSV File). When a field begins with `=`, `+`, `-`, or `@`, a spreadsheet program may interpret it as a formula on open. A crafted field such as `=HYPERLINK(...)` or a command call can exfiltrate data or run an action. On export, prefix such fields with a safe character (for example a single quote or a space) or reject the leading character. Sanitize every field that originates from user input. See `/SECURE_CODING_REFERENCE.md`.
- Delimiter and quote confusion (CWE-20, Improper Input Validation). A field containing an unescaped delimiter or quote shifts every following column. This corrupts data silently and can place attacker-controlled content into a trusted column. Use a parser that enforces RFC 4180 quoting rather than splitting on the delimiter by hand.
- Encoding issues. A byte order mark, mismatched character set, or mixed line endings can mangle the first field or merge rows. Declare UTF-8 and handle the BOM explicitly. Do not guess the encoding.
- Row and field count assumptions. Ragged rows, missing headers, and extra columns lead to off-by-one reads. Validate the column count per row before trusting field positions.

Sanitize fields on export and validate structure on import. Treat any CSV from an external source as untrusted.

## Resources

- RFC 4180, Common Format and MIME Type for Comma-Separated Values (CSV) Files.
- OWASP guidance on CSV injection.

## Related pages

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /formats/json.md
- /formats/ini.md
- /formats/xml.md
