# jq Command Reference

`jq` is a command-line processor for JSON. It reads JSON on standard input, applies a filter program, and writes JSON or plain text to standard output. It pairs naturally with `curl` and log pipelines where structured data needs slicing, filtering, or reshaping. This page covers the filters, builtins, and output modes used in everyday scripting.

## What it is and where it runs

`jq` is a small standalone binary available on Linux, macOS, Windows, and the BSDs. It has no runtime dependencies and streams data, so it handles large inputs without loading everything at once. A jq program is a pipeline of filters joined by `|`, much like a shell pipeline. Input is one or more JSON values; output is whatever the filter produces.

## Core commands

Identity and access.

```bash
jq '.'                     # pretty-print the whole input
jq '.name'                 # value of the name field
jq '.user.email'           # nested field
jq '.items[0]'             # first array element
jq '.items[]'              # each array element in turn
```

Filter and transform.

```bash
jq '.items[] | select(.active)'        # keep active items
jq '[.items[] | .price]'               # collect prices into an array
jq '.items | map(.price)'              # same, with map
jq '.items | map(select(.qty > 0))'    # filter inside an array
```

Inspect keys and membership.

| Filter | Purpose |
| --- | --- |
| `keys` | sorted array of object keys |
| `has("field")` | true if the key exists |
| `length` | element or string count |
| `to_entries` | object to array of key/value pairs |
| `from_entries` | array of pairs back to an object |

Reshape objects.

```bash
jq '.config | to_entries | map(.value) | from_entries'
jq '{name, id}'                          # keep only two fields
jq '{label: .name, count: (.items | length)}'   # build a new object
```

Output modes.

```bash
jq -r '.name'              # raw strings, no quotes
jq -c '.'                  # compact, one line per value
jq -r '.items[] | [.id, .name] | @csv'   # CSV rows
jq -r '@base64'            # base64-encode a value
```

Inject external values safely.

```bash
jq --arg host "$HOSTNAME" '.host = $host'
jq --argjson limit 10 '.items[:$limit]'
```

## Common workflows

Pull one field from an API response.

```bash
curl -s https://api.example.com/user | jq -r '.email'
```

Turn a JSON array into a CSV report.

```bash
curl -s https://api.example.com/orders \
  | jq -r '.orders[] | [.id, .customer, .total] | @csv' > orders.csv
```

Filter log lines and count errors by code.

```bash
cat events.jsonl \
  | jq -c 'select(.level == "error")' \
  | jq -s 'group_by(.code) | map({code: .[0].code, n: length})'
```

Build a request body from shell variables without string concatenation.

```bash
jq -n --arg name "$NAME" --argjson qty "$QTY" \
   '{name: $name, qty: $qty}' \
  | curl -s -H "Content-Type: application/json" -d @- https://api.example.com/items
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `-r` | raw output, strings without quotes |
| `-c` | compact output, one value per line |
| `-n` | start with null input, build from scratch |
| `-s` | slurp all inputs into one array |
| `-e` | set exit code from the last output |
| `--arg name val` | pass a string variable into the program |
| `--argjson name val` | pass a parsed JSON value into the program |

String interpolation uses `\(...)` inside a string, for example `jq -r '"\(.name): \(.id)"'`. Use `@csv`, `@tsv`, `@base64`, and `@sh` to format output for a specific consumer.

## Security notes

Treat JSON from the network as untrusted input. Use `has()` and `select()` to confirm a field exists and matches the expected shape before using it, rather than assuming structure. A missing key yields `null`, which can silently corrupt downstream logic if you do not check for it.

The real footgun is building shell commands from `jq` output. Interpolating a value straight into a command line lets an attacker-controlled field inject shell metacharacters and run arbitrary commands (CWE-78, OS command injection). Consider the unsafe pattern:

```bash
# unsafe: a crafted .name can break out of the quotes
eval "useradd $(jq -r '.name' input.json)"
```

Do not pass JSON-derived strings through `eval` or an unquoted expansion. When a value must become a shell token, use the `@sh` formatter, which quotes each value for the shell:

```bash
jq -r '@sh "useradd \(.name)"' input.json   # value is shell-quoted
```

When feeding values back into another jq program or an API body, prefer `--arg` and `--argjson` over string building, so jq parses and escapes the value instead of splicing raw text. Always quote shell variables that hold jq output. See /SECURE_CODING_REFERENCE.md for command-injection and input-validation guidance.

## Resources

- The `jq(1)` man page, installed with jq.
- The jq Manual, the official filter and builtin reference.
- The jq project wiki with a cookbook of recipes.

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/curl.md
- /commands/linux-commands.md
- /commands/powershell-commands.md
