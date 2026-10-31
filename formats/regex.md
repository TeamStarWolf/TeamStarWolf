# Regular Expressions

Regular expressions are a notation for describing sets of strings through patterns. An engine matches a pattern against input to find, extract, validate, or replace text. They appear in search tools, editors, log pipelines, input validators, and data-extraction code across nearly every language. They are a format for expressing text patterns, not a data serialization format.

## What it is and where it is used

A regular expression (regex) is a compact string that encodes a matching rule. The engine reads the pattern, builds an internal matcher, and runs it over input text. A match can report whether the input conforms, where a substring sits, or what captured groups contain.

Common uses:

- Validating structured input such as identifiers, dates, or postal codes.
- Extracting fields from logs, configuration, and semi-structured text.
- Search-and-replace in editors and in tools like `grep` and `sed`.
- Tokenizing source during lexing and parsing.
- Routing and rewriting in web servers and firewalls.

Regex suits token-level patterns. It cannot parse recursively nested structures such as arbitrary JSON or HTML; use a real parser for those.

## Syntax and constructs

**Literals** match themselves. The pattern `cat` matches the three characters `c`, `a`, `t` in order.

**Metacharacters** carry special meaning: `. ^ $ * + ? ( ) [ ] { } | \`. Escape a metacharacter with a backslash to match it literally.

```
\.        matches a literal dot
\$        matches a literal dollar sign
```

**The dot** `.` matches any single character except a newline, unless the dotall flag is set.

```
a.c       matches "abc", "a9c", "a-c"
```

**Character classes** list allowed characters inside brackets. A range uses a hyphen. A leading `^` negates the class.

```
[aeiou]       one lowercase vowel
[a-z0-9]      one lowercase letter or digit
[^0-9]        one character that is not a digit
```

Shorthand classes cover frequent sets:

```
\d  a digit            \D  a non-digit
\w  a word character   \W  a non-word character
\s  whitespace         \S  non-whitespace
```

**Anchors** match a position, not a character.

```
^abc      "abc" at the start of the line or string
abc$      "abc" at the end of the line or string
\bword\b  "word" bounded by word boundaries
```

**Quantifiers** repeat the preceding element.

```
a*        zero or more "a"
a+        one or more "a"
a?        zero or one "a"
a{3}      exactly three "a"
a{2,4}    two to four "a"
a{2,}     two or more "a"
```

Quantifiers are greedy by default: they match as much as possible, then give back characters if the rest of the pattern fails. A trailing `?` makes a quantifier lazy, matching as little as possible first.

```
<.+>      greedy: on "<a><b>" matches the whole "<a><b>"
<.+?>     lazy:   on "<a><b>" matches only "<a>"
```

Possessive quantifiers (`a++`, `a*+`, `a{2,4}+`) match greedily and never give characters back. They prevent some backtracking and can stop runaway matching, but not all engines support them.

**Groups** use parentheses. A capturing group records its match for reuse. A non-capturing group `(?:...)` groups without capturing.

```
(ab)+         one or more "ab", captured in group 1
(?:ab)+       same repetition, no capture
(?<year>\d{4})  named capture group "year"
```

**Backreferences** match text already captured.

```
(['"]).*?\1   a quote, then text, then the same quote
```

**Alternation** `|` matches one of several options. It has low precedence, so group it when needed.

```
cat|dog       "cat" or "dog"
gr(a|e)y      "gray" or "grey"
```

**Lookaround** asserts context without consuming characters.

```
foo(?=bar)    "foo" only when followed by "bar"
foo(?!bar)    "foo" only when not followed by "bar"
(?<=\$)\d+    digits only when preceded by "$"
(?<!\$)\d+    digits only when not preceded by "$"
```

**Flags** change matching behavior. Syntax varies: inline `(?i)`, a trailing `/pattern/i`, or an engine argument.

```
i   case-insensitive
m   multiline: ^ and $ match at line breaks
s   dotall: . also matches newline
x   extended: ignore whitespace and allow comments
g   global: find all matches (tool- or binding-specific)
```

## A worked example

Extract a key-value pair from a log line.

```
(?<key>\w+)=(?<value>[^;]+)
```

On `user=alice;role=admin` the first match captures `key` as `user` and `value` as `alice`. The `[^;]+` stops at the delimiter so one field is captured at a time.

A pattern for an email-like token, suitable for a first-pass filter, not full validation:

```
[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
```

This matches a local part, an `@`, a domain, and a top-level label of at least two letters. It accepts `alice@example.com` and rejects `alice@@example`.

Validating email fully by regex is a known trap. The real grammar in RFC 5322 permits quoted local parts, comments, and nested constructs that a single readable pattern cannot capture. Attempts to cover every case grow unreadable and still miss edge cases. Prefer a simple pattern for shape, then confirm deliverability by sending a verification message.

## Engines and flavors

Regex dialects differ in syntax and in matching algorithm.

**POSIX BRE** (basic regular expressions) is the older `grep` syntax. Metacharacters `(`, `)`, `{`, and `}` are literal unless escaped as `\(`, `\)`, `\{`, `\}`. There is no `+` or `?` as a quantifier without escaping in strict BRE.

**POSIX ERE** (extended regular expressions), used by `grep -E` and `egrep`, treats `(`, `)`, `+`, `?`, and `|` as metacharacters directly. POSIX engines follow leftmost-longest matching and typically lack lookaround and backreferences.

**PCRE** (Perl Compatible Regular Expressions) is the feature-heavy family used by Perl, PHP, and many others. It adds lazy and possessive quantifiers, lookaround, named groups, and backreferences. Most of these features need a backtracking engine.

**RE2** is a Google engine that guarantees linear-time matching in the input length. It uses automaton-based matching and refuses features that require backtracking, so it has no backreferences and no general lookaround. Go's standard `regexp` package and RE2 bindings in other languages share this model.

Language standard libraries vary:

- Python `re` is backtracking and PCRE-like; the third-party `regex` module adds more features.
- JavaScript `RegExp` is backtracking with lookbehind in current engines.
- Java `java.util.regex` is backtracking with possessive quantifiers.
- Go `regexp` is RE2-based and linear-time.
- Rust `regex` is automaton-based and linear-time, like RE2.

**Backtracking versus automaton-based:** a backtracking engine tries one path, and on failure returns to a saved choice point to try another. This supports backreferences and lookaround but can take exponential time on some patterns. An automaton-based engine (NFA or DFA simulation) tracks all possible states at once, running in time proportional to input length, at the cost of those features.

## Security considerations

**Regular expression denial of service (ReDoS)** is the main risk, classified as CWE-1333, inefficient regular expression complexity. A backtracking engine can take time that grows exponentially with input length on certain patterns. A short malicious string then stalls a thread or process.

Pattern shapes that cause catastrophic backtracking:

- Nested quantifiers, such as `(a+)+` or `(a*)*`, over a long run of `a` followed by a non-matching character.
- Overlapping alternation under a quantifier, such as `(a|a)*` or `(a|ab)+`.
- Adjacent quantifiers on overlapping classes, such as `\d+\d+` or `.*.*$`.

Two trigger paths matter. With an untrusted pattern, an attacker supplies the regex, so any dangerous shape is possible; never compile a regex from untrusted input without a safe engine. With untrusted input against a fixed pattern, an attacker supplies a crafted string that forces the worst case in a vulnerable pattern; audit patterns that run on request data.

Mitigations:

- Use a linear-time engine such as RE2, Go `regexp`, or Rust `regex` for untrusted input or untrusted patterns.
- Cap input length before matching so worst-case work stays bounded.
- Apply a match timeout or step limit where the engine or runtime supports one.
- Avoid nested quantifiers and overlapping alternation; rewrite them with atomic groups, possessive quantifiers, or a more specific class.
- Test patterns with adversarial strings, not only valid examples.

**Using regex to detect secrets:** scanners match patterns for API keys, tokens, and private key headers. This is useful for flagging obvious leaks, but regex alone produces false positives on random-looking strings and false negatives on novel formats. Treat regex secret detection as one signal, paired with entropy checks and provider-specific verification, not as proof. See `/SECURE_CODING_REFERENCE.md` for input-validation and denial-of-service guidance.

## Tooling

**Testers and debuggers** fall into categories. Interactive web testers show matches, groups, and an explanation of each token as you type. Visualizers draw the pattern as a railroad diagram. Debuggers step through the match and expose backtracking, which helps locate ReDoS hot spots. Dedicated ReDoS analyzers scan a pattern and report whether it has super-linear worst-case behavior.

**Regex in command-line tools:**

- `grep` uses BRE by default, `grep -E` uses ERE, and `grep -P` uses PCRE where built with it.
- `sed` matches with BRE and substitutes with `s/pattern/replacement/flags`.
- `awk` uses ERE in conditions and the `~` operator.
- `ripgrep` (`rg`) uses the Rust linear-time engine, avoiding ReDoS by design.

**Editors** expose regex find-and-replace with capture-group references such as `$1` or `\1` in the replacement field. Most support toggles for case sensitivity and whole-word matching.

**Linters** catch problems before runtime. ESLint rules flag unsafe regex and control-character classes in JavaScript. Static analyzers and purpose-built scanners detect ReDoS-prone patterns in source across several languages.

## Resources

- Jeffrey E. F. Friedl, *Mastering Regular Expressions*, 2006, O'Reilly.
- The POSIX specification for regular expressions.
- The PCRE documentation.
- The RE2 documentation.

## Related pages

- `/formats/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/formats/json.md`
- `/formats/csv.md`
- `/formats/markdown.md`
