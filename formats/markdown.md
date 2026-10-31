# Markdown

Markdown is a lightweight markup language that formats plain text with a small set of punctuation conventions. It reads cleanly as source and converts to HTML for display. It is the default format for README files, documentation, issue trackers, chat, and static site generators. Because most renderers allow embedded raw HTML, rendering untrusted Markdown carries the same risks as rendering untrusted HTML.

## What it is and where it is used

Markdown lets authors write structured text without tags. A processor reads the Markdown and emits HTML, which a browser then renders.

It is used in code repositories, wikis, forums, note applications, and content pipelines. Its portability comes from the source staying readable even when no renderer is present.

## Syntax and structure

Headings use leading `#` characters, one per level.

```markdown
# Title
## Section
### Subsection
```

Emphasis uses asterisks or underscores. One marker is italic, two are bold.

```markdown
*italic* and _italic_
**bold** and __bold__
```

Lists are unordered with `-`, `*`, or `+`, and ordered with numbers.

```markdown
- first
- second

1. step one
2. step two
```

Links wrap link text in square brackets followed by the target in parentheses. Images use the same form with a leading `!`.

```markdown
[Specification](https://example.com/spec)
![Diagram alt text](diagram.png)
```

Inline code uses single backticks. Fenced code blocks use three backticks and an optional language tag for highlighting.

````markdown
Use `npm install` to begin.

```python
def greet(name):
    return f"Hello {name}"
```
````

Tables, a flavor extension, use pipes and a divider row.

```markdown
| Format | Extension |
| ------ | --------- |
| JSON   | .json     |
| YAML   | .yaml     |
```

Flavors differ. The original Markdown, CommonMark, and GitHub Flavored Markdown disagree on tables, task lists, autolinks, and raw HTML handling. Write for the renderer you target, and test there.

## A worked example

```markdown
# Deployment runbook

A short guide to shipping the service.

## Prerequisites

- Access to the staging cluster
- The `deploy` CLI, version 2 or later

## Steps

1. Build the image:

   ```bash
   deploy build --tag release
   ```

2. Promote to staging and watch the logs.
3. If checks pass, promote to production.

## Rollback

If a check fails, run `deploy rollback`. See the [incident guide](https://example.com/incident-guide)
for the escalation path.

| Environment | Branch  | Auto-deploy |
| ----------- | ------- | ----------- |
| staging     | main    | yes         |
| production  | release | no          |
```

## Tooling

CommonMark reference implementations, `cmark` and `markdown-it`, parse Markdown predictably. `marked` and Python-Markdown are widely used renderers.

Linters such as `markdownlint` enforce style and catch malformed structure. Formatters such as Prettier normalize spacing and list markers. Sanitizers such as DOMPurify and `sanitize-html` clean the rendered output.

## Security considerations

Markdown is a cross-site scripting vector (CWE-79). Most renderers pass raw HTML through unchanged, so `<script>` tags and inline event handlers in Markdown source reach the DOM and execute.

Rendering untrusted Markdown without sanitization is unsafe. Do not trust source from users, comments, or external documents. The rendered HTML, not the Markdown, is where the danger lands.

Links are a specific hazard. A `[click](javascript:alert(1))` link produces a `javascript:` URL that runs script when followed. Image sources can carry the same scheme. Enforce an allowlist of URL schemes such as `http`, `https`, and `mailto`.

Sanitize the rendered HTML with a vetted allowlist library after rendering, as a distinct step. Where the renderer offers it, disable raw HTML pass-through and enable safe-link modes, then still sanitize.

Markdown can also be used for interface deception. Crafted link text that differs from the target, or images loaded from attacker origins, can mislead users or leak referrer data. Review link targets and constrain remote image loading.

See /SECURE_CODING_REFERENCE.md for input validation, output encoding, and the sanitize-then-render pattern that applies to any format that compiles to HTML.

## Resources

John Gruber's original Markdown description defines the base syntax. The CommonMark specification gives a precise, testable grammar. The GitHub Flavored Markdown specification extends CommonMark with tables, task lists, strikethrough, and autolinks.

## Related pages

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /formats/html.md
- /formats/css.md
- /formats/xml.md
