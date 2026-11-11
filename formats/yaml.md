# YAML

YAML (YAML Ain't Markup Language) is a text format for structured data that favors human readability. It uses indentation instead of brackets and supports scalars, lists, and maps. It is common in configuration and infrastructure tooling. Its flexibility makes it convenient but also creates several sharp edges.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers, engineers and analysts who read, write or parse YAML

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (902 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are reading or writing YAML by hand or in code, you want a worked example and the tools that handle it, or you are parsing untrusted input and need its security considerations

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax and structure](#syntax-and-structure), [A worked example](#a-worked-example), [Security considerations](#security-considerations)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [JSON](/formats/json.md), [TOML](/formats/toml.md), [XML](/formats/xml.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it is used

YAML encodes the same data model as JSON (every JSON document is valid YAML) with a layout meant for people to edit by hand. Significant whitespace replaces most punctuation.

Common uses include:

- Application and service configuration files.
- Kubernetes manifests and Helm charts.
- CI pipeline definitions such as GitHub Actions and GitLab CI.
- Ansible playbooks and other infrastructure-as-code.
- OpenAPI and other API description documents.

YAML is chosen where a human reads and edits the file often. That human focus is also where its risks begin.

## Syntax and structure

Indentation with spaces (never tabs) defines structure. Each nesting level is indented further than its parent.

A mapping is a set of key and value pairs. A colon and a space separate each key from its value.

```yaml
name: web-service
replicas: 3
enabled: true
```

A sequence is a list. Each item begins with a dash and a space.

```yaml
ports:
  - 80
  - 443
```

Scalars are plain, single-quoted, or double-quoted. Plain scalars need no quotes but are subject to type guessing. The literal block scalar `|` keeps newlines; the folded block scalar `>` joins lines with spaces.

```yaml
description: |
  Line one kept.
  Line two kept.
summary: >
  These lines are
  folded into one.
```

Anchors and aliases reuse a node. An anchor `&name` marks a node, and an alias `*name` references it. A merge key `<<` pulls one map into another.

```yaml
defaults: &defaults
  retries: 3
  timeout: 30
service:
  <<: *defaults
  timeout: 60
```

Tags set an explicit type with `!!`, for example `!!str 1.0`. A document starts with `---` and ends with `...`. One stream can hold several documents.

```yaml
---
env: staging
---
env: production
```

## A worked example

This file configures a service with shared defaults, a list, and a multi-line value.

```yaml
---
service:
  name: billing-api
  version: "2.0"
  defaults: &health
    interval: 10
    retries: 3
  liveness:
    <<: *health
    path: /healthz
  regions:
    - us-east-1
    - eu-west-1
  notes: |
    Scales on CPU above 70 percent.
    Owned by the platform team.
```

The version is quoted so it stays a string and is not read as the number `2.0`. The `liveness` check inherits `interval` and `retries` through the merge key, then overrides nothing here. The `notes` block keeps its line breaks.

## Tooling

- `yamllint` checks style and catches indentation and duplicate-key problems.
- Language libraries include PyYAML and ruamel.yaml in Python, SnakeYAML in Java, and go-yaml in Go.
- `kubeconform` and `kubeval` validate Kubernetes YAML against schemas.
- Editors with YAML language servers flag structural errors as you type.

In PyYAML, always call `yaml.safe_load`, never `yaml.load` with the default loader. Other libraries have an equivalent safe mode; prefer it.

## Security relevance

This section is the threat-facing view of YAML: why an unsafe loader is a direct path to code execution and where that is reached. The safe-loader and limit settings that defend against these are in the "Security considerations" section that follows.

### Where it appears

- Infrastructure as code. Kubernetes manifests, Helm charts, and Ansible playbooks are YAML, so a loader processing a supplied manifest handles attacker-influenced input.
- CI and CD pipelines. GitHub Actions and GitLab CI read YAML, and a workflow file in a pull request is untrusted input to the parser that reads it.
- Application and API config. Services and OpenAPI tooling load YAML, bringing untrusted documents to whichever loader the library defaults to.

### Dominant weakness classes

YAML is text, so the risk is not memory corruption but what the loader is allowed to do while building objects from the document.

- Deserialization of untrusted data ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)), where a loader that honors tags such as `!!python/object/apply` constructs arbitrary objects or invokes code, turning a parsed document into code execution.
- Uncontrolled resource consumption ([CWE-400](https://cwe.mitre.org/data/definitions/400.html)) through nested anchors and aliases that expand a tiny input into an enormous structure, the billion-laughs attack adapted to YAML.
- Incorrect type conversion ([CWE-704](https://cwe.mitre.org/data/definitions/704.html)) when plain scalars are guessed into the wrong type, so a value an attacker controls can flip meaning between parsers.

### Why it matters

Recognizing a YAML sink tells a tester to check which loader is used and to try an object-instantiating tag and an alias-expansion payload, because the default loader in some libraries is still unsafe. See [the secure coding reference](/SECURE_CODING_REFERENCE.md) for the surrounding method.

## Security considerations

YAML's convenience features are also its most serious risks. See `/SECURE_CODING_REFERENCE.md` for deserialization and input guidance.

- Unsafe deserialization. Some loaders honor tags that construct arbitrary language objects or invoke code, for example `!!python/object/apply`. Loading untrusted YAML with such a loader can run attacker code. Always use a safe loader that returns only plain scalars, lists, and maps. Reference CWE-502 (Deserialization of Untrusted Data).
- Entity and alias expansion denial of service. Nested anchors and aliases can be expanded into an enormous structure from a tiny input. This is the billion-laughs attack adapted to YAML, where each alias references several of the one below it. Cap alias depth and total node count, and reject inputs that exceed a size budget. Reference CWE-776 (Improper Restriction of Recursive Entity References) and CWE-400 (Uncontrolled Resource Consumption).
- Type coercion surprises. Plain scalars are guessed into types. The Norway problem is the classic case: `NO` (a country code) parses as the boolean `false` under YAML 1.1 rules. Values like `yes`, `off`, `01`, and `1.0` can also change type. Quote any scalar whose string value matters, and prefer parsers that follow YAML 1.2 core schema. Reference CWE-704 (Incorrect Type Conversion or Cast).
- Duplicate keys. A repeated mapping key is handled inconsistently across parsers. Enable duplicate-key detection in your linter and loader so a silent override cannot hide a change.

## Resources

- The YAML 1.2 specification.

## Related pages

- [Data formats and regular expressions](/formats/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [JSON](/formats/json.md)
- [TOML](/formats/toml.md)
- [XML](/formats/xml.md)
