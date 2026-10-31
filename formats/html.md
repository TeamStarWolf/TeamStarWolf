# HTML

HyperText Markup Language is the markup language that describes the structure and content of web pages. Browsers parse it into a tree of nodes called the Document Object Model. Every page a user loads begins as an HTML document, with CSS and JavaScript applied on top. It is the primary surface where untrusted data meets executable context, so its security properties matter to every web application.

## What it is and where it is used

HTML describes documents as a hierarchy of elements. Each element has a meaning, such as a heading, a paragraph, a link, or a form control. The browser reads the markup, builds the DOM, and renders the result.

HTML appears in static pages, server-rendered templates, single-page application shells, email bodies, and documentation. Any system that produces output viewed in a browser produces HTML, directly or through a templating layer.

## Syntax and structure

An element is written with a start tag, content, and an end tag. Some elements are void and have no content or end tag, such as `<br>` and `<img>`.

```html
<p>A paragraph of text.</p>
<img src="logo.png" alt="Company logo">
```

Elements carry attributes as name and value pairs inside the start tag. Attribute values should be quoted.

```html
<a href="https://example.com" title="Example">Visit</a>
<input type="email" name="address" required>
```

A document declares its type, then nests a `<head>` for metadata and a `<body>` for visible content.

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Page title</title>
  </head>
  <body>
    <h1>Heading</h1>
  </body>
</html>
```

Semantic elements name the role of a region. `<header>`, `<nav>`, `<main>`, `<article>`, `<section>`, and `<footer>` convey structure to assistive technology and to search engines. They replace generic `<div>` containers where a meaning exists.

Forms collect input. A `<form>` wraps controls such as `<input>`, `<textarea>`, `<select>`, and `<button>`. The `action` attribute sets the submission target and `method` sets the HTTP verb.

```html
<form action="/subscribe" method="post">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required>
  <button type="submit">Subscribe</button>
</form>
```

The DOM is the live, in-memory representation of the parsed document. Scripts read and change the DOM through interfaces such as `document.querySelector` and `element.textContent`. Changes to the DOM update what the browser renders.

## A worked example

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Reading list</title>
  </head>
  <body>
    <header>
      <h1>Reading list</h1>
    </header>
    <main>
      <section aria-labelledby="pending">
        <h2 id="pending">Pending</h2>
        <ul>
          <li><a href="/books/1">The grammar of markup</a></li>
          <li><a href="/books/2">Parsing in practice</a></li>
        </ul>
      </section>
      <section aria-labelledby="add">
        <h2 id="add">Add a book</h2>
        <form action="/books" method="post">
          <label for="title">Title</label>
          <input id="title" name="title" type="text" required>
          <button type="submit">Save</button>
        </form>
      </section>
    </main>
    <footer>
      <p>Last updated today.</p>
    </footer>
  </body>
</html>
```

## Tooling

The W3C Nu Html Checker validates markup against the living standard. `html-validate` and `vnu.jar` run validation in continuous integration.

Formatters such as Prettier normalize indentation and attribute wrapping. Linters such as `htmlhint` and `eslint-plugin-html` catch structural errors and inline script issues.

Sanitization libraries, including DOMPurify and the server-side `sanitize-html`, strip dangerous markup from untrusted input before it reaches the DOM. Treat these as security controls, not formatters.

## Security considerations

HTML is the main vector for cross-site scripting (CWE-79). When an application inserts untrusted data into markup without encoding, an attacker can inject script that runs in the victim's session.

Encode output for the context where it lands. HTML body context, attribute context, URL context, and JavaScript context each need a different encoding. A value safe in one context can be dangerous in another.

Never render untrusted HTML as trusted markup. Setting `innerHTML` or using a template's raw-output helper on attacker-controlled data executes injected script. Prefer `textContent` and auto-escaping template engines.

When an application must accept HTML from users, sanitize it with a vetted allowlist library before insertion. Do not write your own tag stripper; parsing differentials defeat naive filters.

Dangerous sinks include `javascript:` URLs in `href` and `src`, inline event handler attributes such as `onerror`, and `<script>`, `<iframe>`, and `<object>` elements. Validate and constrain these.

Set a `Content-Security-Policy` header to reduce the impact of injection. A policy that forbids inline script and restricts source origins turns many injection attempts into blocked loads. Treat it as defense in depth, not a replacement for encoding.

See /SECURE_CODING_REFERENCE.md for output encoding and input validation practice, and /WEB_APPLICATION_SECURITY_REFERENCE.md for cross-site scripting, Content Security Policy, and related web controls in depth.

## Resources

The WHATWG HTML Living Standard is the authoritative specification. MDN Web Docs documents elements, attributes, and the DOM with current browser behavior. The OWASP Cross-Site Scripting Prevention Cheat Sheet gives context-specific encoding rules.

## Related pages

- /formats/README.md
- /SECURE_CODING_REFERENCE.md
- /WEB_APPLICATION_SECURITY_REFERENCE.md
- /formats/css.md
- /formats/markdown.md
- /formats/xml.md
