# XML

XML (Extensible Markup Language) is a text format for structured, hierarchical documents. It uses nested tagged elements with attributes to describe data and its relationships. It predates JSON and remains common in enterprise systems, documents, and configuration. Its support for external entities and document type definitions is the source of its best-known vulnerabilities.

## What it is and where it is used

XML marks up data with tags so that structure and content travel together. It is verbose compared with JSON but supports namespaces, schemas, and mixed content.

Common uses include:

- SOAP web services and many enterprise integrations.
- Document formats such as Office Open XML (`.docx`) and SVG.
- Configuration files, for example Maven `pom.xml` and Spring beans.
- Data feeds such as RSS and Atom.
- Security assertions such as SAML.

XML is chosen where documents are complex, schemas are enforced, or an existing standard requires it.

## Syntax and structure

An XML document has one root element that contains all others. Elements nest to form a tree. Each element has a start tag and a matching end tag, or is written as a self-closing empty tag.

```xml
<book>
  <title>Secure Parsing</title>
  <chapter/>
</book>
```

Attributes are name and value pairs in the start tag. Values are always quoted.

```xml
<user id="42" role="admin">Ada</user>
```

An optional prolog declares the version and encoding. Namespaces qualify names with a prefix bound by `xmlns` to avoid collisions between vocabularies.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ns:order xmlns:ns="https://example.com/orders">
  <ns:id>A-100</ns:id>
</ns:order>
```

A document is well-formed when tags are balanced, nested correctly, and properly quoted. Five entities are predefined: `&lt;`, `&gt;`, `&amp;`, `&quot;`, and `&apos;`. Character data that should not be parsed goes in a `CDATA` section.

```xml
<note>Use &lt;b&gt; for bold.</note>
<script><![CDATA[ if (a < b) run(); ]]></script>
```

A Document Type Definition (DTD) can declare elements and custom entities. Schemas such as XSD or RELAX NG impose stronger, typed constraints than a DTD. Both are optional.

```xml
<!DOCTYPE note [
  <!ENTITY company "Example Corp">
]>
<note>&company;</note>
```

## A worked example

This well-formed document uses a namespace, attributes, nested elements, and a predefined entity.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<inv:invoice xmlns:inv="https://example.com/inv" number="A-10294">
  <inv:customer id="42">Ada &amp; Co.</inv:customer>
  <inv:lines>
    <inv:line sku="KB-01" qty="1">99.99</inv:line>
    <inv:line sku="CA-07" qty="2">15.00</inv:line>
  </inv:lines>
  <inv:paid>true</inv:paid>
</inv:invoice>
```

The ampersand in the customer name is escaped as `&amp;` so the document stays well-formed. Prices are element text, and quantities are attributes; a schema would pin down which is which and their types.

## Tooling

- `xmllint` validates and formats XML and checks it against a DTD or schema.
- Parsers include DOM (whole tree in memory), SAX and StAX (streaming), and language libraries such as lxml in Python.
- XPath selects nodes; XSLT transforms one document into another.
- Schema tools validate against XSD or RELAX NG.

Choose a streaming parser for large or untrusted input, and configure the parser securely before you read anything, as described below.

## Security considerations

XML parsers are dangerous in their default configuration because many resolve external entities. See `/SECURE_CODING_REFERENCE.md` and the cheat sheet named below.

- XML external entity (XXE) injection. A DTD can define an entity that points at a local file or a URL, for example `<!ENTITY x SYSTEM "file:///etc/passwd">`. A parser that resolves it leaks file contents or performs server-side requests (SSRF). Disable DTD processing entirely, or at minimum disable external general and parameter entities. Reference CWE-611 (Improper Restriction of XML External Entity Reference).
- Entity expansion denial of service. The billion-laughs attack defines nested entities where each one references several of the next, expanding a few lines into gigabytes. Disable DTDs, or cap entity expansion and total document size. Reference CWE-776 (Improper Restriction of Recursive Entity References) and CWE-400 (Uncontrolled Resource Consumption).
- XML injection. Building XML by concatenating untrusted strings lets an attacker inject tags or break structure, which can alter the parsed meaning. Always serialize through a library that escapes content, and validate against a schema. Reference CWE-91 (XML Injection).
- XPath injection. Concatenating user input into an XPath query lets an attacker change the query logic and read nodes they should not. Use parameterized XPath or a precompiled expression with variable binding, and validate input. Reference CWE-643 (Improper Neutralization of Data within XPath Expressions).

The safe baseline: disable DTD processing and external entity resolution on every parser, reject documents that declare a `DOCTYPE`, and set size and depth limits.

## Resources

- The W3C Extensible Markup Language (XML) 1.0 specification.
- The OWASP XML External Entity Prevention Cheat Sheet.

## Related pages

- `/formats/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/formats/json.md`
- `/formats/yaml.md`
- `/formats/html.md`
