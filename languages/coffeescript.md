# CoffeeScript

CoffeeScript is a language that compiles to JavaScript, created by Jeremy Ashkenas and first released in 2009. It offers a terser, indentation-based syntax influenced by Ruby and Python, and it has no run-time of its own: the compiler produces readable JavaScript that runs in browsers and in Node.js. It was widely used in the early 2010s, especially in the Ruby on Rails community, and its ideas influenced later JavaScript editions.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: same as JavaScript, with lighter syntax |
| Typing | Dynamic, weak; inherits JavaScript's type behavior |
| First appeared | 2009 |
| Memory model | Automatic: inherits the host JavaScript engine's garbage collection |
| Reference implementation | [CoffeeScript compiler](https://github.com/jashkenas/coffeescript) |
| Typical uses | Front-end and Node.js code, historically in Rails projects |
| Governance | Community maintainers on [GitHub](https://github.com/jashkenas/coffeescript) |

Related: [JavaScript](/languages/javascript.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Jeremy Ashkenas released CoffeeScript in 2009 to smooth over the parts of JavaScript that developers found awkward at the time: verbose function syntax, confusing equality rules, and `var` scoping. It compiles one-to-one to JavaScript that a person can read, following the slogan that it is "just JavaScript" underneath. Ruby on Rails shipped CoffeeScript support by default for several years, which drove much of its adoption.

Several of its ideas, such as arrow functions, destructuring, default parameters, and classes, were later standardized in ECMAScript 2015. As modern JavaScript and TypeScript absorbed those features, new CoffeeScript adoption declined, though the compiler is maintained and existing code remains in use. Understanding it matters mainly for reading and maintaining older codebases.

## Paradigm and type system

CoffeeScript has no type system of its own and no run-time semantics beyond what it compiles to; it is dynamically and weakly typed exactly as JavaScript is. Its contribution is syntax: significant indentation instead of braces, implicit returns, a comprehension syntax for loops, and an existential operator `?` for null and undefined checks. Classes compile to JavaScript prototypes (or ES classes in CoffeeScript 2).

```coffeescript
total = (prices, tax = 0) ->
  (prices.reduce ((sum, p) -> sum + p), 0) * (1 + tax)
```

## Toolchain and ecosystem

- Compiler: the `coffee` command compiles `.coffee` files to JavaScript and can run them directly through Node.js.
- Packaging: CoffeeScript code uses the npm registry and the JavaScript ecosystem; the compiler itself installs from npm.
- Integration: build tools compile CoffeeScript as a step; CoffeeScript 2 targets modern JavaScript output.
- There is no separate linter ecosystem of note today; projects lint the compiled JavaScript with [ESLint](https://eslint.org/) or rely on the compiler's errors.

```bash
npm install --global coffeescript
coffee --compile script.coffee   # emit script.js
```

## Syntax tour

```coffeescript
# Variables need no keyword; the compiler scopes them
name = "world"
console.log "hello, #{name}"      # string interpolation

# Comprehensions replace many loops
squares = (n * n for n in [0..4]) # [0, 1, 4, 9, 16]
lookup = { a: 1, b: 2 }

# Functions use -> ; implicit return of the last expression
greet = (who, excited = false) ->
  tail = if excited then "." else "."
  "hi #{who}#{tail}"

# Classes
class Point
  constructor: (@x, @y) ->       # @x assigns to this.x

# The existential operator guards null and undefined
value = input ? 0

# Conditions read as English
console.log "matched" if name is "world"   # is compiles to ===
```

## Idioms and different approaches

- Rely on implicit returns: the last expression in a function is its return value, so explicit `return` is rare.
- Use comprehensions (`x for x in list`) instead of manual loops for transformations.
- Use `is` and `isnt`, which compile to strict `===` and `!==`, so the coercion traps of `==` do not arise.
- Use the existential operator `?` and `?.` to handle missing values concisely.
- The `@` shorthand stands for `this`, and `(@x, @y)` in a constructor assigns parameters to instance properties.

## Design principles

CoffeeScript's design goal was to expose "the good parts" of JavaScript with less syntax and fewer footguns, while compiling to JavaScript that stays readable and debuggable. It deliberately avoided adding a run-time or a standard library, so there is nothing to ship to the browser beyond the compiled output. The project's influence is visible in modern JavaScript, which adopted many of the same ergonomic features, and that success is part of why its own usage has since narrowed.

## Standard library and notable packages

CoffeeScript has no standard library of its own; it uses JavaScript's built-ins and any npm package. Historically it appeared alongside [Backbone.js](https://backbonejs.org/) and jQuery in the client applications of its era, and within [Ruby on Rails](https://rubyonrails.org/) asset pipelines. New libraries are rarely written in it today, so most code pairs it with the same JavaScript ecosystem described on the [JavaScript](/languages/javascript.md) page.

## Testing and packaging

Testing uses the JavaScript runners; [Mocha](https://mochajs.org/) was common in CoffeeScript's peak years and can load `.coffee` test files through a register hook.

```coffeescript
assert = require "assert"

describe "addition", ->
  it "works", ->
    assert.strictEqual 2 + 3, 5
```

A distributable package compiles to JavaScript before publishing to npm, so consumers never need the CoffeeScript compiler; `package.json` points at the compiled entry file.

## Performance and concurrency

CoffeeScript has no run-time of its own, so its performance and concurrency are exactly those of the JavaScript it compiles to: just-in-time compiled execution on an engine such as V8, with a single-threaded event loop and asynchronous I/O (see [JavaScript](/languages/javascript.md)). The compile step adds build time but no run-time cost. Because the output is plain JavaScript, workers and asynchronous patterns are written against the compiled result just as in any JavaScript project.

## Common pitfalls

- Significant whitespace means indentation errors change meaning silently; keep indentation consistent and avoid mixing tabs and spaces.
- Implicit returns can return a value you did not intend (for example the result of a comprehension); add an explicit `return` or a trailing statement when the return value matters.
- Everything is an expression, so constructs such as `if` return values; this is convenient but can surprise readers coming from JavaScript.
- Debugging runs against compiled JavaScript; use source maps so stack traces point back to the `.coffee` source.
- The language is in maintenance rather than active growth; weigh that before choosing it for new work.

## Secure coding

CoffeeScript compiles to JavaScript, so every JavaScript risk applies to the output, and the lighter syntax does not change the security model:

- Cross-site scripting: the same DOM sinks (`innerHTML`, `document.write`) are dangerous in compiled output; insert untrusted data as text, not markup. This maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Code injection: `eval` and `new Function` remain unsafe when fed untrusted input, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Prototype pollution: merging untrusted data into objects can poison prototypes just as in JavaScript, which maps to [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html).
- Server-side injection: in Node.js, use parameterized queries ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) and argument arrays for `child_process` ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)).
- Dependency supply chain: the project depends on the npm ecosystem; pin and audit dependencies. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: because security analyzers target JavaScript, lint and scan the compiled output with [ESLint](https://eslint.org/) and [semgrep](https://semgrep.dev/) rather than the CoffeeScript source. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) and [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [CoffeeScript documentation](https://coffeescript.org/), the official site with a live compiler.
- [The CoffeeScript source repository](https://github.com/jashkenas/coffeescript), for the compiler and changelog.
- [JavaScript](/languages/javascript.md), the language it compiles to and the one to learn alongside it.

## Related pages

- [JavaScript](/languages/javascript.md)
- [TypeScript](/languages/typescript.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
