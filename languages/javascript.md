# JavaScript

JavaScript is a dynamically typed, garbage-collected, multi-paradigm language created by Brendan Eich at Netscape in 1995 and standardized as ECMAScript. It began as a scripting language for web browsers and now also runs on servers, desktops, and embedded devices through runtimes such as Node.js. It executes on just-in-time compiling engines (V8, SpiderMonkey, JavaScriptCore) and is used for front-end web development, server back ends, build tooling, and browser-based security testing.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: event-driven, functional, object-oriented (prototype-based) |
| Typing | Dynamic, weak, with implicit coercion |
| First appeared | 1995 |
| Memory model | Automatic: tracing garbage collection |
| Reference implementation / runtime | Engines: [V8](https://v8.dev/), [SpiderMonkey](https://spidermonkey.dev/), [JavaScriptCore](https://developer.apple.com/documentation/javascriptcore); server runtime [Node.js](https://nodejs.org/) |
| Typical uses | Front-end web, server back ends, build tooling, scripting |
| Governance | [ECMAScript (ECMA-262)](https://tc39.es/ecma262/) via TC39 |

Related: [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [TypeScript](/languages/typescript.md), [languages index](/languages/README.md).

## Overview and history

Brendan Eich wrote the first version of JavaScript in ten days in 1995 for the Netscape Navigator browser. Despite the name, it is not related to Java; the name was a marketing decision of the era. The language was standardized as ECMAScript (ECMA-262) in 1997 to give independent browser vendors a shared target. A long gap followed ECMAScript 3, after which ES5 (2009) tightened the language and ES2015 (also called ES6) added classes, modules, arrow functions, promises, and block scoping. Since then TC39 has shipped a yearly edition.

Browsers run JavaScript in engines such as V8 (Chrome), SpiderMonkey (Firefox), and JavaScriptCore (Safari). [Node.js](https://nodejs.org/) embeds V8 to run JavaScript on the server, and newer server runtimes include [Deno](https://deno.land/) and [Bun](https://bun.sh/).

## Paradigm and type system

JavaScript is dynamically and weakly typed: values have types but variables do not, and the language coerces between types during many operations, which is a frequent source of surprise. It has a small set of primitives (`number`, `string`, `boolean`, `bigint`, `symbol`, `undefined`, `null`) and objects. Inheritance is prototype-based: objects delegate to a prototype object, and the `class` keyword added in ES2015 is syntax over that mechanism. For static typing, teams add [TypeScript](/languages/typescript.md), which checks a superset of JavaScript at build time.

```javascript
function total(prices, tax = 0) {
  return prices.reduce((sum, p) => sum + p, 0) * (1 + tax);
}
```

## Toolchain and ecosystem

- Runtime: browsers execute JavaScript directly; [Node.js](https://nodejs.org/) runs it on the server with a `node` command and read-eval-print loop.
- Packaging: libraries publish to the npm registry and install with `npm`, [pnpm](https://pnpm.io/), or [Yarn](https://yarnpkg.com/); `package.json` and a lockfile record dependencies.
- Bundling and building: [Vite](https://vitejs.dev/), [esbuild](https://esbuild.github.io/), and [webpack](https://webpack.js.org/) bundle modules for the browser.
- Formatting and linting: [Prettier](https://prettier.io/) formats; [ESLint](https://eslint.org/) lints and can enforce security rules.

```bash
npm init -y
npm install express
node --check script.js   # syntax check without running
```

## Syntax tour

```javascript
// Variables: prefer const and let over var
const name = "world";
console.log(`hello, ${name}`);

// Arrays and objects
const squares = [0, 1, 2, 3, 4].map((n) => n * n); // [0,1,4,9,16]
const lookup = { a: 1, b: 2 };
const unique = [...new Set([1, 2, 2, 3])];          // [1,2,3]

// Functions, defaults, arrow functions
function greet(who, { excited = false } = {}) {
  return `hi ${who}${excited ? "." : "."}`;
}

// Classes over prototypes
class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

// Asynchronous code with promises and async/await
async function load(url) {
  const response = await fetch(url);
  return response.json();
}

// Errors
try {
  const value = JSON.parse("not json");
} catch (err) {
  // handle
}
```

## Idioms and different approaches

- Use `const` by default and `let` when reassignment is needed; avoid `var`, which is function-scoped and hoisted.
- Use `===` and `!==` (strict equality) rather than `==`, which coerces operands and produces unexpected matches.
- Model asynchronous work with promises and `async`/`await` rather than nested callbacks.
- Use array methods (`map`, `filter`, `reduce`, `forEach`) and the spread and destructuring syntax for data handling.
- Prefer ES modules (`import`/`export`) over the older CommonJS `require` for new code.

## Design principles

JavaScript was shaped by its origin as a browser scripting language that had to stay backward compatible: a page written decades ago should still run, so the language almost never removes features. TC39 evolves it through staged proposals that must ship in multiple engines, which keeps the standard implementable across vendors. The result is a language with historical inconsistencies (type coercion, `this` binding) alongside modern, well-designed additions, where discipline and tooling cover the rough edges.

## Standard library and notable frameworks

The language's built-ins cover `Array`, `Object`, `Map`, `Set`, `Promise`, `JSON`, and the newer `fetch` and `Temporal` APIs. The environment adds more: browsers provide the DOM and web APIs, and Node.js provides modules for the file system, HTTP, and streams. Widely used libraries and frameworks include [React](https://react.dev/), [Vue](https://vuejs.org/), and [Angular](https://angular.dev/) for user interfaces, [Express](https://expressjs.com/) and [Fastify](https://fastify.dev/) for servers, and [Lodash](https://lodash.com/) for utilities.

## Testing and packaging

Common test runners include [Jest](https://jestjs.io/), [Vitest](https://vitest.dev/), and the built-in `node:test` module.

```javascript
import { test } from "node:test";
import assert from "node:assert";

test("addition works", () => {
  assert.strictEqual(2 + 3, 5);
});
```

A distributable package declares metadata and an entry point in `package.json` and publishes with `npm publish`. Libraries often ship both ES module and CommonJS builds.

## Performance and concurrency

Modern engines compile hot JavaScript to native code with just-in-time compilation, so numeric and loop-heavy code runs fast once warmed up. The concurrency model is single-threaded with an event loop:

- Asynchronous I/O does not block the thread; callbacks, promises, and `async`/`await` resume when work completes.
- CPU-bound work blocks the event loop, so offload it to [Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API) in the browser or [worker threads](https://nodejs.org/api/worker_threads.html) in Node.js.
- `SharedArrayBuffer` and atomics allow shared-memory parallelism between workers where supported.

## Common pitfalls

- Loose equality (`==`) coerces types, so `0 == ""` and `null == undefined` are true; use strict `===`.
- `this` binding depends on how a function is called, not where it is defined; arrow functions capture the surrounding `this`, which usually avoids the problem.
- Floating-point numbers are IEEE 754 doubles, so `0.1 + 0.2 !== 0.3`; use integer cents or a decimal library for money.
- Mutating a shared object or array passed by reference changes it for every holder; copy with spread or structured cloning when isolation is needed.

## Security relevance

JavaScript matters to practitioners twice over: it is the language of the client-side web attack surface, and through Node.js it is also a server back end. This section is the threat-facing context; the defensive patterns are in the Secure coding section that follows.

### Where it appears

- The browser attack surface. JavaScript is the language of cross-site scripting payloads and DOM manipulation, and the target that a Content Security Policy constrains, so reading it is reading the client attack surface. See [Web Application Pentesting](/WEB_APPLICATION_PENTESTING.md) and the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md).
- Server back ends. [Node.js](https://nodejs.org/) back ends built on [Express](https://expressjs.com/) or [Fastify](https://fastify.dev/) are assessment targets with their own injection and access-control risks.
- Tooling and automation. Browser-automation frameworks such as [Puppeteer](https://pptr.dev/) and [Playwright](https://playwright.dev/), along with much recon and build tooling, run on Node.
- Supply chain. The npm registry is a frequent target; see the [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) case study and the [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

JavaScript is memory-safe (garbage-collected), so memory corruption is the engine's concern rather than the script's. The weaknesses that matter are about injection and trust:

- Cross-site scripting from untrusted data written into the DOM through `innerHTML` or framework escape hatches. This is [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Prototype pollution when untrusted JSON is merged into objects and sets `__proto__`. This is [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html).
- Code injection through `eval`, `new Function`, or a string argument to `setTimeout`. This is [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- SQL and command injection on the server, through concatenated queries or a `child_process` shell string. These are [CWE-89](https://cwe.mitre.org/data/definitions/89.html) and [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Server-side request forgery when a back end fetches a URL built from user input. This is [CWE-918](https://cwe.mitre.org/data/definitions/918.html).

### Why it matters

Reading JavaScript lets a practitioner find DOM cross-site-scripting sinks and prototype-pollution gadgets on the client, audit Node back ends for injection, and judge the risk a deep npm dependency tree carries. [ESLint](https://eslint.org/) with security plugins and [semgrep](https://semgrep.dev/) perform static analysis and `npm audit` checks dependencies, as the Secure coding section details.

## Secure coding

JavaScript runs in the browser and on servers, so both client and server risks apply:

- Cross-site scripting: never insert untrusted data into the DOM with `innerHTML`, `document.write`, or framework escape hatches such as `dangerouslySetInnerHTML`; use text nodes or framework-escaped bindings, and set a Content Security Policy. This maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Code injection: never pass untrusted input to `eval`, `new Function`, or `setTimeout` with a string argument, which maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Prototype pollution: merging untrusted JSON into objects can set `__proto__` and alter every object's prototype; validate keys and use `Object.create(null)` or `Map` for untrusted dictionaries. This maps to [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html).
- SQL and command injection on the server: use parameterized queries ([CWE-89](https://cwe.mitre.org/data/definitions/89.html)) and `child_process` argument arrays rather than `exec` with a shell string ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)).
- Dependency supply chain: the npm ecosystem has many small transitive dependencies; pin with a lockfile, run `npm audit`, and watch for typosquatting. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [ESLint](https://eslint.org/) with security plugins and [semgrep](https://semgrep.dev/) perform static analysis, and `npm audit` checks dependencies. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) and [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [MDN Web Docs: JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript), the reference most developers use.
- [ECMA-262 specification](https://tc39.es/ecma262/), the language standard.
- [Node.js documentation](https://nodejs.org/en/docs), for the server runtime.

## Related pages

- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [TypeScript](/languages/typescript.md)
- [CoffeeScript](/languages/coffeescript.md)
- [WebAssembly](/languages/webassembly.md)
- [All languages](/languages/README.md)
