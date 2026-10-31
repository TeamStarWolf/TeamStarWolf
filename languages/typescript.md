# TypeScript

TypeScript is a statically typed superset of JavaScript created by Microsoft and first released in 2012. It adds an optional, structural type system that is checked at compile time and then erased, producing plain JavaScript that runs anywhere JavaScript runs. It is used wherever JavaScript is used, especially in larger front-end and back-end codebases where static types catch errors before run time.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: same as JavaScript, plus static typing |
| Typing | Static, structural, gradual; types are erased at compile time |
| First appeared | 2012 |
| Memory model | Automatic: inherits the host JavaScript engine's garbage collection |
| Reference implementation | [TypeScript compiler (tsc)](https://github.com/microsoft/TypeScript) |
| Typical uses | Front-end web, server back ends, tooling, large JavaScript codebases |
| Governance | Microsoft, with a public design process on [GitHub](https://github.com/microsoft/TypeScript) |

Related: [JavaScript](/languages/javascript.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

TypeScript was designed by a team at Microsoft led by Anders Hejlsberg (also the designer of C# and Turbo Pascal) to make large JavaScript codebases more maintainable by adding static types. Because it is a superset, any valid JavaScript is valid TypeScript, so projects can adopt it file by file. The compiler checks types and then emits JavaScript targeting a chosen ECMAScript version; the types themselves do not exist at run time.

TypeScript became the default for many frameworks and libraries, which publish type definitions alongside their code or through the [DefinitelyTyped](https://github.com/DefinitelyTyped/DefinitelyTyped) repository. Development happens in the open on GitHub, with roughly quarterly releases.

## Paradigm and type system

The type system is structural: two types are compatible if their shapes match, regardless of their declared names. It is also gradual, so you can type as much or as little as you like; the `any` type opts out of checking, and `unknown` is a safe top type that forces a check before use. Features include interfaces, generics, union and intersection types, literal types, discriminated unions, conditional and mapped types, and type inference that reduces how many annotations you write.

```typescript
type Price = number;

function total(prices: Price[], tax: number = 0): number {
  return prices.reduce((sum, p) => sum + p, 0) * (1 + tax);
}
```

Strict mode (the `strict` compiler flag) enables null checking and other rules that catch a large class of errors; new projects should turn it on.

## Toolchain and ecosystem

- Compiler: `tsc` type-checks and emits JavaScript; `tsc --noEmit` checks without producing output.
- Runtime: the emitted JavaScript runs in browsers and in [Node.js](https://nodejs.org/); runtimes such as [Deno](https://deno.land/) and [Bun](https://bun.sh/) and the loader [ts-node](https://typestrong.org/ts-node/) run TypeScript directly.
- Packaging: the same npm registry as JavaScript; packages ship `.d.ts` declaration files so consumers get types.
- Configuration: `tsconfig.json` controls the target, module system, and strictness.
- Linting: [ESLint](https://eslint.org/) with [typescript-eslint](https://typescript-eslint.io/) lints typed code.

```bash
npm install --save-dev typescript
npx tsc --init
npx tsc --noEmit
```

## Syntax tour

```typescript
// Type annotations and inference
const name: string = "world";
let count = 0; // inferred as number

// Interfaces and type aliases
interface Point {
  readonly x: number;
  readonly y: number;
}

type Shape =
  | { kind: "circle"; radius: number }
  | { kind: "square"; side: number };

// Discriminated unions narrow in a switch
function area(shape: Shape): number {
  switch (shape.kind) {
    case "circle":
      return Math.PI * shape.radius ** 2;
    case "square":
      return shape.side ** 2;
  }
}

// Generics
function first<T>(items: T[]): T | undefined {
  return items[0];
}

// unknown forces a check before use
function parse(input: unknown): number {
  if (typeof input === "number") return input;
  return 0;
}
```

## Idioms and different approaches

- Enable `strict` in `tsconfig.json`; it turns on `strictNullChecks` and related rules that catch the most common errors.
- Prefer `unknown` over `any` for values whose type is not yet known, so the compiler forces a narrowing check.
- Model variants with discriminated unions and let the compiler check that a `switch` handles every case (exhaustiveness).
- Let inference do the work; annotate function parameters and public boundaries, and leave local variables inferred.
- Treat type definitions for third-party packages as part of the dependency; install `@types/...` packages where libraries do not bundle their own.

## Design principles

TypeScript's stated goals include catching errors early through a type system, staying aligned with current and proposed ECMAScript, and emitting clean, idiomatic JavaScript. A deliberate choice is that the type system is unsound in a few places (for example, it allows some covariant array assignments and does not check at run time), trading theoretical soundness for compatibility with existing JavaScript and for productivity. Types are a design-time tool: they are erased on compile, so they add no run-time cost and no run-time guarantees.

## Standard library and notable frameworks

TypeScript has no separate standard library; it uses JavaScript's built-ins and ships `lib.d.ts` type definitions for them and for browser and Node.js APIs. The surrounding ecosystem is the JavaScript ecosystem with types: [React](https://react.dev/), [Angular](https://angular.dev/) (written in TypeScript), [Vue](https://vuejs.org/), [NestJS](https://nestjs.com/) for servers, and [Zod](https://zod.dev/) for runtime schema validation that infers static types.

## Testing and packaging

The JavaScript test runners work with TypeScript through a loader or precompilation: [Vitest](https://vitest.dev/) and [Jest](https://jestjs.io/) are common.

```typescript
import { test, expect } from "vitest";

test("addition works", () => {
  expect(2 + 3).toBe(5);
});
```

A distributable library compiles to JavaScript, emits `.d.ts` declaration files (set `declaration: true`), and publishes both to npm so consumers get runtime code and types.

## Performance and concurrency

TypeScript adds no run-time cost: the types are erased and the emitted JavaScript runs on the same engines with the same just-in-time compilation and single-threaded event-loop model as plain JavaScript (see [JavaScript](/languages/javascript.md) for the concurrency details). The build step itself takes time; large projects speed it up with incremental builds (`tsc --build`), project references, and fast transpilers such as [esbuild](https://esbuild.github.io/) or [swc](https://swc.rs/), which strip types without full type checking (so a separate `tsc --noEmit` check still runs for correctness).

## Common pitfalls

- `any` disables checking and spreads silently through a codebase; prefer `unknown` and narrow explicitly.
- Type assertions (`value as Type`) tell the compiler to trust you without a check; a wrong assertion causes a run-time error the types claimed could not happen.
- Types do not exist at run time, so you cannot check them with `instanceof` on an interface; validate untrusted input with a runtime schema library.
- Compiler strictness settings matter: a project without `strictNullChecks` lets `undefined` flow where a value is expected.

## Secure coding

TypeScript inherits every JavaScript risk, because it compiles to JavaScript, and types do not enforce security at run time:

- Run-time validation gap: types are erased, so untrusted input (request bodies, query parameters, JSON) is not validated by the type system; parse it with a runtime validator such as [Zod](https://zod.dev/) before trusting it. Skipping this leads to the same injection and logic flaws as untyped JavaScript.
- Cross-site scripting: the same DOM sinks apply; a typed string assigned to `innerHTML` is still dangerous. This maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Prototype pollution: typed object merges do not prevent `__proto__` manipulation; guard untrusted keys, which maps to [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html).
- Code and command injection: `eval`, `new Function`, and `child_process` with a shell string remain unsafe, mapping to [CWE-94](https://cwe.mitre.org/data/definitions/94.html) and [CWE-78](https://cwe.mitre.org/data/definitions/78.html).
- Unsafe assertions: a wrong `as` assertion can place an attacker-controlled shape where the code assumes a safe one; validate at trust boundaries instead of asserting.
- Dependency supply chain: pin dependencies, run `npm audit`, and prefer packages that ship their own types; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: [typescript-eslint](https://typescript-eslint.io/) adds type-aware lint rules (including bans on `any` and unsafe assertions), and [semgrep](https://semgrep.dev/) scans for insecure patterns. See [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) and [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html), the official guide.
- [TypeScript documentation](https://www.typescriptlang.org/docs/) and the in-browser [Playground](https://www.typescriptlang.org/play).
- [typescript-eslint](https://typescript-eslint.io/), the linting rules and setup.

## Related pages

- [JavaScript](/languages/javascript.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
