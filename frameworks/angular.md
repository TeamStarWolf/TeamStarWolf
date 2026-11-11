# Angular

Angular is a frontend application framework built and maintained by Google. It is written in TypeScript and intended for TypeScript. Unlike a view-only library, it ships routing, forms, HTTP, and dependency injection in one package. Teams choose it for structure, strong typing, and a consistent toolchain on large projects.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Angular, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,357 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing an Angular application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[TypeScript](/languages/typescript.md), [JavaScript](/languages/javascript.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [React](/frameworks/react.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Angular (version 2 and later) was released in 2016 as a full rewrite of the older AngularJS. It adopted TypeScript, a component model, and a command-line tool. The project follows a predictable release cadence with long-term support versions.

Recent versions added standalone components, which reduce the need for NgModules. They also introduced signals for fine-grained reactivity. The framework keeps backward compatibility paths and ships automated migration tools.

Angular targets large, long-lived applications. Its conventions and included libraries aim to keep big codebases consistent across teams.

## Architecture

The core building block is the component, a TypeScript class with an HTML template and styles. A decorator, `@Component`, links the class to its template and selector. Components form a tree, and each manages its own view and state.

Historically components were grouped into NgModules declared with `@NgModule`. Standalone components now let a component declare its own dependencies directly. Both models coexist, and new projects favor standalone components.

Templates use data binding to connect class state to the DOM. Interpolation with `{{ value }}` renders text, property binding with `[prop]` sets element properties, and event binding with `(event)` responds to user input. Two-way binding with `[(ngModel)]` combines both for form inputs. Structural directives such as `*ngIf` and `*ngFor`, or the newer control-flow blocks, add and remove elements.

Dependency injection is central. Services are classes marked injectable and requested through a component constructor. The injector supplies a shared instance, which keeps components decoupled from how dependencies are built. This makes services easy to swap in tests.

Reactivity comes from RxJS observables and, more recently, signals. Observables model streams of asynchronous values such as HTTP responses and events. Lifecycle hooks like `ngOnInit` and `ngOnDestroy` let components run setup and cleanup at defined points.

## Routing, data, and key subsystems

The Angular Router is part of the framework. It maps URL paths to components, supports nested and lazy-loaded routes, and exposes route guards. Guards control access and can block navigation until data or permission checks pass.

Data fetching uses the built-in `HttpClient`, which returns observables. Interceptors sit in the request pipeline to add headers, handle errors, or attach tokens. This is where the framework wires in its cross-site request forgery support.

State management for small apps lives in services holding observables or signals. Larger apps often add NgRx, a Redux-style store built on RxJS. Forms come in two flavors: template-driven for simple cases and reactive forms for typed, testable control.

The Angular CLI drives the project. It scaffolds code, runs the dev server, and produces production builds. Builds use ahead-of-time compilation, which compiles templates during the build rather than in the browser.

## A minimal example

```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-counter',
  standalone: true,
  template: `<button (click)="increment()">Clicked {{ count }} times</button>`,
})
export class CounterComponent {
  count = 0;

  increment(): void {
    this.count += 1;
  }
}
```

## Ecosystem and tooling

Angular ships a consistent set of first-party libraries, which keeps the ecosystem cohesive. Angular Material provides components that follow Material Design. The CLI, router, forms, and HTTP client all come from the Angular team.

RxJS is a core dependency and shapes how data flows through an app. Learning its operators is part of learning Angular. NgRx and related libraries extend the reactive model to application state.

Tooling includes the Angular Language Service for editor support and strong TypeScript integration. Testing uses Karma or Jest with the framework's `TestBed` utility. The CLI's update command automates version migrations.

## Security relevance

This section is the threat-facing view of Angular: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing single-page applications shipped as static JavaScript bundles, plus the JSON API behind them. The whole client runs in the browser, so the downloadable bundle and the API are the attack surface.
- Recognizable from the outside by the `ng-version` attribute on the root element, hashed bundle names such as `main.<hash>.js`, and the bundled `zone.js` runtime.
- Audit and defensive tooling is the npm toolchain: `npm audit` and retire.js flag vulnerable Angular and library versions, and the Angular compiler's template type checking catches some unsafe bindings.
- The dependency surface is the npm ecosystem, including RxJS and third-party components, pinned through `package-lock.json`. A compromised package runs with full application privilege, the pattern in [the npm supply chain study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md).

### Dominant weakness classes

Angular runs on TypeScript compiled to JavaScript, a memory-managed platform, so the dominant classes are logic and injection flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) through the `bypassSecurityTrust*` escape hatches or DOM sinks that skip the built-in sanitizer.
- Missing server-side authorization ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)): route guards run in the browser and can be bypassed, so access must be enforced at the API.
- Information exposure ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)) when secrets, API keys, or internal endpoints are shipped inside the client bundle, which any user can read.
- Prototype pollution ([CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)) reaching the app through a vulnerable client-side dependency.

### Why it matters

Recognizing Angular tells a tester the real application logic sits in a downloadable bundle to read, that authorization must be probed at the API rather than the UI guards, and which XSS sinks and sanitizer bypasses to try first. `npm audit` and retire.js cover the dependency side. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Angular applies contextual output escaping and sanitization by default. Values bound into templates are treated as untrusted and escaped for their context, which blocks most cross-site scripting (CWE-79). The sanitizer understands HTML, style, and URL contexts.

The escape hatch is the `bypassSecurityTrust*` family, such as `bypassSecurityTrustHtml`. These mark a value as safe and skip sanitization. Use them only on values you fully control, because misuse reintroduces XSS. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for output-handling rules.

Angular includes cross-site request forgery support in `HttpClient` (CWE-352). It reads a token from a cookie and sends it as a header on state-changing requests. The server must set the cookie and validate the header for this protection to work.

Template injection is a risk when templates are built from untrusted strings at runtime. Avoid constructing templates dynamically from user input. A Content Security Policy adds defense in depth and limits what injected script can do. The Angular Security guide documents both the trusted-types integration and CSP setup.

Supply-chain exposure applies as with any npm project (CWE-829). Angular pulls in RxJS, build tools, and third-party components. Pin versions, scan dependencies, and prefer maintained packages. See `/SECURE_CODING_REFERENCE.md` for dependency and build-security practices.

## Performance and rendering

Change detection checks bindings to update the DOM. By default it runs broadly, which can be costly in large trees. The `OnPush` strategy limits checks to changed inputs and observable emissions. Signals push this toward fine-grained, targeted updates.

Ahead-of-time compilation produces smaller, faster code than compiling in the browser. Lazy-loaded routes split the bundle so users download only what a route needs. The CLI's production build enables tree shaking and minification.

Server-side rendering through Angular's hydration improves first paint and indexing. Measuring with the browser profiler and Angular DevTools shows where change detection spends time. Correct use of `OnPush` and `trackBy` on lists removes most waste.

## Common pitfalls

Forgetting to unsubscribe from observables leaks memory and causes stale updates. Use the `async` pipe or a teardown operator to manage subscriptions. Running heavy work in default change detection slows the whole app.

Overusing `bypassSecurityTrust*` quietly disables the sanitizer. Treat each use as a security decision. Mixing template-driven and reactive forms in one feature leads to confusing bugs.

Mutating objects in place can defeat `OnPush`, which compares references. Produce new references when state changes. Deeply nested NgModules in older projects slow builds and confuse lazy loading.

## Resources

- The Angular documentation, including its Security guide (official)
- The RxJS documentation (official)
- OWASP Cheat Sheet Series, including the Cross-Site Request Forgery Prevention and DOM-based XSS Prevention Cheat Sheets

## Related pages

- [TypeScript](/languages/typescript.md)
- [JavaScript](/languages/javascript.md)
- [Frameworks index](/frameworks/README.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [React](/frameworks/react.md)
- [Vue.js](/frameworks/vue.md)
- [NestJS](/frameworks/nestjs.md)
