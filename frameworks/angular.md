# Angular

Angular is a frontend application framework built and maintained by Google. It is written in TypeScript and intended for TypeScript. Unlike a view-only library, it ships routing, forms, HTTP, and dependency injection in one package. Teams choose it for structure, strong typing, and a consistent toolchain on large projects.

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
