# Svelte

Svelte is a UI framework that compiles components to small JavaScript modules at build time. It has no virtual DOM and no framework runtime loaded alongside your code. Reactivity is driven by assignments and, in recent versions, by runes. SvelteKit is its full-stack meta-framework and adds routing, server rendering, and data loading.

## Overview and history

Rich Harris released Svelte in 2016. Version 3 in 2019 made reactive assignments the core model. Version 5 in 2024 introduced runes, an explicit signal-based reactivity API.

The project sits under the Svelte organization and is maintained in the open. SvelteKit reached 1.0 in late 2022. It replaced the older Sapper project as the recommended way to build applications.

Svelte targets small bundles and direct DOM updates. The framework code mostly disappears into the compiled output.

## Architecture

Svelte is compiler-first. A component is a single-file `.svelte` module with markup, a `<script>` block, and a `<style>` block. The compiler reads these and emits imperative DOM code that updates only the nodes that change.

There is no virtual DOM and no diffing at runtime. The compiler knows the dependency graph of each piece of state and writes targeted update calls. This keeps runtime overhead low.

SvelteKit splits work across a server and a client. On the server it renders HTML and runs data loading. In the browser it hydrates that HTML and takes over navigation as a single-page application. Routing is file-based under `src/routes`, and each route can have server code, shared code, and a page component.

## Routing, data, and key subsystems

SvelteKit routes map directories to URLs. A `+page.svelte` file is the page component. A `+page.js` file runs on both server and client, while `+page.server.js` runs only on the server and can hold secrets.

`load` functions fetch data for a route before it renders. A server `load` can query a database or call an internal API. Form actions in `+page.server.js` handle `POST` submissions and work without client JavaScript through progressive enhancement.

Stores hold shared reactive state. The `writable`, `readable`, and `derived` helpers in `svelte/store` expose a subscribe contract. Runes such as `$state` and `$derived` cover the same ground inside components in version 5.

## A minimal example

```svelte
<script>
  let count = $state(0);
  const increment = () => count += 1;
</script>

<button onclick={increment}>
  Clicked {count} times
</button>
```

## Ecosystem and tooling

Vite is the build tool for SvelteKit. It provides the dev server, hot module replacement, and production bundling. The `svelte-check` tool type-checks components against TypeScript.

Adapters target deployment platforms. `adapter-node`, `adapter-static`, and platform adapters for serverless hosts shape the build output. UI libraries such as Skeleton and component collections extend the base framework.

Testing uses Vitest for unit tests and Playwright for end-to-end runs. The Svelte language tools power editor support in VS Code and other editors.

## Security model and common vulnerabilities

Svelte escapes text interpolation by default. A value written as `{value}` in markup is HTML-escaped, which blocks the common cross-site scripting path (CWE-79). See `/SECURE_CODING_REFERENCE.md` and `/WEB_APPLICATION_SECURITY_REFERENCE.md` for the general output-encoding rules.

The `{@html ...}` tag bypasses escaping and writes raw HTML. It is the main XSS vector in Svelte code (CWE-79). Only pass sanitized input to it, for example output from a vetted sanitizer, and never user-controlled strings directly.

SvelteKit form actions and server `load` functions are server endpoints. They run with server privileges and must authorize the caller and validate every input. Do not assume a hidden form field or a client check constrains what arrives. Treat action input as hostile and follow `/API_SECURITY_REFERENCE.md`.

SvelteKit enables origin checking for form `POST` requests, which defends against cross-site request forgery (CWE-352). Keep the `csrf.checkOrigin` protection on. If you expose a JSON API that changes state, add your own token or origin checks, since the built-in guard targets form posts.

Environment variables split into public and private modules. Values imported from `$env/static/private` or `$env/dynamic/private` stay on the server. Anything placed in `$env/static/public` or prefixed for public use ships to the browser, so a secret put there leaks to every visitor (CWE-200). Never import private env modules into client-reachable code.

Server `load` return values travel to the client during hydration. Data you return from a universal `load` is serialized into the page. Return only fields the user may see, and keep tokens and internal records in server-only `load` functions.

## Performance and rendering

Compiled output updates the DOM directly, so there is no reconciliation pass. Bundles are small because no framework runtime ships with most apps. First paint is fast when server rendering sends ready HTML.

SvelteKit prefetches route code on link hover and preloads data for likely navigations. Code splitting per route keeps the initial download small. Static generation through `adapter-static` serves prebuilt HTML for content that does not change per request.

## Common pitfalls

Reassigning array or object contents without an assignment does not trigger updates in the pre-runes model. Push to an array, then assign it back, or use a rune. Forgetting this leaves the UI stale.

Putting secrets in a public env variable exposes them. Using `{@html}` on untrusted input opens XSS. Mixing server-only imports into shared code breaks the build or leaks data.

Returning large objects from `load` bloats the serialized payload. Trim the shape to what the page renders.

## Resources

- The Svelte documentation.
- The SvelteKit documentation.
- The OWASP Cheat Sheet Series.

## Related pages

- `/languages/javascript.md`
- `/languages/typescript.md`
- `/frameworks/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/WEB_APPLICATION_SECURITY_REFERENCE.md`
- `/API_SECURITY_REFERENCE.md`
- `/frameworks/react.md`
- `/frameworks/vue.md`
- `/frameworks/nextjs.md`
