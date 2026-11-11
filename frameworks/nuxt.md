# Nuxt

Nuxt is a Vue-based meta-framework for full-stack web applications. It renders on the server and the client, with universal rendering, static generation, and client-only modes. Its server side runs on the Nitro engine, and routing is file-based. It is maintained in the open by the Nuxt team.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Nuxt, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,176 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Nuxt application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[JavaScript](/languages/javascript.md), [TypeScript](/languages/typescript.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Nuxt started in 2016 as a server-rendering layer for Vue. Nuxt 2 built on Vue 2 and popularized file-based routing and the module ecosystem. Nuxt 3 shipped in late 2022 on Vue 3, Vite, and the new Nitro server.

Nitro is the server engine that lets Nuxt deploy to Node, serverless, and edge targets from one codebase. Auto-imports removed much of the manual import boilerplate. The framework continues under the same team with regular releases.

Nuxt aims to make server and client code share one project structure. It leans on Vue's reactivity and single-file components.

## Architecture

Nuxt supports several rendering modes. Universal rendering produces HTML on the server, then hydrates in the browser. Client-side rendering ships a single-page app, and static generation prebuilds pages with `nuxi generate`.

The client side is a Vue 3 application. The server side is a Nitro application that handles API routes, server middleware, and rendering. Nitro compiles to a portable server bundle that runs across hosting targets.

Routing maps the `pages/` directory to URLs. Server routes live under `server/` and expose API endpoints and middleware. Auto-imports make composables and components available without explicit import statements, resolved at build time.

## Routing, data, and key subsystems

Pages under `pages/` become routes, and the `<NuxtPage>` and `<NuxtLayout>` components compose the shell. Data fetching uses `useFetch` and `useAsyncData`, which run on the server during the first render and hydrate the result. The `$fetch` helper calls endpoints from either side.

Server routes under `server/api/` and `server/routes/` define handlers with `defineEventHandler`. Server middleware under `server/middleware/` runs on every request. Nitro exposes storage and caching utilities to these handlers.

Runtime config holds environment-driven values. The `runtimeConfig` object separates private keys, available only on the server, from a `public` block sent to the client. Composables such as `useState` share reactive state across components during a request.

## A minimal example

```ts
// server/api/count.get.ts
export default defineEventHandler(() => {
  return { count: 42 };
});
```

## Ecosystem and tooling

The `nuxi` CLI scaffolds, runs the dev server, builds, and generates static sites. Vite powers the build and hot module replacement. Nuxt modules extend the framework for content, images, auth, and UI.

Common modules include Nuxt Content, Nuxt Image, and Pinia for state. Nitro presets target Node, Vercel, Netlify, Cloudflare, and other hosts. TypeScript support is built in with generated types.

Testing uses Vitest with the `@nuxt/test-utils` package and Playwright for end-to-end runs. The Nuxt DevTools panel inspects routes, state, and modules in development.

## Security relevance

This section is the threat-facing view of Nuxt: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing full-stack web applications served by the Nitro engine on Node, serverless, or edge hosts. A Nuxt app is recognizable from the outside: a `__NUXT__` or `__NUXT_DATA__` hydration payload in the initial HTML, `/_nuxt/` asset paths, and the file-based `server/api/` route shapes.
- Offensive interest centers on the server routes and the hydration payload: unauthenticated `server/api/` handlers, secrets leaked through the public runtime config, and outbound fetches from Nitro handlers. Burp Suite and OWASP ZAP drive the surface.
- Dependency and audit tooling is the npm toolchain: `npm audit`, Snyk, and Socket scan the tree pinned by the lockfile.
- The supply-chain surface is npm. See [the npm supply chain attacks study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) and [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Nuxt runs on Node and JavaScript, memory-managed, so the dominant classes are logic and injection flaws rather than memory corruption. The fixes for each are in the section below.

- Missing authorization ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)) on `server/api/` handlers, which run with server privilege whether or not the UI links to them.
- Sensitive information exposure ([CWE-200](https://cwe.mitre.org/data/definitions/200.html)) through a secret placed under `runtimeConfig.public` or embedded in the hydration payload.
- Server-side request forgery ([CWE-918](https://cwe.mitre.org/data/definitions/918.html)) when a Nitro handler fetches a user-supplied URL.
- Cross-site scripting ([CWE-79](https://cwe.mitre.org/data/definitions/79.html)) through the `v-html` directive on untrusted input.

### Why it matters

Recognizing Nuxt, usually through the `__NUXT__` hydration blob or `/_nuxt/` paths, tells a tester which pivots to try first: enumerate `server/api/` routes for missing authorization, read the hydration payload and public runtime config for leaked secrets, and probe server handlers for SSRF. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Vue escapes template interpolation by default, which reduces cross-site scripting. The `v-html` directive bypasses escaping and is the main XSS path (CWE-79). The general output rules live in `/SECURE_CODING_REFERENCE.md` and `/WEB_APPLICATION_SECURITY_REFERENCE.md`.

Server routes are public endpoints. A handler under `server/api/` runs with server privileges and must authenticate and authorize the caller and validate input (CWE-862). Do not assume a route is private because the UI does not link to it. Apply the checks in `/API_SECURITY_REFERENCE.md`.

Runtime config controls secret exposure. Values under `runtimeConfig.public` ship to the browser, while top-level keys stay on the server. A secret placed in the public block leaks to every visitor (CWE-200), so keep tokens and keys out of `public`.

Server handlers that fetch a user-supplied URL can reach internal services. This is server-side request forgery (CWE-918) and can hit cloud metadata endpoints or internal hosts. Allowlist outbound destinations and block private address ranges.

Server rendering can inject untrusted data into the HTML stream. State serialized for hydration, or values written into templates without escaping, can carry an injection if the data is attacker-controlled. Sanitize anything rendered as raw markup and keep hydration payloads free of secrets (CWE-200).

Cross-origin resource sharing needs explicit, narrow rules. Do not set a wildcard origin with credentials on server routes. Validate the `Origin` header for state-changing requests and prefer an allowlist. Review these points against the OWASP Cheat Sheet Series.

## Performance and rendering

Universal rendering sends ready HTML, which improves first paint and indexing. Nitro caches route responses and supports incremental static regeneration on supported hosts. Payload extraction and code splitting keep the client bundle small.

The `useFetch` and `useAsyncData` helpers deduplicate requests and reuse server-fetched data on hydration. Static generation serves prebuilt pages from a CDN. Edge rendering through Nitro presets cuts latency for dynamic pages.

## Common pitfalls

Putting a secret under `runtimeConfig.public` leaks it to the browser. Calling `useFetch` with a client-only option when data is needed for SSR causes hydration mismatches. Forgetting authorization on a `server/api/` route exposes data.

Using `v-html` on untrusted input opens XSS. Fetching a user-controlled URL from a server handler invites SSRF. Over-relying on auto-imports can hide where a composable runs, server or client.

Returning large payloads from `useAsyncData` bloats the hydration state. Trim results to what the page uses.

## Resources

- The Nuxt documentation.
- The Nitro documentation.
- The OWASP Cheat Sheet Series.

## Related pages

- [JavaScript](/languages/javascript.md)
- [TypeScript](/languages/typescript.md)
- [Software frameworks](/frameworks/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API Security Reference Library](/API_SECURITY_REFERENCE.md)
- [Vue.js](/frameworks/vue.md)
- [Next.js](/frameworks/nextjs.md)
- [Remix](/frameworks/remix.md)
