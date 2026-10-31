# Nuxt

Nuxt is a Vue-based meta-framework for full-stack web applications. It renders on the server and the client, with universal rendering, static generation, and client-only modes. Its server side runs on the Nitro engine, and routing is file-based. It is maintained in the open by the Nuxt team.

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

- `/languages/javascript.md`
- `/languages/typescript.md`
- `/frameworks/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/WEB_APPLICATION_SECURITY_REFERENCE.md`
- `/API_SECURITY_REFERENCE.md`
- `/frameworks/vue.md`
- `/frameworks/nextjs.md`
- `/frameworks/remix.md`
