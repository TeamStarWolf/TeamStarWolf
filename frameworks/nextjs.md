# Next.js

Next.js is a React-based meta-framework for building full-stack web applications. It renders on the server and hydrates on the client, and it offers static generation, server-side rendering, and streaming. Recent versions center on the App Router and React Server Components. It is maintained by Vercel.

## Overview and history

Next.js first shipped in 2016 from Vercel, then named Zeit. It standardized file-based routing and server rendering for React. The Pages Router was the original model.

Version 13 in 2022 introduced the App Router built on React Server Components. Later releases added server actions, streaming, and partial prerendering. Both routers remain supported, and many codebases mix them.

Next.js runs on Node.js and on edge runtimes. It targets both traditional servers and serverless deployment.

## Architecture

The framework splits work between server and client. React Server Components render on the server and send a serialized tree, not JavaScript, to the browser. Client components carry the `"use client"` directive and hydrate in the browser for interactivity.

Server-side rendering produces HTML per request. Static generation produces HTML at build time and can revalidate on a schedule. Streaming sends parts of the page as they resolve, so the user sees content sooner.

The App Router uses a `app/` directory where folders are route segments. The Pages Router uses a `pages/` directory with one component per route. Middleware runs before a request reaches a route and can rewrite, redirect, or set headers.

## Routing, data, and key subsystems

In the App Router, special files define behavior. `page.tsx` is the route UI, `layout.tsx` wraps segments, `loading.tsx` shows fallback UI, and `route.ts` defines an HTTP route handler. Data loading happens inside server components with plain `async` functions and `fetch`.

Server actions are async functions marked `"use server"` that run on the server when called from a form or client event. They mutate data without a hand-written API endpoint. Route handlers in `route.ts` cover REST-style endpoints.

The Pages Router uses `getServerSideProps` and `getStaticProps` for data. Middleware lives in `middleware.ts` at the project root. Caching spans the fetch cache, the full route cache, and the client router cache.

## A minimal example

```tsx
// app/page.tsx
export default async function Home() {
  const res = await fetch("https://api.example.com/count", {
    cache: "no-store",
  });
  const { count } = await res.json();
  return <main>Current count: {count}</main>;
}
```

## Ecosystem and tooling

The `next` CLI runs the dev server, builds, and starts production. Turbopack is the newer bundler, and Webpack remains the stable default in some setups. TypeScript support is first-class.

Vercel is the reference deployment target, but `next start` runs on any Node host and adapters cover other platforms. Common companions include Tailwind CSS, Prisma or Drizzle for data, and NextAuth or Auth.js for authentication.

Testing uses Jest or Vitest with React Testing Library, plus Playwright or Cypress for end-to-end runs. ESLint ships with a Next.js config.

## Security model and common vulnerabilities

Next.js escapes JSX output through React, which reduces cross-site scripting risk. The `dangerouslySetInnerHTML` prop bypasses that and is the main XSS path (CWE-79). The general output rules are in `/SECURE_CODING_REFERENCE.md` and `/WEB_APPLICATION_SECURITY_REFERENCE.md`.

Server actions are a trust boundary, not an internal helper. Any client can invoke an exposed action with crafted input, so each action must authenticate and authorize the caller and validate every argument (CWE-862). Missing checks here are a direct path to broken access control. Protect actions as you would any public endpoint per `/API_SECURITY_REFERENCE.md`.

Server fetches can reach internal hosts. If a server component or action fetches a user-supplied URL, an attacker can target metadata services or internal networks, which is server-side request forgery (CWE-918). Allowlist destinations and reject private address ranges.

Environment variables split by prefix. A variable named with `NEXT_PUBLIC_` is inlined into the client bundle and visible to everyone, so a secret placed there leaks (CWE-200). Keep secrets in unprefixed variables read only in server code.

Middleware has historically been used as the sole authorization gate, and a bypass class let crafted requests skip it. Do not rely on middleware alone for authorization. Enforce access control again in the server component, action, or route handler that touches data (CWE-862).

Caching can expose one user's data to another. A response cached without per-user keys, or a `fetch` left cacheable when it returns private data, can serve that data to the wrong visitor (CWE-200). Mark private fetches `no-store` and scope caches by user.

Server actions accept `POST` requests, and cross-site request forgery is a concern (CWE-352). Next.js checks the request origin for actions, so keep that protection and avoid widening allowed origins. For custom state-changing route handlers, add your own origin or token checks. Review the OWASP Top 10 access-control and SSRF entries alongside this page.

## Performance and rendering

Server components cut client JavaScript because their code never ships to the browser. Streaming and Suspense let the shell paint before slow data resolves. Static generation and incremental revalidation serve cached HTML at the edge.

Image optimization through `next/image`, font optimization, and automatic code splitting reduce payload. Partial prerendering combines a static shell with streamed dynamic holes. Measure with the build output and the bundle analyzer.

## Common pitfalls

Marking a component `"use client"` too high in the tree pulls the whole subtree to the client. Keep the boundary low. Reading a secret in a client component through a `NEXT_PUBLIC_` variable leaks it.

Trusting a hidden form field or client guard in a server action skips real authorization. Forgetting `no-store` on a private fetch can cache sensitive data. Over-fetching in a server component ships more work than the page needs.

Mixing App Router and Pages Router data methods causes confusion about where code runs. Confirm each file's execution context before adding logic.

## Resources

- The Next.js documentation.
- The OWASP Cheat Sheet Series.
- The OWASP Top 10.

## Related pages

- `/languages/javascript.md`
- `/languages/typescript.md`
- `/frameworks/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/WEB_APPLICATION_SECURITY_REFERENCE.md`
- `/API_SECURITY_REFERENCE.md`
- `/frameworks/react.md`
- `/frameworks/remix.md`
- `/frameworks/nuxt.md`
