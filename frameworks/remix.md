# Remix

Remix is a React-based meta-framework built on web standards. It renders on the server first and uses loaders and actions to move data between server and client. It favors progressive enhancement, so pages work before JavaScript loads. The project has merged its core into React Router, which now carries the same model.

## Overview and history

Remix was created by the authors of React Router and released publicly in 2021. It centered on server-first data flow and nested routing. Shopify acquired the project in 2022.

In 2024 the team folded Remix features into React Router version 7. New work largely continues there, and the two share the loader and action model. Existing Remix applications remain supported, and the concepts carry over.

Remix runs on many JavaScript runtimes. Adapters target Node, Deno, Cloudflare Workers, and other hosts.

## Architecture

Remix renders on the server and hydrates on the client. A route module can export a component, a `loader` for reads, and an `action` for writes. The server runs loaders and actions, then sends HTML, and the client hydrates for navigation.

Nested routing maps the route tree to nested URLs and nested layouts. A parent route renders an `<Outlet>` where child routes appear. Each nested route loads its own data in parallel.

Progressive enhancement is a core goal. Forms submit over standard HTTP and reach the matching `action`, so a page works without client JavaScript. When JavaScript is present, Remix intercepts navigation and submissions for a single-page feel.

## Routing, data, and key subsystems

A `loader` runs on the server for `GET` requests and returns data for the route. An `action` runs on the server for `POST`, `PUT`, `PATCH`, and `DELETE` and handles mutations. Both receive the request and can read headers, cookies, and parameters.

Routes compose through the file convention or a route config. The `<Form>` component posts to the route's `action`, and `useLoaderData` reads loader output in the component. `useFetcher` calls loaders and actions without a full navigation.

Sessions use cookie helpers such as `createCookieSessionStorage`. These sign and optionally encrypt session cookies and expose get, commit, and destroy functions. Utilities like `redirect` and `json` shape responses from loaders and actions.

## A minimal example

```tsx
import { json } from "@remix-run/node";
import { useLoaderData } from "@remix-run/react";

export async function loader() {
  return json({ count: 42 });
}

export default function Route() {
  const { count } = useLoaderData<typeof loader>();
  return <main>Count: {count}</main>;
}
```

## Ecosystem and tooling

Remix uses Vite for the dev server and build. Adapters connect the app to a runtime, and templates scaffold common setups. TypeScript support is built in.

Data libraries such as Prisma and Drizzle pair well with loaders and actions. UI work often uses Tailwind CSS. Authentication uses the session utilities or packages such as `remix-auth`.

Testing uses Vitest with React Testing Library and Playwright for end-to-end runs. React Router version 7 shares the tooling for migrated projects.

## Security model and common vulnerabilities

React escapes JSX output, which reduces cross-site scripting. The `dangerouslySetInnerHTML` prop bypasses that and is the main XSS path (CWE-79). The general rules are in `/SECURE_CODING_REFERENCE.md` and `/WEB_APPLICATION_SECURITY_REFERENCE.md`.

Loaders and actions are server endpoints. Any client can call them directly with crafted input, so each must authenticate and authorize the caller and validate input (CWE-862). A loader that returns records by id must check that the current user may read them. Treat them as public API surface per `/API_SECURITY_REFERENCE.md`.

Actions handle state-changing requests and face cross-site request forgery (CWE-352). Remix does not add a CSRF token by default, so protect actions yourself. Validate the request origin, or issue and check a token stored in the session, for any action that mutates data.

Loader data is sent to the client. Values returned from a loader are serialized into the HTML and readable in the browser (CWE-200). Return only fields the user may see, and keep tokens, password hashes, and internal flags out of loader responses.

Loaders and actions that fetch a user-supplied URL can reach internal hosts. This is server-side request forgery (CWE-918) and can target metadata services or internal APIs. Allowlist outbound destinations and reject private address ranges.

Session cookies need a strong secret and safe flags. Set `httpOnly`, `secure`, and a sensible `sameSite` value, and rotate the signing secret if it leaks. Store only an identifier or minimal claims in the cookie, not sensitive data. Review the OWASP Top 10 access-control and SSRF entries with this page.

## Performance and rendering

Server-first rendering sends ready HTML and runs loaders in parallel across nested routes. The client hydrates and then handles navigation without full page loads. Prefetching on link intent loads data and code before the user clicks.

Deferred data lets slow values stream in after the initial response with `defer` and `Await`. Running on edge runtimes cuts latency for dynamic pages. Caching headers set in loaders control CDN and browser caching.

## Common pitfalls

Returning a full database record from a loader can leak columns the user should not see. Select only needed fields. Skipping authorization in a loader or action trusts the client too much.

Assuming a framework CSRF guard exists leaves actions open. Add origin or token checks yourself. Fetching a user-controlled URL on the server invites SSRF.

Storing sensitive data in a non-encrypted session cookie exposes it. Over-deferring data can make the page feel incomplete. Confirm where each export runs before adding logic.

## Resources

- The Remix documentation.
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
- `/frameworks/nextjs.md`
- `/frameworks/nuxt.md`
