# React

React is a JavaScript library for building user interfaces from composable components. It is written in JavaScript and used with JavaScript or TypeScript. Though often called a framework, it focuses on the view layer and relies on an ecosystem for routing and data. Teams choose it for its component model, large community, and incremental adoption path.

## Overview and history

React was created at Facebook and released as open source in 2013. It introduced a declarative component model backed by a virtual DOM. The project is now maintained by Meta and a wide set of outside contributors.

Later releases added hooks (2019), concurrent rendering, and Server Components. React itself stays small. Most applications combine it with a router, a build tool, and a data library.

React runs in the browser, on the server for rendering HTML, and in native apps through React Native. The same component mental model carries across those targets.

## Architecture

The unit of composition is the component, a function that returns a description of UI. Components receive inputs as `props` and may hold local state. They compose into a tree, with data flowing from parent to child.

Components are written in JSX, a syntax that looks like HTML and compiles to function calls. Each JSX element becomes a `React.createElement` call that produces a plain object. That object tree is the virtual DOM, an in-memory representation of the desired output.

On each update React builds a new virtual tree and compares it to the previous one. This reconciliation step computes the smallest set of real DOM changes. Keys on list items help React match elements across renders and avoid unnecessary work.

State and side effects live in hooks. `useState` holds local state, `useReducer` handles complex transitions, and `useEffect` runs side effects after render. `useMemo` and `useCallback` cache values and functions between renders. `useContext` reads shared values without passing props through every level.

Data flow is one way. A parent passes data down through props, and children report changes up through callbacks. This makes state changes easier to trace than two-way binding. `Suspense` lets a component wait for asynchronous data or code and show a fallback while it loads.

## Routing, data, and key subsystems

React has no built-in router. React Router is the common choice for client and server routing. It maps URL paths to components and supports nested routes and loaders.

State management ranges from built-in hooks to external libraries. Context suits low-frequency shared values like theme or current user. Redux, Zustand, and Jotai handle larger or more complex application state.

Data fetching libraries such as TanStack Query and SWR manage caching, revalidation, and request status. They remove most manual `useEffect` fetch code. For server-driven apps, frameworks like Next.js and Remix add file-based routing, data loading, and server rendering on top of React.

Build tooling is usually Vite or the bundler bundled with a meta-framework. Vite gives fast development startup and an optimized production build. TypeScript support is first class across these tools.

## A minimal example

```jsx
import { useState } from "react";

function Counter() {
  const [count, setCount] = useState(0);

  return (
    <button onClick={() => setCount(count + 1)}>
      Clicked {count} times
    </button>
  );
}

export default Counter;
```

## Ecosystem and tooling

The React ecosystem is large and centered on npm. Component libraries include Material UI, Chakra UI, and headless kits like Radix. Styling options span CSS Modules, Tailwind CSS, and CSS-in-JS libraries.

Developer tooling includes the React Developer Tools browser extension for inspecting the component tree. ESLint with the React hooks plugin catches common hook mistakes. Testing uses React Testing Library with Jest or Vitest.

Meta-frameworks extend React for full applications. Next.js and Remix are the most widely used. They add routing, data loading, and build configuration so teams write less glue code.

## Security model and common vulnerabilities

React escapes values rendered in JSX by default. Text placed in `{expression}` is treated as a string, not markup, which prevents most cross-site scripting (CWE-79). This default is the main built-in protection and should be preserved.

The primary XSS vector is `dangerouslySetInnerHTML`. It injects raw HTML and bypasses escaping. Only pass it values you have sanitized with a vetted library such as DOMPurify, and never pass untrusted input directly. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for input and output handling rules.

URL attributes are another risk. A user-controlled `href` or `src` set to a `javascript:` URL can run script when clicked. Validate that such URLs use an allowed scheme like `http`, `https`, or `mailto` before rendering them. Rendering untrusted HTML from a server or third party should always pass through sanitization first.

Supply-chain risk is significant because applications pull in many npm packages (CWE-829). A single compromised or typosquatted dependency can run in the build or the browser. Pin versions, review lockfiles, and use dependency scanning. Prefer maintained packages and watch for unmaintained ones (CWE-1104). See `/SECURE_CODING_REFERENCE.md` for dependency management guidance.

Secrets never belong in a client bundle. Anything shipped to the browser is readable, so API keys and tokens must stay on the server. Environment variables prefixed for client exposure are public by design.

## Performance and rendering

Reconciliation is efficient, but unnecessary renders still cost time. Stable keys, memoized components with `React.memo`, and cached callbacks reduce wasted work. Profiling with the React Developer Tools shows which components re-render and why.

Large lists benefit from virtualization libraries that render only visible rows. Code splitting with `React.lazy` and `Suspense` keeps the initial bundle small. Server rendering and streaming improve first paint for content-heavy pages.

Concurrent features let React interrupt rendering to keep the interface responsive. `useTransition` marks non-urgent updates so typing and clicks stay smooth. These tools help, but correct state structure matters more than micro-optimization.

## Common pitfalls

Mutating state directly instead of creating new objects breaks change detection. Always produce new state values rather than editing existing ones. Missing dependency arrays in `useEffect` cause stale closures or infinite loops.

Overusing context for high-frequency updates forces wide re-renders. Keep fast-changing state in a dedicated store instead. Using array indexes as keys in reorderable lists causes subtle rendering bugs.

Fetching data in `useEffect` without cleanup can set state on unmounted components. A data library or an abort signal avoids this. Trusting that escaping covers every case is wrong once `dangerouslySetInnerHTML` or raw URLs enter the code.

## Resources

- The React documentation (official)
- OWASP Cheat Sheet Series, including the DOM-based XSS Prevention Cheat Sheet
- *Learning React* by Alex Banks and Eve Porcello

## Related pages

- [JavaScript](/languages/javascript.md)
- [TypeScript](/languages/typescript.md)
- [Frameworks index](/frameworks/README.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Vue.js](/frameworks/vue.md)
- [Angular](/frameworks/angular.md)
- [Next.js](/frameworks/nextjs.md)
- [Remix](/frameworks/remix.md)
