# Vue.js

Vue.js is a frontend framework for building user interfaces and single-page applications. It is written in TypeScript and used with JavaScript or TypeScript. It sits between a view-only library and a full framework, with official routing and state packages available when needed. Teams choose it for its gentle learning curve, readable templates, and incremental adoption.

## Overview and history

Vue was created by Evan You and first released in 2014. It drew ideas from AngularJS and React while aiming for a simpler API. Vue 2 grew a large community, and Vue 3 arrived in 2020 with a rewritten reactivity system.

Vue 3 introduced the Composition API and a faster, Proxy-based reactivity core. It is written in TypeScript and provides strong type support. The project is community driven with a core team rather than a single company owner.

Vue can enhance a small part of an existing page or power a full application. This range makes it easy to adopt gradually.

## Architecture

The reactive component model is the heart of Vue. A component declares reactive state, and the framework tracks which parts of the template read that state. When state changes, only the affected DOM updates. Vue 3 implements this tracking with JavaScript Proxies.

Components are usually written as single-file components in `.vue` files. Each file holds a `<template>`, a `<script>`, and optional `<style>` in one place. This keeps markup, logic, and styles for a component together.

Vue offers two authoring styles. The Options API organizes a component into `data`, `methods`, `computed`, and lifecycle options. The Composition API uses `setup` or `<script setup>` and functions like `ref` and `reactive` to group logic by feature. The Composition API scales better for complex components and shared logic.

Templates use directives, special attributes prefixed with `v-`. `v-if` and `v-for` control rendering, `v-bind` (shorthand `:`) sets attributes, and `v-on` (shorthand `@`) handles events. `v-model` provides two-way binding on form inputs. Computed properties derive values that cache until their dependencies change.

Lifecycle hooks such as `onMounted` and `onUnmounted` run code at defined stages. The template compiler turns templates into render functions ahead of time. That compiled output drives the fast, targeted updates.

## Routing, data, and key subsystems

Vue Router is the official router. It maps URL paths to components, supports nested routes and lazy loading, and provides navigation guards. Guards gate access and can defer navigation until checks complete.

State management has an official library, Pinia, which replaced Vuex as the recommended choice. Pinia stores hold reactive state, getters, and actions with strong TypeScript inference. Vuex remains in older projects but is in maintenance.

Data fetching uses the browser `fetch` API or libraries like Axios, often wrapped in a composable. Libraries such as TanStack Query have Vue adapters for caching and revalidation. Vue's reactivity makes it simple to bind request status to the template.

Build tooling centers on Vite, which the Vue team maintains. Vite gives fast startup and an optimized production build. The official `create-vue` scaffold sets up a project with TypeScript, routing, and testing options.

## A minimal example

```vue
<script setup>
import { ref } from 'vue';

const count = ref(0);
</script>

<template>
  <button @click="count++">Clicked {{ count }} times</button>
</template>
```

## Ecosystem and tooling

Vue's official libraries cover routing, state, and build tooling, which keeps the core ecosystem coherent. Component libraries include Vuetify, PrimeVue, and Element Plus. Headless options and Tailwind CSS are common for custom designs.

Nuxt is the main meta-framework for Vue. It adds file-based routing, server rendering, and data fetching on top of Vue. Teams reach for it when they need SSR or static generation.

Tooling includes the Vue Devtools extension and the Volar language service for editors. Testing uses Vitest with Vue Test Utils. The single-file component format is supported across these tools.

## Security model and common vulnerabilities

Vue escapes content in templates by default. Text interpolated with `{{ }}` and values bound with `v-bind` are escaped, which blocks most cross-site scripting (CWE-79). This default protection holds as long as you render data as text.

The main XSS vector is `v-html`, which inserts raw HTML into an element. Never pass untrusted input to `v-html`, and sanitize any HTML you must render with a vetted library such as DOMPurify. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for input and output rules.

Dynamic binding carries its own risks. Binding a user-controlled value to an `href` or `src` can introduce a `javascript:` URL that runs script. Validate URL schemes before binding them. Dynamic components rendered from untrusted names should be restricted to an allowed set.

Server-side rendering adds injection concerns. Interpolating unescaped data into the rendered HTML stream can break out of context. Use the framework's rendering APIs rather than building HTML strings by hand. A Content Security Policy adds a further layer of defense.

Supply-chain risk applies to every npm dependency (CWE-829). Vue apps pull in the router, state library, and third-party components. Pin versions, scan dependencies, and prefer maintained packages. See `/SECURE_CODING_REFERENCE.md` for dependency management.

## Performance and rendering

Vue's reactivity updates only the parts of the DOM that depend on changed state. The compiler adds hints that skip static content during updates. This keeps most apps fast without manual tuning.

Computed properties cache results and recompute only when dependencies change. Overusing deep watchers or large reactive objects can add overhead. `v-once` and `v-memo` skip re-rendering of stable content.

Lazy-loaded routes and dynamic imports keep the initial bundle small. Nuxt adds server rendering and static generation for faster first paint. Measuring with Vue Devtools shows which components update most often.

## Common pitfalls

Losing reactivity by destructuring a reactive object is a frequent mistake. Use `toRefs` or keep the reference intact. Forgetting that a `ref` needs `.value` in script code causes confusing bugs.

Using array index as the `v-for` key breaks updates on reordered lists. Provide a stable unique key. Mutating props directly violates one-way data flow and triggers warnings.

Reaching for `v-html` to render markup invites XSS when the source is not fully trusted. Treat every use as a security decision. Mixing the Options and Composition APIs in one component without reason reduces readability.

## Resources

- The Vue.js documentation, including its Security guide (official)
- The Vue Router and Pinia documentation (official)
- OWASP Cheat Sheet Series, including the DOM-based XSS Prevention Cheat Sheet

## Related pages

- [JavaScript](/languages/javascript.md)
- [TypeScript](/languages/typescript.md)
- [Frameworks index](/frameworks/README.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [React](/frameworks/react.md)
- [Angular](/frameworks/angular.md)
- [Nuxt](/frameworks/nuxt.md)
- [Svelte](/frameworks/svelte.md)
