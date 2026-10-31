# Software frameworks

In-depth reference pages for the application frameworks that most software is built on: backend and full-stack web frameworks, frontend UI frameworks, full-stack meta-frameworks, and mobile and cross-platform frameworks. Each page covers the framework's history and design, its architecture and request or rendering model, routing and data layers, a minimal example, the ecosystem, and, as the point of this library, its security model and the framework-specific weaknesses and misuse that lead to real vulnerabilities.

A framework is not a language: it is a structure and a set of defaults built on top of one. For the languages these frameworks run on, see [All languages](/languages/README.md); for the ways programs are organized, see [Programming paradigms](/paradigms/README.md). For the weaknesses the security sections reference, see the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), the [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), and the [API Security Reference](/API_SECURITY_REFERENCE.md).

Related: [All languages](/languages/README.md), [Programming paradigms](/paradigms/README.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Reference Index](/INDEX.md).

---

## Backend and full-stack web frameworks

| Framework | Summary |
|---|---|
| [Ruby on Rails](/frameworks/rails.md) | Convention-over-configuration MVC framework for Ruby, with Active Record and Hotwire |
| [Django](/frameworks/django.md) | Batteries-included Python framework with an ORM, admin, and strong security defaults |
| [Flask](/frameworks/flask.md) | Minimal Python microframework on Werkzeug and Jinja2, extended through add-ons |
| [FastAPI](/frameworks/fastapi.md) | Async Python framework with type-driven validation and automatic OpenAPI docs |
| [Spring Boot](/frameworks/spring-boot.md) | Auto-configured Java framework over the Spring ecosystem, with Spring Security |
| [ASP.NET Core](/frameworks/aspnet-core.md) | Cross-platform C# framework with a middleware pipeline, MVC, and minimal APIs |
| [Laravel](/frameworks/laravel.md) | Expressive PHP framework with Eloquent ORM, Blade templates, and Artisan |
| [Symfony](/frameworks/symfony.md) | Component-based PHP framework with Doctrine, Twig, and a mature security component |
| [Express.js](/frameworks/express.md) | Minimal unopinionated Node.js framework built around a middleware chain |
| [NestJS](/frameworks/nestjs.md) | Modular TypeScript framework with dependency injection, over Express or Fastify |
| [Phoenix](/frameworks/phoenix.md) | Elixir framework on the BEAM with Ecto and real-time LiveView |
| [Gin](/frameworks/gin.md) | Lightweight Go HTTP framework with a fast router and middleware |
| [Axum](/frameworks/axum.md) | Async Rust web framework on Tokio and Tower, with typed extractors |

## Frontend frameworks

| Framework | Summary |
|---|---|
| [React](/frameworks/react.md) | Component library for building user interfaces with JSX and hooks |
| [Angular](/frameworks/angular.md) | Full TypeScript frontend framework with dependency injection and RxJS |
| [Vue.js](/frameworks/vue.md) | Progressive frontend framework with a reactive component model and single-file components |
| [Svelte](/frameworks/svelte.md) | Compiler-first UI framework with no virtual DOM, and SvelteKit for full-stack apps |

## Full-stack meta-frameworks

| Framework | Summary |
|---|---|
| [Next.js](/frameworks/nextjs.md) | React meta-framework with server components, server-side rendering, and server actions |
| [Nuxt](/frameworks/nuxt.md) | Vue meta-framework with universal rendering and the Nitro server engine |
| [Remix](/frameworks/remix.md) | React meta-framework built on web standards, with server loaders and actions |

## Mobile and cross-platform frameworks

| Framework | Summary |
|---|---|
| [Flutter](/frameworks/flutter.md) | Dart framework rendering its own widgets across iOS, Android, web, and desktop |
| [React Native](/frameworks/react-native.md) | JavaScript framework rendering native iOS and Android components |
| [SwiftUI](/frameworks/swiftui.md) | Declarative UI framework for Apple platforms in Swift |
| [Jetpack Compose](/frameworks/jetpack-compose.md) | Declarative Android UI toolkit in Kotlin |
| [.NET MAUI](/frameworks/dotnet-maui.md) | Single-project C# framework targeting iOS, Android, macOS, and Windows |

## Frameworks and security

Frameworks ship defaults that help or hurt. Most web frameworks escape template output and protect against cross-site request forgery by default, so the common vulnerabilities come from turning those protections off: a raw-HTML helper that reintroduces cross-site scripting (CWE-79), a raw query method that reintroduces SQL injection (CWE-89), mass assignment when request data binds straight to a model (CWE-915). Server-rendering meta-frameworks add a new trust boundary in their server actions and loaders, which must authorize and validate like any endpoint (CWE-862, CWE-918). Mobile frameworks shift the risk to the device: secrets in the app binary, data in insecure local storage, and missing certificate pinning (CWE-312, CWE-798, CWE-295). Each page's security section has the specifics, tied to the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
