# FastAPI

FastAPI is a Python web framework for building HTTP APIs on top of the ASGI standard. It uses standard Python type hints to drive request parsing, validation, and serialization. Teams choose it for its async support, its automatic OpenAPI documentation, and the editor completion that comes from typed signatures.

## Overview and history

FastAPI was first released in 2018 by Sebastián Ramírez. It builds on two existing libraries rather than reinventing them. Starlette supplies the ASGI toolkit, routing, and middleware. Pydantic supplies data validation and settings management.

The framework targets Python 3.8 and later. Its central idea is that a function signature already describes the data a route accepts and returns. FastAPI reads those annotations at startup and turns them into validators, serializers, and an OpenAPI schema.

Adoption grew quickly in data and machine learning teams, where typed request bodies and generated docs reduce glue code. It now appears in general API work, internal services, and gateways in front of model inference.

## Architecture

A FastAPI application is an ASGI app. An ASGI server such as `uvicorn` or `hypercorn` accepts the connection and passes each request to the app as an event. This differs from the older WSGI model, which handles one synchronous request per worker thread.

The request lifecycle starts when the server calls the app with a request scope. Middleware wraps the call stack from the outside in. Starlette's router then matches the path and method to an endpoint.

Before the endpoint runs, FastAPI resolves its declared dependencies and parses inputs. Path parameters, query parameters, headers, and the request body are each extracted and validated against their type hints. A validation failure returns a `422` response with a structured error body, and the endpoint never runs.

The endpoint function returns a Python object. FastAPI serializes it according to the declared `response_model`, filtering fields and coercing types. The result travels back out through the same middleware stack to the client.

Endpoints may be `async def` or plain `def`. Async endpoints run on the event loop. Synchronous endpoints run in a thread pool so a blocking call does not stall the loop. Mixing a blocking library inside an `async def` endpoint is a frequent source of latency.

## Routing, data, and key subsystems

Routes are declared with decorators such as `@app.get` and `@app.post`. The `APIRouter` class groups related routes into modules that mount under a shared prefix. Tags and summaries on each route feed the generated documentation.

Pydantic models define request and response shapes. A model is a class whose attributes carry type annotations and optional constraints. FastAPI uses these models to parse JSON bodies into typed objects and to shape outgoing responses.

Dependency injection is a first-class subsystem. A dependency is a callable declared with `Depends`. FastAPI resolves it per request, caches the result within that request, and injects it into the endpoint. Dependencies handle database sessions, authentication, pagination, and shared setup.

The framework builds an OpenAPI 3 schema from the routes and models. It serves interactive docs at `/docs` using Swagger UI and at `/redoc` using ReDoc. These pages come from the same schema that clients can consume for code generation.

## A minimal example

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Item(BaseModel):
    name: str
    price: float

@app.post("/items/", response_model=Item)
async def create_item(item: Item) -> Item:
    return item
```

## Ecosystem and tooling

`uvicorn` is the common development and production ASGI server, often run behind `gunicorn` with uvicorn workers. `hypercorn` is an alternative that also supports HTTP/2.

Pydantic v2 moved its validation core to Rust, which changed some APIs from v1. Projects pin the major version because model configuration and validators differ between them. SQLModel, from the same author, combines Pydantic models with SQLAlchemy for typed database access.

Testing uses `TestClient`, a wrapper over `httpx` that drives the app without a network socket. `pytest` is the usual runner. For background jobs, teams reach for Celery or ARQ rather than the lightweight `BackgroundTasks` built into the framework.

## Security model and common vulnerabilities

Pydantic models act as an input-validation boundary. Declaring strict types, length limits, and value ranges rejects malformed input before it reaches business logic. This addresses CWE-20 (improper input validation), but only for fields that are actually typed and constrained. A field typed as `dict` or `Any` accepts arbitrary structure and bypasses the boundary. See `/SECURE_CODING_REFERENCE.md` for validation design.

The `fastapi.security` module provides OAuth2 flows, API key schemes, and HTTP bearer helpers. These classes extract credentials from the request but do not verify them. The application must validate tokens itself. A common failure is decoding a JWT without checking the signature or restricting the `alg` header, which allows forged tokens (CWE-347, improper verification of a cryptographic signature). Reject tokens whose algorithm is not on an explicit allowlist, and never accept `none`.

Authentication logic lives in dependencies. Weak or missing checks there produce CWE-287 (improper authentication). Authorization belongs in dependencies too: a dependency that loads the current user and asserts a role or ownership gives a single place to enforce access. Scattering those checks across endpoints invites gaps. See `/API_SECURITY_REFERENCE.md` for authentication and authorization patterns.

CORS is configured with `CORSMiddleware`. Setting `allow_origins=["*"]` together with `allow_credentials=True` is a misconfiguration that exposes authenticated endpoints to any site. List exact origins, and do not reflect the request origin back without a check. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for CORS guidance.

Response models can leak data. Returning an ORM object or a broad model may serialize fields the client should never see, such as password hashes or internal flags (CWE-942 overlaps here on the permissive side, and over-broad responses expose sensitive data). Declare a narrow `response_model` that lists only the fields a caller may read, and keep input and output models separate.

## Performance and scaling

The async model handles many concurrent connections with few threads, which suits I/O-bound workloads such as calling other services or databases. CPU-bound work still blocks the event loop and should move to a worker process or a thread pool.

Horizontal scaling runs several worker processes behind a load balancer or a process manager. Each worker holds its own event loop and connection pools. Database pool sizes must account for the total across all workers so the database is not overwhelmed.

Serialization cost grows with response size. Large payloads spend real time in Pydantic. Streaming responses and pagination keep memory and latency bounded for big result sets.

## Common pitfalls

Calling a blocking library inside an `async def` endpoint stalls every request on that worker. Use an async client or offload the call.

Defining a dependency with per-request state as a module-level singleton shares that state across requests. Scope database sessions and user context to the request.

Forgetting `response_model` returns whatever the function produces, often more than intended. Set it explicitly on routes that touch sensitive records.

Pinning the wrong Pydantic major version breaks validators and model config silently in subtle ways. Match the version your code was written against.

## Resources

- FastAPI documentation, including its Security tutorial
- Pydantic documentation
- OWASP API Security Top 10
- OWASP Cheat Sheet Series

## Related pages

- /languages/python.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /WEB_APPLICATION_SECURITY_REFERENCE.md
- /API_SECURITY_REFERENCE.md
- /frameworks/flask.md
- /frameworks/django.md
- /frameworks/express.md
