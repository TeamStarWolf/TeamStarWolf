# Django

Django is a server-side web framework written in Python. It follows a Model-Template-View pattern and ships with an ORM, an admin site, and a strong security posture. Teams use it to build database-backed applications with batteries included, so authentication, forms, and migrations come in the box. It suits content sites, internal tools, and JSON APIs through Django REST Framework.

## Overview and history

Django grew out of a newspaper web operation in Lawrence, Kansas, and was released publicly in 2005. Its origins explain a focus on fast, content-heavy development and a reusable admin interface. The Django Software Foundation now stewards the project.

The framework values explicit configuration and included components. Rather than assembling many small libraries, you get a coordinated stack. Long-term support releases give teams a predictable upgrade path.

Django favors clear structure over magic. Applications are organized as reusable apps inside a project. This modularity lets teams share functionality across projects.

## Architecture

Django names its pattern Model-Template-View, which maps to the familiar Model-View-Controller idea. A request enters through the WSGI or ASGI handler. Middleware processes the request in order, handling sessions, authentication, CSRF, and security headers. The URL resolver then matches the path to a view.

A view is a callable that takes a request and returns a response. Views can be plain functions or class-based views that provide reusable behavior for common patterns. Class-based generic views handle list, detail, create, and update flows with little code. The view queries models, then renders a template or serializes data.

Models are Python classes that subclass `models.Model`. Each model maps to a database table, and each attribute maps to a column. The ORM translates method calls into SQL and returns model instances. Migrations are generated files that evolve the schema as models change.

Templates render HTML with the Django template language. The template layer autoescapes variables by default to prevent injection. The admin reads model metadata and builds a working management interface automatically. These layers connect through settings and explicit URL configuration.

## Routing, data, and key subsystems

URLs are declared in `urls.py` with path patterns that map to views. Patterns capture typed parameters and can be named for reverse lookups. Apps include their own URL modules, which the project combines.

The ORM is a central subsystem. QuerySets are lazy and chainable, so `Article.objects.filter(published=True).order_by("-created")` builds one parameterized query. Migrations keep the schema in sync and are tracked in version control. The `makemigrations` and `migrate` commands generate and apply them.

The admin is a notable subsystem. Registering a model exposes create, read, update, and delete screens for staff users. Middleware is an ordered pipeline that wraps every request and response. Django REST Framework adds serializers, viewsets, and routers for building JSON APIs on the same models.

## A minimal example

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("articles/<int:pk>/", views.article_detail, name="article-detail"),
]

# views.py
from django.shortcuts import render, get_object_or_404
from .models import Article

def article_detail(request, pk):
    article = get_object_or_404(Article, pk=pk, published=True)
    return render(request, "articles/detail.html", {"article": article})
```

## Ecosystem and tooling

Packages are installed from PyPI with `pip`, usually inside a virtual environment. The `manage.py` script runs migrations, the development server, the shell, and tests. Django ships a test runner built on Python's `unittest`, and `pytest-django` is a common alternative.

Django REST Framework is the standard choice for APIs. Celery runs background tasks, and Channels adds WebSocket support over ASGI. Gunicorn and uWSGI serve the application in production, often behind Nginx. Bandit and `pip-audit` scan code and dependencies for known issues.

## Security model and common vulnerabilities

Django has a careful security design, and its documented defaults block many common attacks. See `/SECURE_CODING_REFERENCE.md`, `/WEB_APPLICATION_SECURITY_REFERENCE.md`, and `/API_SECURITY_REFERENCE.md` for shared guidance.

The template engine autoescapes output, which blocks most cross-site scripting (CWE-79). Marking a string with `mark_safe` or using the `|safe` filter disables escaping. Only apply those to trusted content. The `format_html` helper escapes arguments while building markup.

CSRF protection (CWE-352) runs as middleware and requires a token in POST forms. The `{% csrf_token %}` tag inserts it. Removing `CsrfViewMiddleware` or decorating views with `csrf_exempt` without a replacement check exposes state-changing endpoints.

The ORM parameterizes queries, which prevents SQL injection (CWE-89) in normal use. Risk returns through `Model.objects.raw()` and `QuerySet.extra()` when you interpolate input into SQL strings. Pass parameters as arguments rather than building the string yourself. Avoid `extra()` entirely where a QuerySet expression works.

The `SECRET_KEY` signs sessions, cookies, and password reset tokens. Leaking it lets an attacker forge signed values, so keep it out of version control and rotate it if exposed. Running with `DEBUG = True` in production discloses settings, stack traces, and SQL in error pages (CWE-215). Set `DEBUG = False` and configure `ALLOWED_HOSTS`. The `XFrameOptionsMiddleware` sets the `X-Frame-Options` header to defend against clickjacking.

## Performance and scaling

The N+1 query problem is the most frequent slowdown; use `select_related` for foreign keys and `prefetch_related` for many-to-many links. The per-site and per-view cache framework stores rendered output in Redis or Memcached. Database connection pooling and persistent connections reduce overhead.

Horizontal scaling runs several application processes behind a load balancer, with the database and cache as shared state. Offload slow work to Celery. ASGI deployment with Channels or async views helps with concurrent, long-lived connections.

## Common pitfalls

Leaving `DEBUG = True` in production is the classic deployment mistake. Forgetting database indexes on filtered and foreign-key columns slows queries at scale. Overusing signals scatters side effects and complicates tests.

Fat views and models that mix concerns grow hard to maintain. Serializing sensitive fields through DRF without explicit field lists can leak data. Trusting `extra()` or `raw()` with user input reopens SQL injection.

## Resources

- Django documentation, the official reference
- Django Security topic guide, the official security chapter
- OWASP Django Cheat Sheet
- *Two Scoops of Django* by Daniel and Audrey Feldroy
- OWASP Top 10

## Related pages

- [Python](/languages/python.md)
- [Frameworks index](/frameworks/README.md)
- [Secure coding reference](/SECURE_CODING_REFERENCE.md)
- [Web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API security reference](/API_SECURITY_REFERENCE.md)
- [Flask](/frameworks/flask.md)
- [FastAPI](/frameworks/fastapi.md)
- [Rails](/frameworks/rails.md)
