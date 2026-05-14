"""Smoke tests for the public OpenAPI spec.

Spec 000: every route in the published spec must carry a non-empty
``summary``, ``description``, and at least one documented response code. The
spec is the integration contract — these checks catch undocumented routes
sneaking in.
"""

import pytest

from accelerator_pack_auth_service.main import OPENAPI_TAGS

# Routes that are intentionally public (no bearer token required). Anything
# else with ``security: []`` is a downgrade and the suite fails. Mirror
# `openapi_extra={"security": []}` on the route decorator with this list.
PUBLIC_PATHS: set[tuple[str, str]] = {
    ("get", "/auth/health"),
    ("get", "/auth/alive"),
    ("get", "/auth/pack/model"),
    ("post", "/auth/register"),
    ("post", "/auth/login"),
    ("post", "/auth/refresh"),
    ("post", "/auth/sso/callback"),
    ("get", "/auth/sso/providers"),
    ("get", "/auth/sso/{slug}/authorize"),
    ("post", "/auth/sso/{slug}/token"),
    ("post", "/auth/oauth/token"),
    ("get", "/auth/.well-known/jwks.json"),
    ("get", "/auth/.well-known/openid-configuration"),
    ("get", "/auth/.well-known/oauth-authorization-server"),
}


@pytest.mark.asyncio
async def test_openapi_json_is_public_and_valid(client):
    """GET /openapi.json is public, returns JSON, and advertises an info.version."""
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    spec = response.json()
    assert spec["openapi"].startswith("3.")
    assert spec["info"]["title"] == "OCI AI Accelerator Auth Service"
    assert spec["info"]["version"]
    assert spec["info"]["description"]


@pytest.mark.asyncio
async def test_docs_endpoints_are_public(client):
    """Swagger UI and ReDoc are always reachable without auth."""
    docs = await client.get("/docs")
    assert docs.status_code == 200
    redoc = await client.get("/redoc")
    assert redoc.status_code == 200


@pytest.mark.asyncio
async def test_every_route_has_summary_description_and_responses(client):
    """Every documented operation has a non-empty summary, description, and ≥1 response."""
    response = await client.get("/openapi.json")
    spec = response.json()

    missing: list[str] = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not op.get("summary"):
                missing.append(f"{method.upper()} {path}: missing summary")
            if not op.get("description"):
                missing.append(f"{method.upper()} {path}: missing description")
            if not op.get("responses"):
                missing.append(f"{method.upper()} {path}: missing responses")

    assert not missing, "Undocumented routes:\n" + "\n".join(missing)


@pytest.mark.asyncio
async def test_bearer_auth_security_scheme_declared(client):
    """The custom_openapi() hook should declare a bearerAuth scheme."""
    response = await client.get("/openapi.json")
    spec = response.json()
    schemes = spec.get("components", {}).get("securitySchemes", {})
    assert "bearerAuth" in schemes
    assert schemes["bearerAuth"]["type"] == "http"
    assert schemes["bearerAuth"]["scheme"] == "bearer"
    assert schemes["bearerAuth"]["bearerFormat"] == "JWT"


@pytest.mark.asyncio
async def test_default_security_applies_bearer_globally(client):
    """Top-level security default makes routes require bearerAuth unless they opt out."""
    response = await client.get("/openapi.json")
    spec = response.json()
    assert {"bearerAuth": []} in spec.get("security", [])


@pytest.mark.asyncio
async def test_only_allowlisted_routes_opt_out_of_bearer(client):
    """No route may declare ``security: []`` unless it is in ``PUBLIC_PATHS``.

    Catches the downgrade where a future PR adds ``openapi_extra={"security": []}``
    to an authenticated route. Also asserts every allowlisted route DOES declare
    it (catches the inverse drift — a route quietly gaining a token requirement).
    """
    response = await client.get("/openapi.json")
    spec = response.json()

    declared_public: set[tuple[str, str]] = set()
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            if op.get("security") == []:
                declared_public.add((method, path))

    unexpected = declared_public - PUBLIC_PATHS
    missing = PUBLIC_PATHS - declared_public
    assert not unexpected, (
        "Routes silently downgraded to public (add to PUBLIC_PATHS if intentional):\n  "
        + "\n  ".join(f"{m.upper()} {p}" for m, p in sorted(unexpected))
    )
    assert not missing, (
        "Allowlisted public routes missing security=[] declaration:\n  "
        + "\n  ".join(f"{m.upper()} {p}" for m, p in sorted(missing))
    )


@pytest.mark.asyncio
async def test_every_route_has_at_least_one_tag(client):
    """A route with no ``tags`` renders under "default" in Swagger and bypasses the tag taxonomy."""
    response = await client.get("/openapi.json")
    spec = response.json()

    untagged: list[str] = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not op.get("tags"):
                untagged.append(f"{method.upper()} {path}")

    assert not untagged, "Routes missing tags:\n  " + "\n  ".join(untagged)


@pytest.mark.asyncio
async def test_every_used_tag_is_declared_in_openapi_tags(client):
    """Bidirectional: every tag on a route is declared in OPENAPI_TAGS, and every
    declared tag is used by at least one route (catches typos like
    ``Authenitcation`` and orphan tags after a rename).
    """
    response = await client.get("/openapi.json")
    spec = response.json()

    declared = {tag["name"] for tag in OPENAPI_TAGS}
    used: set[str] = set()
    for methods in spec.get("paths", {}).values():
        for method, op in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            used.update(op.get("tags") or [])

    unknown = used - declared
    orphan = declared - used
    assert not unknown, f"Routes use tags not in OPENAPI_TAGS: {sorted(unknown)}"
    assert not orphan, f"OPENAPI_TAGS declares unused tags: {sorted(orphan)}"
