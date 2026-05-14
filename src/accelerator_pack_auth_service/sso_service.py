"""SSO service: JIT provisioning, claim-to-role mapping, token bridge.

Security model — what this module defends against:

- **Stolen authorization code replay.** The OIDC ``state`` parameter is
  persisted at ``/authorize`` time and consumed (deleted) on the callback so
  an attacker who replays a victim's callback URL gets ``invalid_state``.
- **ID-token forgery / MITM.** The IdP's ID token is signature-verified
  against the IdP's published JWKS (RS256 by default) before any of its
  claims are trusted. ``iss`` and ``aud`` are checked against the
  provider's registered config. The ``userinfo`` endpoint is consulted ONLY
  as supplemental claim enrichment; we never derive identity from a
  signature-less HTTP response body.
- **Nonce replay.** A fresh ``nonce`` is minted per authorize request and
  verified to match the one inside the ID token's ``nonce`` claim — protects
  against ID-token replay across sessions.

External-identity stability — for IDCS and Entra, ``sub`` is NOT the stable
identifier:

- IDCS: ``sub`` is the user login id (changeable up to 255 ASCII chars); the
  stable identifier is the ``user_id`` GUID claim.
- Entra: ``sub`` is per-app pairwise; the stable identifier is the ``oid``
  object id claim.
- Generic OIDC: ``sub`` is stable by spec and used as the final fallback.

``select_external_id`` codifies the preference order so the persisted
``external_id`` doesn't change underneath us when the operator renames a
user or migrates the app to a new client_id.
"""

import re
import threading
import time
from datetime import UTC, datetime, timedelta

import httpx
import jwt
from fastapi import HTTPException, status
from jwt import PyJWKSet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import create_access_token, create_refresh_token_value, store_refresh_token
from .models import (
    ClaimRoleMapping,
    DbRole,
    ExternalIdentity,
    IdentityProvider,
    Role,
    SsoState,
    User,
    UserRole,
)

# Discovery cache TTL — 1 hour matches the JWKS-cache convention. Long enough
# to keep load off the IdP, short enough that a config rotation propagates
# within the typical incident-response window.
_DISCOVERY_CACHE_TTL = timedelta(hours=1)

# State TTL — 10 minutes per spec D2. Long enough to cover a user's IdP login
# (including MFA prompts); short enough that a leaked state value is useless.
_SSO_STATE_TTL = timedelta(minutes=10)

# Allowable clock skew when verifying ID-token timestamps. IdP clocks drift;
# 60s is the widely-deployed default (e.g. AWS Cognito).
_ID_TOKEN_LEEWAY_SECONDS = 60


_discovery_cache: dict[str, tuple[float, dict]] = {}
_discovery_lock = threading.Lock()


def _discovery_url(issuer: str) -> str:
    """Build the well-known discovery URL, tolerating trailing slashes."""
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


async def discover_oidc_metadata(issuer: str) -> dict:
    """Fetch and cache the IdP's RFC 8414 / OIDC Discovery 1.0 metadata.

    Returns the parsed JSON document. Cached in-process by issuer for
    ``_DISCOVERY_CACHE_TTL``. Raises ``HTTPException(422)`` if the document
    is unreachable or unparseable so provider create/update returns a clear
    "this IdP is misconfigured" signal at registration time, not first-login
    time.

    The cache is keyed by issuer (the canonical identifier in OIDC); rotating
    a provider's IdP issuer creates a fresh cache entry naturally.
    """
    now = time.monotonic()
    with _discovery_lock:
        cached = _discovery_cache.get(issuer)
        if cached and cached[0] > now:
            return cached[1]

    url = _discovery_url(issuer)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"OIDC discovery fetch failed for {issuer}: {exc}",
        ) from exc

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"OIDC discovery returned {resp.status_code} for {issuer}",
        )

    try:
        metadata = resp.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"OIDC discovery document is not valid JSON: {exc}",
        ) from exc

    if not isinstance(metadata, dict) or "issuer" not in metadata or "jwks_uri" not in metadata:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="OIDC discovery document missing required fields (issuer, jwks_uri)",
        )

    with _discovery_lock:
        _discovery_cache[issuer] = (now + _DISCOVERY_CACHE_TTL.total_seconds(), metadata)
    return metadata


def _resolve_oidc_endpoints(config: dict, discovery: dict) -> dict:
    """Resolve the IdP endpoints from operator overrides, then discovery.

    Operator-supplied keys (``token_url``, ``userinfo_url``, ``jwks_url``,
    ``authorize_url``) take precedence so an integrator can pin a specific
    endpoint without losing the discovery default for the others.
    """
    issuer = config.get("issuer", "")
    return {
        "token_url": config.get("token_url") or discovery.get("token_endpoint"),
        "userinfo_url": config.get("userinfo_url") or discovery.get("userinfo_endpoint"),
        "jwks_url": config.get("jwks_url") or discovery.get("jwks_uri"),
        "authorize_url": config.get("authorize_url") or discovery.get("authorization_endpoint"),
        "issuer": discovery.get("issuer") or issuer,
        "id_token_signing_alg_values_supported": discovery.get(
            "id_token_signing_alg_values_supported", ["RS256"]
        ),
    }


# Module-level JWKS cache — one parsed PyJWKSet per jwks_url + the timestamp
# it was fetched at. Reused across requests; refreshed when the cached entry
# is older than _DISCOVERY_CACHE_TTL or when a kid miss demands it. Using
# httpx (vs PyJWKClient's urllib-based fetcher) keeps the I/O path uniform
# and lets respx-based tests stub JWKS endpoints.
_jwks_cache: dict[str, tuple[float, PyJWKSet]] = {}
_jwks_cache_lock = threading.Lock()


# Client-credentials token cache — one bearer per (token_url, client_id) +
# the absolute monotonic time it expires. Used as the OAuth fallback path
# when an IdP's JWKS endpoint is admin-gated (e.g. OCI IAM Identity Domains
# expose ``jwks_uri`` at ``/admin/v1/SigningCert/jwk``, which rejects
# unauthenticated GETs).
_cc_token_cache: dict[tuple[str, str], tuple[float, str]] = {}
_cc_token_cache_lock = threading.Lock()


# Default scope requested when grabbing a client_credentials token to fetch
# admin-gated JWKS. ``urn:opc:idm:__myscopes__`` is the IDCS-specific meta
# scope meaning "all scopes this app has been granted via app roles" —
# operators grant the ``Authenticator Client`` (or equivalent) app role on
# the OAuth client. Override per-provider via ``config.jwks_fallback_scope``.
_DEFAULT_JWKS_FALLBACK_SCOPE = "urn:opc:idm:__myscopes__"

# CC-token cache margin — refresh ``_CC_TOKEN_REFRESH_MARGIN`` seconds before
# the IdP-reported expiry so an in-flight request never trips on a freshly
# expired token. 60s comfortably covers clock skew + JWKS fetch latency.
_CC_TOKEN_REFRESH_MARGIN = 60


async def _client_credentials_token(
    token_url: str,
    client_id: str,
    client_secret: str,
    scope: str | None,
) -> str:
    """Fetch (or return cached) a ``client_credentials`` bearer token.

    Used only as a fallback when the IdP gates its JWKS endpoint behind
    OAuth. The token is cached per ``(token_url, client_id)`` until
    ``_CC_TOKEN_REFRESH_MARGIN`` seconds before the IdP-reported ``expires_in``.
    """
    cache_key = (token_url, client_id)
    now = time.monotonic()
    with _cc_token_cache_lock:
        cached = _cc_token_cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]

    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_url,
            data=data,
            auth=(client_id, client_secret),
            headers={"Accept": "application/json"},
        )
    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Client-credentials token fetch failed ({resp.status_code}) "
                f"at {token_url}: {resp.text}"
            ),
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Client-credentials response at {token_url} was not JSON",
        ) from exc

    access_token = payload.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Client-credentials response at {token_url} missing access_token",
        )

    expires_in = int(payload.get("expires_in", 300))
    ttl = max(expires_in - _CC_TOKEN_REFRESH_MARGIN, 30)
    with _cc_token_cache_lock:
        _cc_token_cache[cache_key] = (now + ttl, access_token)
    return access_token


async def _fetch_jwks(
    jwks_url: str,
    *,
    oauth_fallback: tuple[str, str, str, str | None] | None = None,
) -> PyJWKSet:
    """Fetch (or return cached) PyJWKSet for ``jwks_url``.

    ``oauth_fallback`` — when supplied as
    ``(token_url, client_id, client_secret, scope)``, a 401 from the
    unauthenticated GET triggers a ``client_credentials`` grant against
    ``token_url`` and a retry with ``Authorization: Bearer``. This
    accommodates IdPs whose JWKS endpoint is admin-gated (OCI IAM Identity
    Domains, in particular, expose ``jwks_uri`` at
    ``/admin/v1/SigningCert/jwk`` which rejects anonymous requests). The
    fallback is opt-in — passing ``None`` preserves the strict public-JWKS
    behavior expected of standards-compliant OIDC providers.
    """
    now = time.monotonic()
    with _jwks_cache_lock:
        cached = _jwks_cache.get(jwks_url)
        if cached and cached[0] > now:
            return cached[1]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(jwks_url)
        if resp.status_code == 401 and oauth_fallback is not None:
            token_url, client_id, client_secret, scope = oauth_fallback
            bearer = await _client_credentials_token(token_url, client_id, client_secret, scope)
            resp = await client.get(
                jwks_url,
                headers={"Authorization": f"Bearer {bearer}"},
            )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"JWKS fetch failed ({resp.status_code}) for {jwks_url}",
        )
    try:
        jwks = PyJWKSet.from_dict(resp.json())
    except (ValueError, jwt.InvalidKeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid JWKS at {jwks_url}: {exc}",
        ) from exc

    with _jwks_cache_lock:
        _jwks_cache[jwks_url] = (now + _DISCOVERY_CACHE_TTL.total_seconds(), jwks)
    return jwks


def _verify_id_token_with_jwks(
    id_token: str,
    *,
    jwks: PyJWKSet,
    audience: str,
    issuer: str,
    expected_nonce: str | None,
    allowed_algs: list[str],
) -> dict:
    """Verify an IdP-issued ID token's signature and standard claims.

    Threat model: a malicious or compromised network path could MITM the
    userinfo response and inject arbitrary claims. Verifying the *signed*
    ID token first means every claim we later trust (sub/oid/user_id, email,
    name) is cryptographically attested by the IdP's private key.

    Raises :class:`HTTPException(401)` on any failure — signature mismatch,
    wrong issuer, wrong audience, expired token, or nonce mismatch.
    """
    try:
        unverified_header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid ID token from IdP: {exc}",
        ) from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ID token missing kid header",
        )

    try:
        signing_key = jwks[kid]
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"ID token signed by unknown key {kid}",
        ) from exc

    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=allowed_algs,
            audience=audience,
            issuer=issuer,
            leeway=_ID_TOKEN_LEEWAY_SECONDS,
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_iat": True,
            },
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid ID token from IdP: {exc}",
        ) from exc

    if expected_nonce is not None:
        token_nonce = claims.get("nonce")
        if not token_nonce or token_nonce != expected_nonce:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="ID token nonce mismatch",
            )

    return claims


def select_external_id(claims: dict) -> str:
    """Pick the stable external identifier from IdP claims.

    Preference order:

    1. ``oid`` — Microsoft Entra object id (stable across tenant, app, and
       user-principal rename).
    2. ``user_id`` — Oracle IDCS user GUID (stable across login-id rename).
    3. ``sub`` — generic OIDC subject (stable per OIDC §2; safe fallback).

    Returns an empty string when none of the claims is present — callers
    should treat that as a misconfigured IdP and abort.
    """
    for key in ("oid", "user_id", "sub"):
        value = claims.get(key)
        if value:
            return str(value)
    return ""


async def jit_provision_user(
    db: AsyncSession,
    provider: IdentityProvider,
    external_id: str,
    email: str,
    name: str,
    raw_claims: dict | None = None,
) -> tuple[User, bool]:
    """Just-In-Time provision a user from SSO.

    Returns (user, created) — created=True if this is a new user.
    """
    # Check for existing external identity link
    result = await db.execute(
        select(ExternalIdentity).where(
            ExternalIdentity.provider_id == provider.id,
            ExternalIdentity.external_id == external_id,
        )
    )
    ext_identity = result.scalar_one_or_none()

    if ext_identity:
        # Existing user — update last login and claims
        ext_identity.last_login_at = datetime.now(UTC)
        ext_identity.raw_claims = raw_claims
        await db.commit()

        user_result = await db.execute(select(User).where(User.id == ext_identity.user_id))
        user = user_result.scalar_one()
        return user, False

    # Check if a user with this email already exists (link accounts)
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()

    created = False
    if not user:
        # Create new user with default role
        user = User(
            email=email,
            name=name,
            password_hash="!sso-only",  # noqa: S106 — sentinel that fails bcrypt.verify; SSO-provisioned users have no password path
            role=Role.user,  # SSO users get 'user' role by default
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        created = True

    # Link external identity
    ext_identity = ExternalIdentity(
        user_id=user.id,
        provider_id=provider.id,
        external_id=external_id,
        email=email,
        raw_claims=raw_claims,
        last_login_at=datetime.now(UTC),
    )
    db.add(ext_identity)
    await db.commit()

    return user, created


async def apply_claim_mappings(
    db: AsyncSession,
    provider: IdentityProvider,
    user: User,
    claims: dict,
) -> list[str]:
    """Apply claim-to-role mappings for a provider. Returns list of assigned role names."""
    result = await db.execute(
        select(ClaimRoleMapping)
        .where(ClaimRoleMapping.provider_id == provider.id)
        .order_by(ClaimRoleMapping.priority.desc())
    )
    mappings = result.scalars().all()
    assigned_roles = []

    for mapping in mappings:
        claim_value = claims.get(mapping.claim_key)
        if claim_value is None:
            continue

        # Support claim values that are lists (e.g., groups)
        values = claim_value if isinstance(claim_value, list) else [claim_value]

        for val in values:
            val_str = str(val)
            matched = False
            if mapping.is_regex:
                matched = bool(re.search(mapping.claim_value_pattern, val_str))
            else:
                matched = val_str == mapping.claim_value_pattern

            if matched:
                # Assign role if not already assigned
                existing = await db.execute(
                    select(UserRole).where(
                        UserRole.user_id == user.id,
                        UserRole.role_id == mapping.role_id,
                    )
                )
                if not existing.scalar_one_or_none():
                    db.add(
                        UserRole(
                            user_id=user.id,
                            role_id=mapping.role_id,
                            created_at=datetime.now(UTC),
                        )
                    )
                    # Get role name
                    role_result = await db.execute(
                        select(DbRole).where(DbRole.id == mapping.role_id)
                    )
                    role = role_result.scalar_one_or_none()
                    if role:
                        assigned_roles.append(role.name)
                break  # First match per claim key wins

    if assigned_roles:
        await db.commit()
    return assigned_roles


async def store_sso_state(
    db: AsyncSession, *, provider_id: int, redirect_uri: str
) -> tuple[str, str]:
    """Mint and persist a single-use ``(state, nonce)`` pair for an authorize call.

    Returns ``(state, nonce)``. The row is keyed on ``state`` (PK); the
    nonce is round-tripped through the IdP via the ``nonce`` request
    parameter and verified inside the ID token at callback time.
    """
    import secrets

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    row = SsoState(
        state=state,
        nonce=nonce,
        provider_id=provider_id,
        redirect_uri=redirect_uri,
        expires_at=datetime.now(UTC) + _SSO_STATE_TTL,
    )
    db.add(row)
    await db.commit()
    return state, nonce


async def consume_sso_state(db: AsyncSession, *, state: str, provider_id: int) -> SsoState:
    """Look up + delete an SSO state row; raise if missing, expired, or wrong provider.

    Single-use semantics: the row is deleted on successful consume so a
    replayed callback returns ``invalid_state`` even if it carries the
    same state value.
    """
    result = await db.execute(select(SsoState).where(SsoState.state == state))
    row = result.scalar_one_or_none()
    if row is None or row.provider_id != provider_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_state", "error_description": "Unknown state"},
        )

    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(UTC):
        await db.delete(row)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_state", "error_description": "State expired"},
        )

    await db.delete(row)
    await db.commit()
    return row


async def exchange_oidc_code(
    provider: IdentityProvider,
    code: str,
    redirect_uri: str,
    *,
    expected_nonce: str | None = None,
) -> dict:
    """Exchange an OIDC authorization code at the IdP and return verified claims.

    Steps:

    1. Resolve token / userinfo / JWKS / authorize URLs via OIDC discovery
       (operator overrides win where set).
    2. POST the auth code to the IdP token endpoint with our client creds.
    3. Verify the returned ID token's signature against the IdP JWKS,
       check ``iss``, ``aud``, ``exp``, and the ``nonce`` we minted.
    4. Optionally enrich claims via the userinfo endpoint, but only after
       the ID token has been cryptographically validated — the userinfo
       response is HTTPS-only and is NOT a source of trusted identity by
       itself.

    Returns the merged claims dict for downstream JIT-provisioning.
    """
    config = provider.config or {}
    issuer = config.get("issuer", "")
    client_id = config.get("client_id", "")
    client_secret = config.get("client_secret", "")

    discovery = await discover_oidc_metadata(issuer)
    endpoints = _resolve_oidc_endpoints(config, discovery)
    token_url = endpoints["token_url"]
    userinfo_url = endpoints["userinfo_url"]
    jwks_url = endpoints["jwks_url"]
    canonical_issuer = endpoints["issuer"]
    allowed_algs = endpoints["id_token_signing_alg_values_supported"] or ["RS256"]

    if not token_url or not jwks_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="OIDC provider missing token_endpoint or jwks_uri",
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
            headers={"Accept": "application/json"},
        )

        if token_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"IdP token exchange failed: {token_resp.text}",
            )

        tokens = token_resp.json()
        id_token = tokens.get("id_token", "")
        if not id_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="IdP token response missing id_token",
            )

        jwks_fallback: tuple[str, str, str, str | None] | None = None
        if token_url and client_id and client_secret:
            jwks_fallback = (
                token_url,
                client_id,
                client_secret,
                config.get("jwks_fallback_scope", _DEFAULT_JWKS_FALLBACK_SCOPE),
            )

        jwks = await _fetch_jwks(jwks_url, oauth_fallback=jwks_fallback)
        claims = _verify_id_token_with_jwks(
            id_token,
            jwks=jwks,
            audience=client_id,
            issuer=canonical_issuer,
            expected_nonce=expected_nonce,
            allowed_algs=allowed_algs,
        )

        # Optional userinfo enrichment — only AFTER the ID token has been
        # cryptographically validated. Userinfo claims merge into the verified
        # set but cannot override the signed identity ones.
        if userinfo_url:
            access_token = tokens.get("access_token", "")
            if access_token:
                userinfo_resp = await client.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if userinfo_resp.status_code == 200:
                    userinfo_claims = userinfo_resp.json()
                    if isinstance(userinfo_claims, dict):
                        for key, value in userinfo_claims.items():
                            claims.setdefault(key, value)

        return claims


async def issue_sso_tokens(
    db: AsyncSession,
    user: User,
) -> tuple[str, str]:
    """Issue internal JWT tokens after SSO authentication.

    Scopes default-resolve from the user's role expansion (or
    ``allowed_scopes`` override if set) per spec 003. SSO callers can't
    request a narrower per-token scope today — the IdP callback is a coarse
    login flow, not an OAuth2 grant.
    """
    access_token = await create_access_token(db, user)
    refresh_value = create_refresh_token_value()
    await store_refresh_token(db, user.id, refresh_value)
    return access_token, refresh_value
