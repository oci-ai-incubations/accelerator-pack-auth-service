"""OAuth2 scope resolution and grant logic (spec 003).

Scopes ride in the JWT ``scope`` claim as a space-separated string per
RFC 6749 §3.3. The functions here decouple two concerns:

- :func:`resolve_principal_scopes` — given a principal (User or
  ServiceAccount) and the active pack model, what set of scopes is this
  principal *allowed* to receive?
- :func:`grant_scopes` — given that allowed set and a per-issuance request
  string, what scopes does the issued token actually carry?

Split into a separate module so unit tests can exercise the pure logic
without booting the FastAPI app or the DB.
"""

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import DbRole, Permission, RolePermission, ServiceAccount, User, UserRole
from .pack_models import PackAuthModel

# Wildcard sentinel: a principal whose stamped scope set contains this token
# is allowed every codename the active pack declares. We expand the wildcard
# at issuance so verifiers never need wildcard logic on the read path — the
# scope claim that ships in the token is the fully-enumerated list.
SCOPE_WILDCARD = "*"


def serialize_scopes(scopes: list[str]) -> str:
    """Encode a list of scope codenames as the JSON column representation."""
    return json.dumps(list(scopes))


def deserialize_scopes(raw: str | None) -> list[str]:
    """Decode the JSON-encoded scopes column back into a list.

    Returns the empty list for None / empty input or any payload that isn't
    a JSON list — corrupt rows fail closed rather than authorize unexpected
    shapes.
    """
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(s) for s in decoded] if isinstance(decoded, list) else []


class InvalidScopeError(ValueError):
    """Raised when scope-grant validation fails per RFC 6749 §5.2 invalid_scope.

    Two failure modes the OAuth2 token endpoint maps to ``invalid_scope``:

    1. The requested set has no intersection with the allowed set (the caller
       asked for scopes they cannot ever have).
    2. The auth service is configured for strict scope-grant (the
       ``auth_strict_scopes`` setting is true) and the request asked for at
       least one scope outside the allowed set.

    Lenient mode (the default) returns the intersection silently for partial
    overlaps; the second failure mode only fires under strict mode.
    """


def parse_scope_string(raw: str | None) -> list[str]:
    """Split an RFC 6749 §3.3 space-delimited scope string into a list.

    Empty / None / whitespace-only input returns an empty list. Internal
    whitespace runs (multiple spaces or tabs) are collapsed by ``str.split``.
    Order is preserved; duplicates are NOT deduped — the caller decides
    whether to ``set()`` after parsing (intersection logic wants set
    semantics; logging the raw request wants the original order).
    """
    if not raw:
        return []
    return raw.split()


def resolve_principal_scopes(
    principal: User | ServiceAccount, pack_model: PackAuthModel
) -> list[str]:
    """Resolve the full set of scopes a principal is permitted to hold.

    For service accounts, that's the static list stamped on the row when the
    admin registered the client. For users with an explicit
    ``allowed_scopes`` override, that JSON-encoded list. For users with no
    override (the default), the pack model's role-to-permission expansion.

    Wildcards are always expanded here so verifiers never need wildcard
    logic on the read path. A user (or service account) stamped with
    ``["*"]`` gets the active pack's full permission set for their role —
    we never ship the literal ``*`` in the scope claim (spec 003 line 103).
    """
    if isinstance(principal, ServiceAccount):
        stamped = deserialize_scopes(principal.scopes)
        if SCOPE_WILDCARD in stamped:
            # ServiceAccounts have no role; the wildcard expands to the
            # pack's full permission vocabulary so admin-issued integrations
            # carry an enumerated claim.
            return list(pack_model.permissions)
        return stamped

    role_value = principal.role.value if hasattr(principal.role, "value") else str(principal.role)

    if principal.allowed_scopes:
        decoded = deserialize_scopes(principal.allowed_scopes)
        if SCOPE_WILDCARD in decoded:
            return pack_model.permissions_for_role(role_value)
        return decoded

    return pack_model.permissions_for_role(role_value)


def grant_scopes(allowed: list[str], requested: list[str] | None, *, strict: bool) -> list[str]:
    """Compute the scope set to stamp on a token.

    When ``requested`` is None or empty the issued set is the full allowed
    set — RFC 6749 §3.3 calls this out as the "no scope requested" path. When
    ``requested`` is non-empty:

    - In lenient mode (the default, ``strict=False``), the granted set is the
      intersection of requested and allowed. A non-empty request that
      *partially* overlaps yields a partial token; a non-empty request that
      has *no* overlap raises ``InvalidScopeError`` because issuing an empty-
      scope token would silently neuter the caller's intent.
    - In strict mode, any requested scope outside the allowed set raises
      ``InvalidScopeError`` — useful for integrators who want loud failures.

    Preserves the order of ``allowed`` so two callers requesting the same
    scopes in different orders get byte-identical token claims (which
    simplifies caching upstream).
    """
    if not requested:
        return list(allowed)

    allowed_set = set(allowed)
    granted = [s for s in allowed if s in set(requested)]

    if strict:
        missing = set(requested) - allowed_set
        if missing:
            joined = " ".join(sorted(missing))
            raise InvalidScopeError(f"requested scopes not allowed: {joined}")

    if not granted:
        unallowed = " ".join(sorted(set(requested) - allowed_set))
        raise InvalidScopeError(f"requested scopes not allowed: {unallowed}")

    return granted


async def fetch_user_role_permissions(db: AsyncSession, user_id: int) -> set[str]:
    """Return permission codenames reachable from a user's UserRole assignments.

    Walks UserRole → DbRole → RolePermission → Permission. The same join the
    runtime permission check at ``permission_service.user_has_permission``
    uses, but returned as a set for unioning into a JWT scope claim at token-
    issue time.

    Callers should union this set with the principal's primary-role scopes
    from :func:`resolve_principal_scopes` when minting tokens; otherwise the
    JWT under-advertises and FEs that gate on the ``scope`` claim will deny
    actions the BE would actually authorize.
    """
    result = await db.execute(
        select(Permission.codename)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(DbRole, DbRole.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == DbRole.id)
        .where(UserRole.user_id == user_id)
        .distinct()
    )
    return {row[0] for row in result.all()}
