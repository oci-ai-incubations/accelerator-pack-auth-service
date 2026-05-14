"""Validation tests for ServiceAccountCreate / ServiceAccountUpdate.

H2 (expires_at unbounded) + H3 (scopes list unbounded). Pydantic rejects bad
input at the API boundary so business logic can trust its inputs.
"""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from accelerator_pack_auth_service.schemas import (
    ServiceAccountCreate,
    ServiceAccountUpdate,
)


def test_expires_at_in_past_rejected():
    past = datetime.now(UTC) - timedelta(minutes=1)
    with pytest.raises(ValidationError, match="expires_at must be in the future"):
        ServiceAccountCreate(name="x", expires_at=past)


def test_expires_at_far_future_rejected():
    far_future = datetime.now(UTC) + timedelta(days=3651)
    with pytest.raises(ValidationError, match="expires_at must be within 10 years"):
        ServiceAccountCreate(name="x", expires_at=far_future)


def test_expires_at_naive_coerced_to_utc():
    """Naive datetimes are tagged as UTC so downstream comparisons stay tz-aware."""
    naive_future = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=30)
    sa = ServiceAccountCreate(name="x", expires_at=naive_future)
    assert sa.expires_at is not None
    assert sa.expires_at.tzinfo is not None


def test_expires_at_mid_range_accepted():
    mid = datetime.now(UTC) + timedelta(days=365)
    sa = ServiceAccountCreate(name="x", expires_at=mid)
    assert sa.expires_at == mid


def test_expires_at_none_accepted():
    sa = ServiceAccountCreate(name="x", expires_at=None)
    assert sa.expires_at is None


def test_scopes_empty_list_accepted():
    sa = ServiceAccountCreate(name="x", scopes=[])
    assert sa.scopes == []


def test_scopes_default_is_empty_list():
    sa = ServiceAccountCreate(name="x")
    assert sa.scopes == []


def test_scopes_at_max_length_accepted():
    sa = ServiceAccountCreate(name="x", scopes=[f"scope.{i}" for i in range(64)])
    assert len(sa.scopes) == 64


def test_scopes_over_max_length_rejected():
    with pytest.raises(ValidationError):
        ServiceAccountCreate(name="x", scopes=[f"scope.{i}" for i in range(65)])


def test_scopes_entry_too_long_rejected():
    too_long = "a" * 129
    with pytest.raises(ValidationError, match="RFC 6749"):
        ServiceAccountCreate(name="x", scopes=[too_long])


def test_scopes_entry_bad_characters_rejected():
    with pytest.raises(ValidationError, match="RFC 6749"):
        ServiceAccountCreate(name="x", scopes=["bad scope with spaces"])


def test_scopes_entry_empty_string_rejected():
    with pytest.raises(ValidationError, match="RFC 6749"):
        ServiceAccountCreate(name="x", scopes=[""])


def test_scopes_valid_punctuation_accepted():
    """``.``, ``-``, ``_``, ``:`` are all valid scope-string characters."""
    sa = ServiceAccountCreate(name="x", scopes=["cuopt.solve", "ns:read-only", "a_b", "1.2.3"])
    assert sa.scopes == ["cuopt.solve", "ns:read-only", "a_b", "1.2.3"]


def test_update_schema_applies_same_constraints():
    past = datetime.now(UTC) - timedelta(minutes=1)
    with pytest.raises(ValidationError, match="expires_at must be in the future"):
        ServiceAccountUpdate(expires_at=past)
    with pytest.raises(ValidationError):
        ServiceAccountUpdate(scopes=[f"s.{i}" for i in range(65)])
