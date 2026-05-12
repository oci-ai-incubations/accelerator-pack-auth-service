"""GET /auth/pack/model returns the active model and is public.

Tests hit the registered route on the production app (via the session-shared
async client fixture) so a regression that removes the @app.get decorator
would actually fail.
"""

import pytest
from httpx import AsyncClient

from accelerator_pack_auth_service.config import settings


@pytest.mark.asyncio
async def test_pack_model_endpoint_returns_active_model(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "pack", "cuopt")
    r = await client.get("/auth/pack/model")
    assert r.status_code == 200
    body = r.json()
    assert body["pack_id"] == "cuopt"
    assert "admin" in body["roles"]
    assert "user" in body["roles"]
    assert "reader" in body["roles"]
    assert "cuopt.solve" in body["permissions"]
    assert body["role_permissions"]["reader"] == ["cuopt.view", "config.read"]


@pytest.mark.asyncio
async def test_pack_model_endpoint_no_auth_required(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "pack", "cuopt")
    r = await client.get("/auth/pack/model")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_pack_model_endpoint_unknown_pack_falls_back(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "pack", "nope")
    r = await client.get("/auth/pack/model")
    assert r.status_code == 200
    assert r.json()["pack_id"] == "base"
