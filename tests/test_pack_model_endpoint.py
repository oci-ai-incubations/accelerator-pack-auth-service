"""GET /auth/pack/model returns the active model and is public.

The endpoint is pure (just reads the active pack model and dumps it). To
keep this test isolated from the global FastAPI app's lifespan — which
otherwise runs alembic + seeds roles and pollutes the session-shared DB
engine — we mount the same handler on a small standalone app.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from accelerator_pack_auth_service.config import settings
from accelerator_pack_auth_service.pack_models import load_active_model


def _make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/auth/pack/model")
    async def get_pack_model() -> dict:
        return load_active_model(settings.pack).model_dump()

    return app


def test_pack_model_endpoint_returns_active_model(monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    client = TestClient(_make_app())
    r = client.get("/auth/pack/model")
    assert r.status_code == 200
    body = r.json()
    assert body["pack_id"] == "cuopt"
    assert "admin" in body["roles"]
    assert "user" in body["roles"]
    assert "reader" in body["roles"]
    assert "cuopt.solve" in body["permissions"]
    assert body["role_permissions"]["reader"] == ["cuopt.view", "config.read"]


def test_pack_model_endpoint_no_auth_required(monkeypatch):
    monkeypatch.setattr(settings, "pack", "cuopt")
    client = TestClient(_make_app())
    r = client.get("/auth/pack/model")
    assert r.status_code == 200


def test_pack_model_endpoint_unknown_pack_falls_back(monkeypatch):
    monkeypatch.setattr(settings, "pack", "nope")
    client = TestClient(_make_app())
    r = client.get("/auth/pack/model")
    assert r.status_code == 200
    assert r.json()["pack_id"] == "base"
