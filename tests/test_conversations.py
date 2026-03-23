"""Tests for conversation CRUD endpoints."""

import json

import pytest
from httpx import AsyncClient


async def _register_admin(client: AsyncClient) -> str:
    resp = await client.post(
        "/auth/register",
        json={"email": "admin@test.com", "password": "password123", "name": "Admin"},
    )
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_create_conversation(client: AsyncClient):
    token = await _register_admin(client)
    messages = json.dumps([{"role": "user", "content": "Hello"}])

    resp = await client.post(
        "/auth/conversations",
        json={"external_id": "conv-1", "title": "Test Chat", "messages": messages},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["external_id"] == "conv-1"
    assert data["title"] == "Test Chat"
    assert json.loads(data["messages"]) == [{"role": "user", "content": "Hello"}]


@pytest.mark.asyncio
async def test_list_conversations(client: AsyncClient):
    token = await _register_admin(client)

    await client.post(
        "/auth/conversations",
        json={"external_id": "conv-a", "title": "Chat A", "messages": "[]"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await client.post(
        "/auth/conversations",
        json={"external_id": "conv-b", "title": "Chat B", "messages": "[]"},
        headers={"Authorization": f"Bearer {token}"},
    )

    resp = await client.get("/auth/conversations", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_update_conversation(client: AsyncClient):
    token = await _register_admin(client)

    await client.post(
        "/auth/conversations",
        json={"external_id": "conv-up", "title": "Original", "messages": "[]"},
        headers={"Authorization": f"Bearer {token}"},
    )

    new_messages = json.dumps([{"role": "user", "content": "Updated"}])
    resp = await client.put(
        "/auth/conversations/conv-up",
        json={"title": "Updated Title", "messages": new_messages},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Updated Title"


@pytest.mark.asyncio
async def test_delete_conversation(client: AsyncClient):
    token = await _register_admin(client)

    await client.post(
        "/auth/conversations",
        json={"external_id": "conv-del", "title": "Delete Me", "messages": "[]"},
        headers={"Authorization": f"Bearer {token}"},
    )

    resp = await client.delete(
        "/auth/conversations/conv-del",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204

    resp = await client.get(
        "/auth/conversations/conv-del",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_conversation_isolation(client: AsyncClient):
    """User A cannot see User B's conversations."""
    token_a = await _register_admin(client)

    # Register second user
    resp = await client.post(
        "/auth/register",
        json={"email": "b@test.com", "password": "password123", "name": "User B"},
    )
    token_b = resp.json()["access_token"]

    # User A creates a conversation
    await client.post(
        "/auth/conversations",
        json={"external_id": "conv-private", "title": "Private", "messages": "[]"},
        headers={"Authorization": f"Bearer {token_a}"},
    )

    # User B cannot see it
    resp = await client.get(
        "/auth/conversations/conv-private",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_messages_json(client: AsyncClient):
    token = await _register_admin(client)

    resp = await client.post(
        "/auth/conversations",
        json={"external_id": "bad", "title": "Bad", "messages": "not-json"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422
