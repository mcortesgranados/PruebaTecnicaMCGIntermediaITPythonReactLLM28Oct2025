"""Unit tests for REST controllers (POST /messages)."""
from fastapi.testclient import TestClient
from src.secure_message_service.adapter.rest.main import app

client = TestClient(app)


def test_health():
    resp = client.get('/health')
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_message_missing_jwt():
    payload = {"user_id": "00000000-0000-0000-0000-000000000000", "content": "Hello"}
    resp = client.post('/api/v1/messages', json=payload)
    assert resp.status_code == 403


def test_create_message_invalid_token_format():
    payload = {"user_id": "00000000-0000-0000-0000-000000000000", "content": "Hello"}
    headers = {"Authorization": "Bearer badtoken"}
    resp = client.post('/api/v1/messages', json=payload, headers=headers)
    assert resp.status_code == 403


def test_create_message_forbidden_role():
    payload = {"user_id": "00000000-0000-0000-0000-000000000000", "content": "Hello"}
    headers = {"Authorization": "Bearer sub:guest"}
    resp = client.post('/api/v1/messages', json=payload, headers=headers)
    assert resp.status_code == 403


def test_create_message_success():
    payload = {"user_id": "00000000-0000-0000-0000-000000000000", "content": "Hello <script>alert(1)</script> World"}
    headers = {"Authorization": "Bearer 123:user"}
    resp = client.post('/api/v1/messages', json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert 'message_id' in data
    assert data['status'] == 'queued'
