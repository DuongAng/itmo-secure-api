"""Базовые тесты API: регистрация/вход работают, доступ без токена запрещён,
SQLi и XSS нейтрализуются."""
import os
import tempfile

import pytest

os.environ["JWT_SECRET"] = "test-secret"
import app as api  # noqa: E402


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()
    api.DB_PATH = db_path
    api.init_db()
    api.app.config["TESTING"] = True
    with api.app.test_client() as c:
        yield c
    os.close(db_fd)
    os.unlink(db_path)


def register_and_login(client, username="alice", password="Secret12345"):
    client.post("/auth/register", json={"username": username, "password": password})
    r = client.post("/auth/login", json={"username": username, "password": password})
    return r.get_json()["token"]


def test_data_requires_token(client):
    # Без токена доступ к защищённому эндпоинту запрещён.
    r = client.get("/api/data")
    assert r.status_code == 401


def test_login_and_access(client):
    token = register_and_login(client)
    r = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.get_json()["user"] == "alice"


def test_wrong_password(client):
    client.post("/auth/register", json={"username": "bob", "password": "Secret12345"})
    r = client.post("/auth/login", json={"username": "bob", "password": "wrongpass"})
    assert r.status_code == 401


def test_sqli_in_login_is_safe(client):
    # Классическая инъекция в логине не должна проходить аутентификацию.
    r = client.post("/auth/login", json={"username": "' OR '1'='1", "password": "x"})
    assert r.status_code == 401


def test_xss_is_escaped(client):
    token = register_and_login(client, "carol", "Secret12345")
    payload = {"title": "hi", "content": "<script>alert(1)</script>"}
    r = client.post("/api/posts", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201
    # Опасные символы экранированы — тег не вернётся в исходном виде.
    assert "<script>" not in r.get_json()["content"]
    assert "&lt;script&gt;" in r.get_json()["content"]
