#!/usr/bin/env python3
"""
Test suite for API Workshop
Tests all endpoints in the correct CRUD sequence and validates error paths.

Run with:  pytest test_api.py -v
"""

import pytest
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from app import app, db, User, Token, Task, AuditLog


# ─────────────────────────── fixtures ───────────────────────────


@pytest.fixture(scope="session")
def client():
    """Create a Flask test client with a fresh in-memory database."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SERVER_NAME"] = "localhost:5000"

    with app.app_context():
        db.create_all()

    with app.test_client() as client:
        yield client

    # Teardown
    with app.app_context():
        db.drop_all()


# Shared state across the sequential CRUD tests
_state: dict = {}


# ─────────────────────── 0  Welcome / Misc ──────────────────────


class TestWelcomeAndMisc:
    """Non-authenticated endpoints."""

    def test_welcome_endpoint(self, client):
        """GET / should return 200 and a welcome message."""
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == 200
        assert "message" in data

    def test_swagger_docs_available(self, client):
        """GET /hidden/swagger/ should return 200 (Swagger UI)."""
        resp = client.get("/hidden/swagger/")
        assert resp.status_code == 200

    def test_unknown_endpoint_returns_404(self, client):
        """GET /unknown should return 404."""
        resp = client.get("/unknown")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "NOT_FOUND"


# ─────────────────── 1  Admin – Add User ────────────────────────


class TestAdminAddUser:
    """POST /admin/add_user – requires X-Admin-Password header."""

    def test_add_user_missing_admin_header(self, client):
        """Should return 401 when X-Admin-Password header is absent."""
        resp = client.post(
            "/admin/add_user",
            data=json.dumps({"email": "test@workshop.com"}),
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_add_user_wrong_admin_password(self, client):
        """Should return 401 when X-Admin-Password value is wrong."""
        resp = client.post(
            "/admin/add_user",
            data=json.dumps({"email": "test@workshop.com"}),
            content_type="application/json",
            headers={"X-Admin-Password": "wrong_password"},
        )
        assert resp.status_code == 401

    def test_add_user_missing_email(self, client):
        """Should return 400 when email field is missing."""
        resp = client.post(
            "/admin/add_user",
            data=json.dumps({}),
            content_type="application/json",
            headers={"X-Admin-Password": "workshop_admin_pass"},
        )
        assert resp.status_code == 400

    def test_add_user_success(self, client):
        """Should create a new user and return 201 with an api_key."""
        resp = client.post(
            "/admin/add_user",
            data=json.dumps({"email": "test@workshop.com"}),
            content_type="application/json",
            headers={"X-Admin-Password": "workshop_admin_pass"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["email"] == "test@workshop.com"
        assert "api_key" in data
        _state["api_key"] = data["api_key"]

    def test_add_user_duplicate(self, client):
        """Should return 400 when the same email is added twice."""
        resp = client.post(
            "/admin/add_user",
            data=json.dumps({"email": "test@workshop.com"}),
            content_type="application/json",
            headers={"X-Admin-Password": "workshop_admin_pass"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "USER_EXISTS"


# ────────────────── 2  Auth – Get JWT Token ─────────────────────


class TestAuthToken:
    """POST /api/auth/token – exchange api_key for a JWT token."""

    def test_get_token_no_json(self, client):
        """Should return 400 when Content-Type is not application/json."""
        resp = client.post(
            "/api/auth/token",
            data="not json",
            content_type="text/plain",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "MALFORMED_JSON"

    def test_get_token_missing_api_key(self, client):
        """Should return 400 when api_key field is missing."""
        resp = client.post(
            "/api/auth/token",
            data=json.dumps({"wrong_field": "value"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "API_KEY_REQUIRED"

    def test_get_token_invalid_api_key(self, client):
        """Should return 404 for a non-existent api_key."""
        resp = client.post(
            "/api/auth/token",
            data=json.dumps({"api_key": "this_key_does_not_exist"}),
            content_type="application/json",
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "INVALID_API_KEY"

    def test_get_token_success(self, client):
        """Should return 200 and a valid JWT token."""
        resp = client.post(
            "/api/auth/token",
            data=json.dumps({"api_key": _state["api_key"]}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert "expires_at" in data
        _state["token"] = data["token"]


# ─────────────────── 3  Task 1 – GET (Read) ─────────────────────


class TestTask1:
    """GET /api/task1 – retrieve task_id (Read operation)."""

    def test_task1_no_token(self, client):
        """Should return 401 when Authorization header is missing."""
        resp = client.get("/api/task1")
        assert resp.status_code == 401

    def test_task1_bad_token(self, client):
        """Should return 401 when the token is invalid."""
        resp = client.get(
            "/api/task1",
            headers={"Authorization": "Bearer bad_token_value"},
        )
        assert resp.status_code == 401

    def test_task1_success(self, client):
        """Should return 200 with task_id and next_endpoint pointing to /api/task2."""
        resp = client.get(
            "/api/task1",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "task_id" in data
        assert data["next_endpoint"] == "/api/task2"
        _state["task_id"] = data["task_id"]


# ─────────────────── 4  Task 2 – POST (Create) ──────────────────


class TestTask2:
    """POST /api/task2 – save task_id to tasks table (Create operation)."""

    def test_task2_missing_body(self, client):
        """Should return 400 when task_id is missing from body."""
        resp = client.post(
            "/api/task2",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "TASK_ID_REQUIRED"

    def test_task2_wrong_task_id(self, client):
        """Should return 400 when task_id doesn't belong to the user."""
        resp = client.post(
            "/api/task2",
            data=json.dumps({"task_id": "not_my_task_id_000"}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_TASK_ID"

    def test_task2_success(self, client):
        """Should return 201 with task_record_id and next_endpoint for task3."""
        resp = client.post(
            "/api/task2",
            data=json.dumps({"task_id": _state["task_id"]}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "task_record_id" in data
        assert data["next_endpoint"] == f"/api/task3/{data['task_record_id']}"
        _state["task_record_id"] = data["task_record_id"]

    def test_task2_duplicate(self, client):
        """Should return 400 when the same task_id is submitted again."""
        resp = client.post(
            "/api/task2",
            data=json.dumps({"task_id": _state["task_id"]}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "TASK_EXISTS"


# ─────────────────── 5  Task 3 – PUT (Update) ───────────────────


class TestTask3:
    """PUT /api/task3/<task_record_id> – update task record (Update operation)."""

    def test_task3_missing_data_field(self, client):
        """Should return 400 when 'data' field is missing from body."""
        resp = client.put(
            f"/api/task3/{_state['task_record_id']}",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "DATA_REQUIRED"

    def test_task3_wrong_record_id(self, client):
        """Should return 404 when task_record_id doesn't exist."""
        resp = client.put(
            "/api/task3/99999",
            data=json.dumps({"data": "test"}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "TASK_NOT_FOUND"

    def test_task3_success(self, client):
        """Should return 200 with action_id and next_endpoint /api/task4."""
        resp = client.put(
            f"/api/task3/{_state['task_record_id']}",
            data=json.dumps({"data": "Updated task data from test"}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "action_id" in data
        assert data["next_endpoint"] == "/api/task4"
        _state["action_id"] = data["action_id"]


# ─────────────────── 6  Task 4 – DELETE (Delete) ────────────────


class TestTask4:
    """DELETE /api/task4 – delete task record (Delete operation)."""

    def test_task4_missing_action_id(self, client):
        """Should return 400 when action_id is missing."""
        resp = client.delete(
            "/api/task4",
            data=json.dumps({}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "ACTION_ID_REQUIRED"

    def test_task4_wrong_action_id(self, client):
        """Should return 404 when action_id doesn't match any record."""
        resp = client.delete(
            "/api/task4",
            data=json.dumps({"action_id": "wrong_action_id"}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "TASK_NOT_FOUND"

    def test_task4_success(self, client):
        """Should return 200 with certification_id – workshop completed!"""
        resp = client.delete(
            "/api/task4",
            data=json.dumps({"action_id": _state["action_id"]}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "certification_id" in data
        assert data["certification_id"].startswith("cert_")
        assert "completed" in data["message"].lower() or "finished" in data["message"].lower()

    def test_task4_replay_after_delete(self, client):
        """Should return 404 if the same action_id is sent again (record deleted)."""
        resp = client.delete(
            "/api/task4",
            data=json.dumps({"action_id": _state["action_id"]}),
            content_type="application/json",
            headers={"Authorization": f"Bearer {_state['token']}"},
        )
        assert resp.status_code == 404


# ─────────────── 7  Full CRUD Sequence Sanity Check ─────────────


class TestFullCRUDSequence:
    """
    End-to-end: create a second user and run the entire
    CRUD workflow (GET → POST → PUT → DELETE) in one test
    to confirm task sequencing works from scratch.
    """

    def test_full_crud_sequence(self, client):
        # ── Admin: create user ──
        resp = client.post(
            "/admin/add_user",
            data=json.dumps({"email": "crud_test@workshop.com"}),
            content_type="application/json",
            headers={"X-Admin-Password": "workshop_admin_pass"},
        )
        assert resp.status_code == 201
        api_key = resp.get_json()["api_key"]

        # ── Auth: get token ──
        resp = client.post(
            "/api/auth/token",
            data=json.dumps({"api_key": api_key}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        token = resp.get_json()["token"]
        auth = {"Authorization": f"Bearer {token}"}

        # ── Task 1  (READ) ──
        resp = client.get("/api/task1", headers=auth)
        assert resp.status_code == 200
        task_id = resp.get_json()["task_id"]

        # ── Task 2  (CREATE) ──
        resp = client.post(
            "/api/task2",
            data=json.dumps({"task_id": task_id}),
            content_type="application/json",
            headers=auth,
        )
        assert resp.status_code == 201
        task_record_id = resp.get_json()["task_record_id"]

        # ── Task 3  (UPDATE) ──
        resp = client.put(
            f"/api/task3/{task_record_id}",
            data=json.dumps({"data": "end-to-end test data"}),
            content_type="application/json",
            headers=auth,
        )
        assert resp.status_code == 200
        action_id = resp.get_json()["action_id"]

        # ── Task 4  (DELETE) ──
        resp = client.delete(
            "/api/task4",
            data=json.dumps({"action_id": action_id}),
            content_type="application/json",
            headers=auth,
        )
        assert resp.status_code == 200
        assert resp.get_json()["certification_id"].startswith("cert_")
