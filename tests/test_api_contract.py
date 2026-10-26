"""Тесты контракта API.

Проверяют, что ответы всех эндпоинтов имеют предсказуемую структуру, а
чувствительные данные (пароли) не покидают сервер.
"""

import pytest

LOGIN_ENDPOINTS = [
    "/api/vulnerable/login",
    "/api/secure/login",
]

TECHNIQUE_ENDPOINTS = [
    "/api/vulnerable/blind",
    "/api/secure/blind",
    "/api/vulnerable/extract",
    "/api/secure/extract",
    "/api/vulnerable/time",
    "/api/secure/time",
    "/api/vulnerable/error",
    "/api/secure/error",
]


@pytest.mark.parametrize("path", LOGIN_ENDPOINTS)
def test_login_response_shape(client, path):
    j = client.post(path, json={"username": "student", "password": "lab_pass_123"}).get_json()
    for key in ("mode", "success", "row_count", "rows", "sql", "analysis", "message"):
        assert key in j, f"нет ключа {key}"
    assert j["mode"] in ("vulnerable", "secure")
    assert isinstance(j["success"], bool)
    assert isinstance(j["row_count"], int)
    assert isinstance(j["rows"], list)
    assert j["row_count"] == len(j["rows"])


@pytest.mark.parametrize("path", LOGIN_ENDPOINTS)
def test_login_response_never_returns_stored_passwords(client, path):
    """Хранимые в базе пароли не должны попадать в ответ.

    Отправленный пользователем пароль в SQL-блоке присутствует — это
    неизбежное свойство конкатенации (в secure-режиме он передаётся
    параметром). Но чужие пароли из базы утекать не должны никогда.
    """
    j = client.post("/api/vulnerable/login", json={"username": "student", "password": "x"}).get_json()
    for stored in ("lab_pass_123", "demo_2025", "readonly_42"):
        assert stored not in str(j)
    for row in j["rows"]:
        assert "password" not in row


@pytest.mark.parametrize("path", LOGIN_ENDPOINTS)
def test_login_rows_never_contain_password_field(client, path):
    j = client.post(path, json={"username": "student", "password": "lab_pass_123"}).get_json()
    for row in j["rows"]:
        assert "password" not in row
        assert set(row) == {"id", "username", "role"}


@pytest.mark.parametrize("path", LOGIN_ENDPOINTS)
def test_login_sql_block_shape(client, path):
    j = client.post(path, json={"username": "student", "password": "lab_pass_123"}).get_json()
    sql = j["sql"]
    for key in ("raw", "template", "segments", "style"):
        assert key in sql
    assert sql["style"] in ("concat", "parameterized")
    assert isinstance(sql["segments"], list)
    for seg in sql["segments"]:
        assert seg["kind"] in ("code", "input", "param")
        assert "text" in seg


@pytest.mark.parametrize("path", LOGIN_ENDPOINTS)
def test_login_analysis_shape(client, path):
    j = client.post(path, json={"username": "student", "password": "lab_pass_123"}).get_json()
    analysis = j["analysis"]
    for key in ("verdict", "summary", "signals", "signal_count", "parameterized"):
        assert key in analysis
    assert isinstance(analysis["signals"], list)
    assert analysis["signal_count"] == len(analysis["signals"])


@pytest.mark.parametrize("path", TECHNIQUE_ENDPOINTS)
def test_technique_endpoints_share_response_shape(client, path):
    j = client.post(path, json={"username": "x", "password": "y", "condition": "1=1"}).get_json()
    for key in ("mode", "success", "row_count", "rows", "sql", "analysis", "message"):
        assert key in j, f"{path}: нет ключа {key}"


def test_blind_response_has_result(client):
    j = client.post("/api/vulnerable/blind", json={"condition": "1=1"}).get_json()
    assert j["result"] is True
    assert "condition" in j


def test_extract_response_has_extraction(client):
    j = client.post("/api/vulnerable/extract", json={"row": 1}).get_json()
    extraction = j["extraction"]
    for key in ("value", "steps", "log", "truncated", "max_steps"):
        assert key in extraction
    assert isinstance(extraction["log"], list)


def test_time_response_has_timing(client):
    j = client.post("/api/vulnerable/time", json={"workload": 1000000}).get_json()
    timing = j["timing"]
    for key in ("baseline_ms", "payload_ms", "delta_ms", "detectable"):
        assert key in timing


def test_error_response_has_leak_flag(client):
    j = client.post("/api/vulnerable/error", json={"username": "oops'", "password": "x"}).get_json()
    assert "leaked" in j
    assert "error_type" in j


def test_vulnerable_mode_is_labelled_everywhere(client):
    j = client.post("/api/vulnerable/login", json={"username": "a", "password": "b"}).get_json()
    assert j["mode"] == "vulnerable"
    assert j["sql"]["style"] == "concat"


def test_secure_mode_is_labelled_everywhere(client):
    j = client.post("/api/secure/login", json={"username": "a", "password": "b"}).get_json()
    assert j["mode"] == "secure"
    assert j["sql"]["style"] == "parameterized"


def test_index_page_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "SQL Injection Lab" in body
    assert "/static/script.js" in body or "/static/js/" in body


def test_static_assets_available(client):
    assert client.get("/static/style.css").status_code == 200


def test_content_type_is_json(client):
    r = client.post("/api/vulnerable/login", json={"username": "a", "password": "b"})
    assert r.headers["Content-Type"].startswith("application/json")


def test_cyrillic_not_escaped_in_json(client):
    r = client.post("/api/vulnerable/login", json={"username": "a", "password": "b"})
    assert "\\u" not in r.get_data(as_text=True)
