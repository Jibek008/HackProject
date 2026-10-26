"""Проверки безопасности: уязвимый режим, защищённый режим, техники атаки."""

import json

import pytest

from lab import db
from tests.conftest import INJECTION


# --- 1. Успешная авторизация с корректными данными ---------------------------
def test_vulnerable_success_with_valid(client, creds):
    r = client.post("/api/vulnerable/login", json=creds)
    assert r.status_code == 200
    j = r.get_json()
    assert j["mode"] == "vulnerable"
    assert j["success"] is True
    assert j["row_count"] == 1
    assert j["bypassed"] is False


def test_secure_success_with_valid(client, creds):
    r = client.post("/api/secure/login", json=creds)
    assert r.status_code == 200
    j = r.get_json()
    assert j["mode"] == "secure"
    assert j["success"] is True
    assert j["row_count"] == 1
    for row in j["rows"]:
        assert "password" not in row


# --- 2. Отказ при неправильных учётных данных --------------------------------
def test_vulnerable_rejects_wrong(client, bad_creds):
    j = client.post("/api/vulnerable/login", json=bad_creds).get_json()
    assert j["success"] is False
    assert j["row_count"] == 0
    assert j["bypassed"] is False


def test_secure_rejects_wrong(client, bad_creds):
    j = client.post("/api/secure/login", json=bad_creds).get_json()
    assert j["success"] is False
    assert j["row_count"] == 0


# --- 3. Демонстрация уязвимости только в изолированном учебном режиме --------
def test_vulnerable_sql_injection_demonstrates_bypass(client):
    payload = {"username": INJECTION, "password": "anything"}
    r = client.post("/api/vulnerable/login", json=payload)
    j = r.get_json()
    assert r.status_code == 200
    assert j["mode"] == "vulnerable"
    assert j["success"] is True
    assert j["row_count"] >= 1
    assert j["bypassed"] is True
    assert j["sql"]["raw"] is not None and isinstance(j["sql"]["raw"], str)


def test_vulnerable_injection_shows_generated_sql(client):
    payload = {"username": INJECTION, "password": "anything"}
    j = client.post("/api/vulnerable/login", json=payload).get_json()
    raw = j["sql"]["raw"]
    assert "OR '1'='1'" in raw
    assert "--" in raw


def test_vulnerable_injection_signals_detected(client):
    payload = {"username": INJECTION, "password": "anything"}
    j = client.post("/api/vulnerable/login", json=payload).get_json()
    ids = {s["id"] for s in j["analysis"]["signals"]}
    assert "tautology" in ids
    assert "quote_terminator" in ids
    assert "comment" in ids
    assert j["analysis"]["verdict"] == "dangerous"


def test_sql_segments_split_code_and_input(client):
    payload = {"username": "student", "password": "lab_pass_123"}
    j = client.post("/api/vulnerable/login", json=payload).get_json()
    segments = j["sql"]["segments"]
    kinds = [s["kind"] for s in segments]
    assert "code" in kinds
    assert "input" in kinds
    inputs = [s for s in segments if s["kind"] == "input"]
    assert {s["field"] for s in inputs} == {"username", "password"}
    assert inputs[0]["text"] == "student"


# --- 4. Отсутствие аналогичного обхода в защищённом режиме -------------------
def test_secure_sql_injection_blocked(client):
    payload = {"username": INJECTION, "password": "anything"}
    r = client.post("/api/secure/login", json=payload)
    j = r.get_json()
    assert r.status_code == 200
    assert j["mode"] == "secure"
    assert j["success"] is False
    assert j["row_count"] == 0
    assert j["sql"]["params"] is not None
    assert j["sql"]["style"] == "parameterized"


def test_secure_uses_placeholders_in_raw_sql(client):
    payload = {"username": INJECTION, "password": "anything"}
    j = client.post("/api/secure/login", json=payload).get_json()
    raw = j["sql"]["raw"]
    assert "?" in raw
    assert "OR" not in raw
    assert INJECTION not in raw


def test_secure_reports_parameterized_even_for_injection_input(client):
    payload = {"username": INJECTION, "password": "anything"}
    j = client.post("/api/secure/login", json=payload).get_json()
    assert j["analysis"]["parameterized"] is True
    assert j["analysis"]["signals"], "сигналы во вводе должны быть найдены"
    assert "параметризован" in j["analysis"]["summary"].lower()


# --- 5. Корректная обработка некорректного пользовательского ввода ------------
def test_empty_fields_handled(client):
    r = client.post("/api/vulnerable/login", json={"username": "", "password": ""})
    j = r.get_json()
    assert r.status_code == 200
    assert j["success"] is False

    r = client.post("/api/secure/login", json={"username": "", "password": ""})
    j = r.get_json()
    assert r.status_code == 200
    assert j["success"] is False


def test_long_input_truncated_no_crash(client):
    long_u = "a" * 200
    long_p = "b" * 200
    r1 = client.post("/api/vulnerable/login", json={"username": long_u, "password": long_p})
    assert r1.status_code == 200
    r2 = client.post("/api/secure/login", json={"username": long_u, "password": long_p})
    assert r2.status_code == 200


def test_malformed_json_or_wrong_content_type_no_500(client):
    r = client.post("/api/vulnerable/login", data="not json", content_type="text/plain")
    assert r.status_code == 200
    r = client.post("/api/secure/login", data="not json", content_type="text/plain")
    assert r.status_code == 200


def test_missing_fields_no_500(client):
    r = client.post("/api/vulnerable/login", json={})
    assert r.status_code == 200
    j = r.get_json()
    assert j["success"] is False


def test_non_string_values_no_500(client):
    r = client.post(
        "/api/vulnerable/login", json={"username": 123, "password": ["a", "b"]}
    )
    assert r.status_code == 200
    assert r.get_json()["success"] is False


def test_unicode_input_handled(client):
    r = client.post(
        "/api/vulnerable/login", json={"username": "студент", "password": "пароль"}
    )
    assert r.status_code == 200
    assert r.get_json()["success"] is False


def test_null_byte_truncated(client):
    r = client.post(
        "/api/vulnerable/login",
        json={"username": "stu\x00dent", "password": "lab_pass_123"},
    )
    assert r.status_code == 200


# --- 6. UNION: извлечение данных из другой таблицы ----------------------------
def test_union_extracts_secrets_in_vulnerable(client):
    payload = {"username": "' UNION SELECT id, owner, content FROM secrets --", "password": "x"}
    j = client.post("/api/vulnerable/login", json=payload).get_json()
    assert j["success"] is True
    values = [r.get("role", "") for r in j["rows"]]
    assert any(v.startswith("FLAG{") for v in values)


def test_union_blocked_in_secure(client):
    payload = {"username": "' UNION SELECT id, owner, content FROM secrets --", "password": "x"}
    j = client.post("/api/secure/login", json=payload).get_json()
    assert j["success"] is False
    assert j["row_count"] == 0
    assert "FLAG" not in json.dumps(j, ensure_ascii=False)


def test_union_schema_disclosure(client):
    payload = {"username": "' UNION SELECT 1, name, sql FROM sqlite_master --", "password": "x"}
    j = client.post("/api/vulnerable/login", json=payload).get_json()
    assert j["success"] is True
    assert j["row_count"] >= 2
    blob = str(j["rows"])
    assert "users" in blob
    assert "secrets" in blob


# --- 7. Blind: булев канал ----------------------------------------------------
def test_blind_true_condition(client):
    j = client.post("/api/vulnerable/blind", json={"condition": "1=1"}).get_json()
    assert j["result"] is True


def test_blind_false_condition(client):
    j = client.post("/api/vulnerable/blind", json={"condition": "1=0"}).get_json()
    assert j["result"] is False


def test_blind_blocked_in_secure(client):
    j = client.post("/api/secure/blind", json={"condition": "1=1"}).get_json()
    assert j["result"] is False
    assert j["analysis"]["parameterized"] is True


def test_blind_extracts_flag_in_vulnerable(client):
    j = client.post("/api/vulnerable/extract", json={"row": 1}).get_json()
    assert j["extraction"]["value"] == db.SECRET_VALUE
    assert j["extraction"]["steps"] > 0
    assert len(j["extraction"]["log"]) == len(db.SECRET_VALUE)


def test_blind_extract_finds_nothing_in_secure(client):
    j = client.post("/api/secure/extract", json={"row": 1}).get_json()
    assert j["extraction"]["value"] == ""
    assert j["success"] is False


def test_blind_extract_respects_step_limit(client):
    j = client.post("/api/vulnerable/extract", json={"row": 1, "max_steps": 2}).get_json()
    assert j["extraction"]["max_steps"] == 2
    assert len(j["extraction"]["value"]) <= 2


# --- 8. Error-based: утечка деталей ошибки ------------------------------------
def test_error_based_leaks_details_in_vulnerable(client):
    j = client.post("/api/vulnerable/error", json={"username": "oops'", "password": "x"}).get_json()
    assert j["leaked"] is True
    assert j["error_type"]
    assert j["error"]


def test_error_based_hides_details_in_secure(client):
    j = client.post("/api/secure/error", json={"username": "oops'", "password": "x"}).get_json()
    assert j["leaked"] is False
    assert j["error"] == "" or "Внутренняя" in j["error"]


# --- 9. Time-based ------------------------------------------------------------
def test_time_based_detectable_in_vulnerable(client):
    j = client.post("/api/vulnerable/time", json={"workload": 20000000}).get_json()
    assert j["timing"]["detectable"] is True
    assert j["timing"]["delta_ms"] > 0


def test_time_based_not_detectable_in_secure(client):
    j = client.post("/api/secure/time", json={"workload": 20000000}).get_json()
    assert j["timing"]["detectable"] is False


def test_time_workload_is_capped(client):
    j = client.post("/api/vulnerable/time", json={"workload": 10**12}).get_json()
    assert j["timing"]["workload"] <= 100_000_000


# --- 10. Стек-логи и обработка ошибок ----------------------------------------
def test_unknown_route_returns_404_json(client):
    r = client.get("/api/nope")
    assert r.status_code == 404
    assert r.get_json()["error"] == "not_found"


def test_wrong_method_returns_405_json(client):
    r = client.get("/api/vulnerable/login")
    assert r.status_code == 405
    assert r.get_json()["error"] == "method_not_allowed"


def test_health_endpoint(client):
    j = client.get("/api/health").get_json()
    assert j["status"] == "ok"


def test_schema_endpoint_lists_tables(client):
    j = client.get("/api/schema").get_json()
    names = {t["name"] for t in j["tables"]}
    assert {"users", "secrets"} <= names
    assert len(j["users"]) == 3


def test_payloads_endpoint_returns_catalog(client):
    j = client.get("/api/payloads").get_json()
    assert len(j["payloads"]) >= 8
    for p in j["payloads"]:
        assert "id" in p and "title" in p and "expected_vulnerable" in p


def test_analyze_endpoint_is_static(client):
    j = client.post("/api/analyze", json={"username": "x' OR '1'='1' --"}).get_json()
    assert j["analysis"]["verdict"] == "dangerous"
    assert j["sql_preview"]["segments"]


@pytest.mark.parametrize("path", ["/api/vulnerable/login", "/api/secure/login"])
def test_oversized_body_rejected(client, path):
    r = client.post(
        path,
        data="x" * 20000,
        content_type="application/json",
    )
    assert r.status_code in (200, 413)
