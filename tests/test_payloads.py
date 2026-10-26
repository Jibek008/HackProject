"""Тесты каталога payload'ов.

Главная проверка — самосогласованность каталога: каждый заявленный payload
обязан вести себя ровно так, как описано в его карточке, и каждая карточка
обязана вести себя одинаково в обоих режимах лаборатории.
"""

import pytest

from lab import payloads


def test_catalog_not_empty():
    assert len(payloads.PAYLOADS) >= 8


def test_payload_ids_unique():
    ids = [p["id"] for p in payloads.PAYLOADS]
    assert len(ids) == len(set(ids))


def test_every_payload_has_required_fields():
    required = (
        "id",
        "title",
        "technique",
        "severity",
        "username",
        "password",
        "expected_vulnerable",
        "expected_secure",
        "summary",
        "why",
    )
    for p in payloads.PAYLOADS:
        for field in required:
            assert field in p, f"{p['id']}: нет поля {field}"
            assert p[field] not in (None, ""), f"{p['id']}: пустое поле {field}"


def test_every_payload_expects_blocked_in_secure():
    for p in payloads.PAYLOADS:
        assert p["expected_secure"] == "blocked", p["id"]


def test_every_expected_outcome_is_known():
    known = set(payloads.EXPECTED_OUTCOMES)
    for p in payloads.PAYLOADS:
        assert p["expected_vulnerable"] in known, p["id"]


def test_by_id_returns_payload():
    p = payloads.by_id("classic_or_bypass")
    assert p is not None
    assert p["technique"] == "Tautology"


def test_by_id_returns_none_for_unknown():
    assert payloads.by_id("does-not-exist") is None


def test_public_catalog_adds_description():
    catalog = payloads.public_catalog()
    assert len(catalog) == len(payloads.PAYLOADS)
    for item in catalog:
        assert item["expected_description"]
        assert item["notes"]


# --- Поведенческая проверка каталога -----------------------------------------
def _login(client, mode, username, password):
    """Выполнить вход в нужном режиме."""
    return client.post(
        f"/api/{mode}/login",
        json={"username": username, "password": password},
    ).get_json()


@pytest.mark.parametrize("payload", payloads.PAYLOADS, ids=lambda p: p["id"])
def test_payload_bypasses_vulnerable_login(client, payload):
    """Каждый payload обязан менять поведение уязвимого обработчика."""
    j = _login(client, "vulnerable", payload["username"], payload["password"])
    expected = payload["expected_vulnerable"]

    if expected == "bypass":
        assert j["success"] is True
        assert j["bypassed"] is True
        assert j["row_count"] > 1
    elif expected == "leak":
        assert j["success"] is True
        assert "FLAG" in str(j["rows"])
    elif expected == "schema":
        assert j["success"] is True
        assert "users" in str(j["rows"])
        assert "secrets" in str(j["rows"])
    elif expected == "error":
        assert j["success"] is False
        assert j.get("error")
    elif expected in ("signal", "delay"):
        # Успех может быть и не нужен — важен сам факт отклонения
        # от штатного «доступ запрещён».
        assert j["row_count"] != 1 or j.get("bypassed")


@pytest.mark.parametrize("payload", payloads.PAYLOADS, ids=lambda p: p["id"])
def test_payload_is_blocked_in_secure_login(client, payload):
    """Ни один payload не должен сработать в защищённом режиме."""
    j = _login(client, "secure", payload["username"], payload["password"])
    assert j["success"] is False
    assert j["row_count"] == 0
    assert "FLAG" not in str(j.get("rows", []))
    assert j["sql"]["style"] == "parameterized"
    assert "?" in j["sql"]["raw"]


@pytest.mark.parametrize("payload", payloads.PAYLOADS, ids=lambda p: p["id"])
def test_payload_produces_signals(client, payload):
    """Анализатор обязан узнать во вводе характерные конструкции."""
    j = client.post(
        "/api/analyze", json={"username": payload["username"], "password": payload["password"]}
    ).get_json()
    assert j["analysis"]["verdict"] == "dangerous"
    assert j["analysis"]["signal_count"] >= 1
