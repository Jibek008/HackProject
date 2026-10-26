"""Небезопасные обработчики — только для изолированной учебной демонстрации.

Каждый эндпоинт здесь намеренно содержит типичную ошибку: пользовательский
ввод попадает в текст SQL. Ни в одном реальном приложении так делать
нельзя. Рядом всегда существует защищённый аналог в ``lab/routes/secure.py``.
"""

import sqlite3
import time

from flask import Blueprint, current_app, request

from config import MAX_TIME_WORKLOAD, TIME_DELTA_THRESHOLD_MS
from lab import analyzer, blind, security

from ._common import (
    analyze_pair,
    credentials,
    get_connection,
    payload_response,
    too_large_response,
)

bp = Blueprint("vulnerable", __name__, url_prefix="/api/vulnerable")


def _vulnerable_query(username, password):
    """Собрать SQL конкатенацией — так, как это делают в небезопасном коде."""
    return (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )


@bp.route("/login", methods=["POST"])
def login():
    """Небезопасная авторизация.

    Показывает, что происходит, когда ввод пользователя становится частью
    SQL-кода: он может изменить условие WHERE и обойти проверку пароля.
    """
    if security.request_too_large(request):
        return too_large_response()

    username, password = credentials(request)

    if not username.strip() or not password.strip():
        return payload_response(
            "vulnerable",
            {
                "raw": None,
                "template": analyzer.VULNERABLE_TEMPLATE,
                "segments": [],
                "style": "concat",
            },
            analyze_pair("", ""),
            [],
            False,
            "Введите имя пользователя и пароль.",
        )

    query = _vulnerable_query(username, password)
    sql_block = {
        "raw": query,
        "template": analyzer.VULNERABLE_TEMPLATE,
        "segments": analyzer.build_segments(
            analyzer.VULNERABLE_TEMPLATE,
            {"username": username, "password": password},
        ),
        "style": "concat",
    }

    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(query)
            rows = [dict(row) for row in cur.fetchall()]

            # Эталон: тот же ввод, но обработанный параметризованно.
            # Если параметризованный запрос не нашёл бы ничего, а
            # уязвимый нашёл — значит доступ получен именно за счёт
            # инъекции. Это точнее, чем «больше одной строки».
            cur.execute(analyzer.SECURE_SQL, (username, password))
            expected_rows = cur.fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return payload_response(
            "vulnerable",
            sql_block,
            analyze_pair(username, password),
            [],
            False,
            f"Ошибка SQL: {exc} — приложение раскрыло детали ошибки. "
            "Это отдельная уязвимость: пользователю не следует показывать "
            "внутренности СУБД.",
            error_type=type(exc).__name__,
            error=str(exc),
        )

    # Уязвимый обработчик считает успехом любую непустую выдачу: если запрос
    # вернул запись, приложение пустит пользователя внутрь.
    success = len(rows) > 0
    # Обход зафиксирован, если параметризованный запрос с тем же вводом
    # не нашёл бы ни одной записи, а уязвимый нашёл.
    bypassed = len(rows) > 0 and len(expected_rows) == 0

    if bypassed:
        note = (
            "ВНИМАНИЕ: авторизация обойдена. Тот же ввод, обработанный "
            "параметризованно, не нашёл бы ни одной записи — доступ получен "
            "именно за счёт подстановки в SQL."
        )
    elif success:
        note = "Вход выполнен. Сравните, как формируется запрос."
    else:
        note = "Совпадений нет: учётные данные не подошли."

    return payload_response(
        "vulnerable",
        sql_block,
        analyze_pair(username, password),
        rows,
        success,
        note,
        bypassed=bypassed,
        explanation=analyzer.explain_outcome("vulnerable", len(rows), success, bypassed),
    )


@bp.route("/blind", methods=["POST"])
def blind_probe():
    """Boolean blind: ответ содержит только true/false, без данных.

    Классический сценарий, когда вывод данных заблокирован, но остаётся
    канал утечки через сам факт истинности условия.
    """
    if security.request_too_large(request):
        return too_large_response()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    condition = security.clean(data.get("condition", "1=1"), 400)

    if not condition.strip():
        condition = "1=1"

    conn = get_connection()
    try:
        result = blind.probe_vulnerable(conn, condition)
    finally:
        conn.close()

    return payload_response(
        "vulnerable",
        {
            "raw": f"SELECT 1 FROM users WHERE ({condition}) LIMIT 1",
            "template": "SELECT 1 FROM users WHERE (<condition>) LIMIT 1",
            "segments": [
                {"kind": "code", "text": "SELECT 1 FROM users WHERE ("},
                {"kind": "input", "text": condition, "field": "condition"},
                {"kind": "code", "text": ") LIMIT 1"},
            ],
            "style": "concat",
        },
        {
            "verdict": "blind",
            "summary": (
                "Условие выполнено как часть SQL. Ответ true/false — это "
                "один бит информации, которого хватает для восстановления "
                "данных посимвольно."
            ),
            "signals": [],
            "signal_count": 0,
            "max_severity": "none",
            "parameterized": False,
        },
        [],
        bool(result),
        "Условие истинно — канал утечки работает."
        if result
        else "Условие ложно — канал утечки работает.",
        condition=condition,
        result=result,
    )


@bp.route("/extract", methods=["POST"])
def extract():
    """Авто-извлечение секрета посимвольно через boolean blind.

    Показывает полный журнал проб: какое условие уходило в базу на каждом
    шаге и какой символ оно подтвердило.
    """
    if security.request_too_large(request):
        return too_large_response()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    row = int(security.clean(data.get("row", "1")) or 1)
    max_steps = int(security.clean(data.get("max_steps", "64")) or 64)
    max_steps = max(1, min(max_steps, current_app.config["MAX_EXTRACT_STEPS"]))

    conn = get_connection()
    try:
        result = blind.extract_value(
            lambda cond: blind.probe_vulnerable(conn, cond),
            row=row,
            max_steps=max_steps,
        )
    finally:
        conn.close()

    return payload_response(
        "vulnerable",
        {
            "raw": "SELECT 1 FROM users WHERE (SUBSTR((SELECT content FROM secrets ...)))",
            "template": "SELECT 1 FROM users WHERE (SUBSTR((SELECT content FROM secrets ORDER BY id LIMIT 1),<n>,1)='<char>')",
            "segments": [],
            "style": "concat",
        },
        {
            "verdict": "leak",
            "summary": (
                f"Значение восстановлено перебором за {result['steps']} проб. "
                "Данные не возвращались напрямую — они были собраны из "
                "отдельных битов (true/false)."
            ),
            "signals": [],
            "signal_count": 0,
            "max_severity": "none",
            "parameterized": False,
        },
        [],
        bool(result["value"]),
        "Секрет извлечён: " + (result["value"] or "(не найден)"),
        extraction=result,
    )


@bp.route("/time", methods=["POST"])
def time_based():
    """Time-based: измерить задержку ответа из-за вставленного выражения.

    В SQLite нет функции SLEEP(), поэтому нагрузка эмулируется генерацией
    большого объёма данных (randomblob). В MySQL тот же эффект дал бы
    ``SLEEP(5)``.
    """
    if security.request_too_large(request):
        return too_large_response()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    workload = int(security.clean(data.get("workload", "20000000")) or 20000000)
    workload = max(0, min(workload, current_app.config["MAX_TIME_WORKLOAD"]))

    conn = get_connection()
    try:
        start = time.perf_counter()
        conn.execute("SELECT 1").fetchone()
        baseline_ms = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        conn.execute(
            f"SELECT 1 FROM users WHERE length(randomblob({workload})) > 0 LIMIT 1"
        ).fetchone()
        payload_ms = (time.perf_counter() - start) * 1000
    finally:
        conn.close()

    delta = payload_ms - baseline_ms
    detectable = delta >= current_app.config["TIME_DELTA_THRESHOLD_MS"]

    return payload_response(
        "vulnerable",
        {
            "raw": f"SELECT 1 FROM users WHERE length(randomblob({workload})) > 0 LIMIT 1",
            "template": "SELECT 1 FROM users WHERE length(randomblob(<N>)) > 0 LIMIT 1",
            "segments": [
                {"kind": "code", "text": "SELECT 1 FROM users WHERE length(randomblob("},
                {"kind": "input", "text": str(workload), "field": "workload"},
                {"kind": "code", "text": ")) > 0 LIMIT 1"},
            ],
            "style": "concat",
        },
        {
            "verdict": "delay" if detectable else "info",
            "summary": (
                f"Базовая задержка {baseline_ms:.1f} мс, с нагрузкой "
                f"{payload_ms:.1f} мс. Разница {delta:.1f} мс "
                + (
                    "заметна — канал time-based работает."
                    if detectable
                    else "слишком мала, чтобы её можно было уверенно измерить."
                )
            ),
            "signals": [],
            "signal_count": 0,
            "max_severity": "none",
            "parameterized": False,
        },
        [],
        detectable,
        "Время ответа измеримо отличается — канал time-based работает."
        if detectable
        else "Разница во времени недостаточна для уверенного вывода.",
        timing={
            "baseline_ms": round(baseline_ms, 2),
            "payload_ms": round(payload_ms, 2),
            "delta_ms": round(delta, 2),
            "threshold_ms": TIME_DELTA_THRESHOLD_MS,
            "workload": workload,
            "detectable": detectable,
        },
    )


@bp.route("/error", methods=["POST"])
def error_based():
    """Error-based: показать, что именно утекает в ответе при ошибке SQL.

    Уязвимый обработчик отдаёт текст ошибки СУБД целиком; защищённый
    заменяет его нейтральным сообщением.
    """
    if security.request_too_large(request):
        return too_large_response()

    username, password = credentials(request)
    if not username.strip():
        username = "oops'"
    if not password.strip():
        password = "x"

    query = _vulnerable_query(username, password)
    error_type = ""
    error_text = ""
    try:
        conn = get_connection()
        try:
            conn.execute(query).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        error_type = type(exc).__name__
        error_text = str(exc)

    leaked = bool(error_text)
    return payload_response(
        "vulnerable",
        {
            "raw": query,
            "template": analyzer.VULNERABLE_TEMPLATE,
            "segments": analyzer.build_segments(
                analyzer.VULNERABLE_TEMPLATE,
                {"username": username, "password": password},
            ),
            "style": "concat",
        },
        analyze_pair(username, password),
        [],
        False,
        (
            f"Приложение вернуло пользователю детали ошибки SQL: "
            f"{error_type}: {error_text}. По этой информации можно судить "
            "о структуре запроса и подбирать инъекцию."
            if leaked
            else "Ошибки не возникло."
        ),
        error_type=error_type,
        error=error_text,
        leaked=leaked,
    )
