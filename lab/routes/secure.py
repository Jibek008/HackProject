"""Защищённые обработчики — рекомендуемый образец.

Единственное отличие от ``lab/routes/vulnerable.py`` в том, что значения
пользователя **никогда не попадают в текст SQL**. Передаются они отдельно,
через плейсхолдеры, и для СУБД остаются данными в любом случае — даже если
внутри них есть кавычки, операторы SQL и комментарии.
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

bp = Blueprint("secure", __name__, url_prefix="/api/secure")

SECURE_SQL = analyzer.SECURE_SQL


@bp.route("/login", methods=["POST"])
def login():
    """Авторизация через параметризованный запрос."""
    if security.request_too_large(request):
        return too_large_response()

    username, password = credentials(request)

    sql_block = {
        "raw": SECURE_SQL,
        "template": SECURE_SQL,
        "segments": analyzer.build_secure_segments(
            username, security.mask_secret(password)
        ),
        "style": "parameterized",
        # Значения параметров показываются, кроме пароля: его содержимое
        # клиенту не нужно, а сам факт передачи через плейсхолдер виден
        # в сегментах.
        "params": [username, security.mask_secret(password)],
    }

    if not username.strip() or not password.strip():
        return payload_response(
            "secure",
            sql_block,
            analyze_pair("", "", parameterized=True),
            [],
            False,
            "Введите имя пользователя и пароль.",
        )

    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(SECURE_SQL, (username, password))
            rows = [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()
    except sqlite3.Error:
        return payload_response(
            "secure",
            sql_block,
            analyze_pair(username, password, parameterized=True),
            [],
            False,
            "Внутренняя ошибка. Повторите попытку позже.",
        )

    success = len(rows) == 1
    if success:
        note = "Вход выполнен. Ввод обработан как данные, а не как код."
    elif len(rows) == 0:
        note = "Доступ запрещён: учётные данные не совпали."
    else:
        note = "Доступ запрещён: найдено несколько записей (аномалия подавлена)."

    return payload_response(
        "secure",
        sql_block,
        analyze_pair(username, password, parameterized=True),
        rows,
        success,
        note,
        explanation=analyzer.explain_outcome("secure", len(rows), success, False),
    )


@bp.route("/blind", methods=["POST"])
def blind_probe():
    """Blind-проба в защищённом режиме: условие передаётся как значение.

    Тот же ввод, что и в уязвимом режиме, но теперь он не может изменить
    логику запроса — условие ищется буквально и всегда даёт ложь.
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
        result = blind.probe_secure(conn, condition)
    finally:
        conn.close()

    return payload_response(
        "secure",
        {
            "raw": "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            "template": "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            "segments": [
                {"kind": "code", "text": "SELECT 1 FROM users WHERE username = "},
                {"kind": "param", "text": "?", "field": "condition", "value": condition},
                {"kind": "code", "text": " AND password = "},
                {"kind": "param", "text": "?", "field": "password", "value": condition},
            ],
            "style": "parameterized",
            "params": [condition, condition],
        },
        {
            "verdict": "blocked",
            "summary": (
                "Условие передано параметром и искалось буквально. Логика "
                "запроса осталась неизменной — канал blind закрыт."
            ),
            "signals": [],
            "signal_count": 0,
            "max_severity": "none",
            "parameterized": True,
        },
        [],
        bool(result),
        "Условие истинно — обратите внимание: параметр не может стать "
        "предикатом." if result else "Условие ложно — канал blind закрыт.",
        condition=condition,
        result=result,
    )


@bp.route("/extract", methods=["POST"])
def extract():
    """Тот же перебор символов, но через параметризованный запрос.

    Каждая проба ищется как обычная строка, поэтому ни одна из них не
    срабатывает, и секрет восстановить не удаётся.
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
            lambda cond: blind.probe_secure(conn, cond),
            row=row,
            max_steps=max_steps,
        )
    finally:
        conn.close()

    return payload_response(
        "secure",
        {
            "raw": "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            "template": "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            "segments": [],
            "style": "parameterized",
            "params": None,
        },
        {
            "verdict": "blocked",
            "summary": (
                f"Выполнено проб: {result['steps']}. Ни одна не сработала: "
                "условие передавалось параметром и не могло повлиять на "
                "логику запроса. Секрет не восстановлен."
            ),
            "signals": [],
            "signal_count": 0,
            "max_severity": "none",
            "parameterized": True,
        },
        [],
        False,
        "Секрет не извлечён — это и есть ожидаемый результат защиты.",
        extraction=result,
    )


@bp.route("/time", methods=["POST"])
def time_based():
    """Time-based в защищённом режиме: нагрузка не влияет на ответ.

    Параметр остаётся значением, поэтому тяжёлое выражение из ввода не
    выполняется вовсе.
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
            "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            (f"' AND length(randomblob({workload})) > 0 --", "x"),
        ).fetchone()
        payload_ms = (time.perf_counter() - start) * 1000
    finally:
        conn.close()

    delta = payload_ms - baseline_ms
    detectable = delta >= current_app.config["TIME_DELTA_THRESHOLD_MS"]

    return payload_response(
        "secure",
        {
            "raw": "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            "template": "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
            "segments": [
                {"kind": "code", "text": "SELECT 1 FROM users WHERE username = "},
                {
                    "kind": "param",
                    "text": "?",
                    "field": "username",
                    "value": f"' AND length(randomblob({workload})) > 0 --",
                },
                {"kind": "code", "text": " AND password = "},
                {"kind": "param", "text": "?", "field": "password", "value": "x"},
            ],
            "style": "parameterized",
            "params": [f"' AND length(randomblob({workload})) > 0 --", "x"],
        },
        {
            "verdict": "blocked",
            "summary": (
                f"Базовая задержка {baseline_ms:.1f} мс, с вводом "
                f"{payload_ms:.1f} мс. Разница {delta:.1f} мс — нагрузка из "
                "ввода не выполнялась, потому что это данные, а не код."
            ),
            "signals": [],
            "signal_count": 0,
            "max_severity": "none",
            "parameterized": True,
        },
        [],
        detectable,
        "Канал time-based закрыт: задержка не изменилась.",
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
    """Error-based в защищённом режиме: детали ошибки наружу не уходят."""
    if security.request_too_large(request):
        return too_large_response()

    username, password = credentials(request)
    if not username.strip():
        username = "oops'"
    if not password.strip():
        password = "x"

    try:
        conn = get_connection()
        try:
            conn.execute(SECURE_SQL, (username, password)).fetchall()
        finally:
            conn.close()
        error_type = ""
        error_text = ""
    except sqlite3.Error:
        error_type = "InternalError"
        error_text = "Внутренняя ошибка. Повторите попытку позже."

    return payload_response(
        "secure",
        {
            "raw": SECURE_SQL,
            "template": SECURE_SQL,
            "segments": analyzer.build_secure_segments(
                username, security.mask_secret(password)
            ),
            "style": "parameterized",
            "params": [username, security.mask_secret(password)],
        },
        analyze_pair(username, password, parameterized=True),
        [],
        False,
        (
            "Приложение не раскрыло детали ошибки — вместо них вернуло "
            "нейтральное сообщение. Пользователь не может использовать "
            "информацию об ошибке для подбора инъекции."
        ),
        error_type=error_type,
        error=error_text,
        leaked=False,
    )
