"""Общие части роутов.

Вынесено отдельно, чтобы ``vulnerable`` и ``secure`` отличались только той
реализацией, которую действительно сравнивают, — а не копипастой.
"""

from flask import current_app, jsonify, request

from lab import analyzer, db, security


def get_connection():
    """Соединение с БД, путь которой задаётся в конфиге приложения."""
    return db.get_connection(current_app.config["DB_PATH"])


def payload_response(mode, sql_block, analysis, rows, success, message, **extra):
    """Собрать единообразный JSON-ответ обоих режимов."""
    body = {
        "mode": mode,
        "success": success,
        "row_count": len(rows),
        "rows": rows,
        "sql": sql_block,
        "analysis": analysis,
        "message": message,
    }
    body.update(extra)
    return jsonify(body)


def query_rows(conn, sql, params=None):
    """Выполнить запрос и вернуть список словарей."""
    cur = conn.cursor()
    if params is None:
        cur.execute(sql)
    else:
        cur.execute(sql, params)
    return [dict(row) for row in cur.fetchall()]


def read_json():
    """Разобрать JSON-тело запроса (никогда не бросает исключений)."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def too_large_response():
    """Единый ответ на слишком большое тело запроса."""
    return (
        jsonify(
            {
                "error": "payload_too_large",
                "message": "Тело запроса слишком велико.",
            }
        ),
        413,
    )


def credentials(request_obj):
    """Достать очищенные логин и пароль из тела запроса."""
    return security.credentials_from_request(request_obj)


def analyze_pair(username, password, parameterized=False):
    """Разобрать пару ввода (общий вызов анализатора)."""
    return analyzer.analyze(username, password, parameterized=parameterized)
