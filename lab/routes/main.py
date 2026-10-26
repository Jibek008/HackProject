"""Главная страница и справочные эндпоинты."""

from flask import Blueprint, current_app, jsonify, render_template, request

from lab import db, payloads, security

from ._common import get_connection, too_large_response

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    """Дашборд лаборатории."""
    return render_template("index.html")


@bp.route("/api/health")
def health():
    """Проверка живости приложения."""
    return jsonify(
        {
            "status": "ok",
            "app": current_app.config.get("LAB_NAME", "SQL Injection Lab"),
            "version": current_app.config.get("LAB_VERSION", "2.0"),
        }
    )


@bp.route("/api/payloads")
def list_payloads():
    """Каталог демонстрационных техник."""
    return jsonify({"payloads": payloads.public_catalog()})


@bp.route("/api/schema")
def schema():
    """Описание цели атаки: таблицы, колонки, демонстрационные данные."""
    if security.request_too_large(request):
        return too_large_response()
    return jsonify(db.describe(current_app.config["DB_PATH"]))


@bp.route("/api/analyze", methods=["POST"])
def analyze():
    """Статический разбор ввода без обращения к базе.

    Полезно, чтобы заранее понять, что сделает тот или иной payload,
    ещё до отправки запроса к СУБД.
    """
    if security.request_too_large(request):
        return too_large_response()
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}
    username = security.clean(data.get("username"))
    password = security.clean(data.get("password"))
    return jsonify(
        {
            "username": username,
            "password": password,
            "analysis": _analyze(username, password),
            "sql_preview": _preview(username, password),
        }
    )


def _analyze(username, password):
    from lab import analyzer

    return analyzer.analyze(username, password, parameterized=False)


def _preview(username, password):
    """Показать, как выглядел бы уязвимый запрос, не выполняя его."""
    from lab import analyzer

    raw = analyzer.VULNERABLE_TEMPLATE.format(
        username=username.replace("'", "''"),
        password=password.replace("'", "''"),
    )
    return {
        "raw": raw,
        "segments": analyzer.build_segments(
            analyzer.VULNERABLE_TEMPLATE,
            {"username": username, "password": password},
        ),
        "note": (
            "Это предпросмотр без экранирования кавычек. Реальный "
            "уязвимый обработчик подставляет ввод как есть — именно поэтому "
            "полезно сначала разобрать ввод здесь."
        ),
    }


@bp.route("/api/tables")
def tables():
    """Список таблиц и их определений (разведка)."""
    return jsonify({"tables": db.list_tables(current_app.config["DB_PATH"])})
