"""SQL Injection Lab — локальная учебная лаборатория.

Приложение поднимает два параллельных обработчика авторизации над ОДНОЙ и
той же вымышленной базой:

* **Vulnerable Demo** (``/api/vulnerable/*``) — SQL собирается конкатенацией
  пользовательского ввода. Только для изолированной учебной демонстрации.
* **Secure Demo** (``/api/secure/*``) — параметризованный запрос.
  Рекомендуемый образец.

Лаборатория предназначена исключительно для локального обучения.
Сервер слушает только ``127.0.0.1`` — по умолчанию, без настройки.
"""

import os
import sys

from flask import Flask, jsonify

import config
from lab import db
from lab.routes import main, secure, vulnerable

__all__ = ["app", "create_app"]


def create_app(config_overrides=None):
    """Создать и настроить экземпляр Flask-приложения."""
    app = Flask(__name__)

    app.config.from_object(config)
    app.config["LAB_NAME"] = config.LAB_NAME
    app.config["LAB_VERSION"] = config.LAB_VERSION
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    app.config["MAX_EXTRACT_STEPS"] = config.MAX_EXTRACT_STEPS
    app.config["MAX_TIME_WORKLOAD"] = config.MAX_TIME_WORKLOAD
    app.config["TIME_DELTA_THRESHOLD_MS"] = config.TIME_DELTA_THRESHOLD_MS
    app.config["JSON_AS_ASCII"] = False
    app.json.ensure_ascii = False

    if config_overrides:
        app.config.update(config_overrides)

    app.register_blueprint(main.bp)
    app.register_blueprint(vulnerable.bp)
    app.register_blueprint(secure.bp)

    @app.errorhandler(413)
    def _too_large(_exc):
        return (
            jsonify(
                {
                    "error": "payload_too_large",
                    "message": "Тело запроса слишком велико.",
                }
            ),
            413,
        )

    @app.errorhandler(404)
    def _not_found(_exc):
        return (
            jsonify(
                {
                    "error": "not_found",
                    "message": "Такого адреса в лаборатории нет.",
                }
            ),
            404,
        )

    @app.errorhandler(405)
    def _method_not_allowed(_exc):
        return (
            jsonify(
                {
                    "error": "method_not_allowed",
                    "message": "Этот адрес не поддерживает данный HTTP-метод.",
                }
            ),
            405,
        )

    @app.errorhandler(500)
    def _internal_error(_exc):
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Внутренняя ошибка лаборатории.",
                }
            ),
            500,
        )

    # Схема создаётся сразу при загрузке приложения, чтобы база была
    # готова независимо от способа запуска (py app.py, flask run, pytest).
    db.init_db(app.config["DB_PATH"])

    return app


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("LAB_HOST", config.HOST)
    port = int(os.environ.get("LAB_PORT", config.PORT))
    print(f"[lab] {config.LAB_NAME} v{config.LAB_VERSION}")
    print(f"[lab] База: {os.path.abspath(config.DB_PATH)}")
    print(f"[lab] Откройте в браузере: http://{host}:{port}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("[lab] ВНИМАНИЕ: сервер слушает не только loopback. Лаборатория "
              "не должна быть доступна из сети.")
    app.run(host=host, port=port, debug=config.DEBUG)
    sys.stdout.flush()
