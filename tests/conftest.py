"""Общие фикстуры тестов лаборатории.

Каждый тест работает на собственной временной базе — состояние основного
``lab.db`` никогда не затрагивается.
"""

import pytest

from app import app as flask_app
from lab import db


@pytest.fixture
def app(tmp_path):
    """Приложение, направленное на временную базу."""
    db_file = tmp_path / "test_lab.db"
    db.init_db(str(db_file))
    flask_app.config["DB_PATH"] = str(db_file)
    flask_app.config.update(TESTING=True)
    yield flask_app
    flask_app.config["DB_PATH"] = str(db_path())


def db_path():
    """Путь к основной базе (для восстановления конфигурации)."""
    import config

    return config.DB_PATH


@pytest.fixture
def client(app):
    """Тестовый клиент Flask."""
    with app.test_client() as c:
        yield c


@pytest.fixture
def creds():
    """Корректные демонстрационные учётные данные."""
    return {"username": db.DEMO_USERS[0][0], "password": db.DEMO_USERS[0][1]}


@pytest.fixture
def bad_creds():
    """Заведомо неверные учётные данные."""
    return {"username": "student", "password": "wrong_pass"}


INJECTION = "student' OR '1'='1' --"
