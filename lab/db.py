"""Работа с базой данных лаборатории.

В базе лежат ТОЛЬКО вымышленные данные: три демо-пользователя и две записи
в таблице ``secrets``. Никаких реальных аккаунтов, паролей или данных из
сторонних источников не используется.

Пароли намеренно хранятся в открытом виде: цель лаборатории — изолированно
показать именно принцип SQL Injection. В реальных приложениях так делать
нельзя (см. ``docs/DEFENSE.md``).
"""

import os
import sqlite3

from config import DB_PATH

# --- Демонстрационные данные ------------------------------------------------
DEMO_USERS = [
    ("student", "lab_pass_123", "student"),
    ("analyst", "demo_2025", "analyst"),
    ("viewer", "readonly_42", "viewer"),
]

DEMO_SECRETS = [
    ("student", "FLAG{sql_injection_demo_only}"),
    ("analyst", "FLAG{parameterized_queries_win}"),
]

# --- Схема -------------------------------------------------------------------
SCHEMA_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
"""

SCHEMA_SECRETS = """
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    content TEXT NOT NULL
)
"""

SECRET_VALUE = "FLAG{sql_injection_demo_only}"


def get_connection(db_path=None):
    """Вернуть соединение с базой. Путь можно переопределить (нужно для тестов)."""
    conn = sqlite3.connect(db_path or DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None, seed=True):
    """Создать схему и, при необходимости, заполнить вымышленными данными."""
    conn = get_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(SCHEMA_USERS)
        cur.execute(SCHEMA_SECRETS)

        if seed:
            cur.execute("DELETE FROM users")
            cur.executemany(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                DEMO_USERS,
            )
            cur.execute("DELETE FROM secrets")
            cur.executemany(
                "INSERT INTO secrets (owner, content) VALUES (?, ?)",
                DEMO_SECRETS,
            )
        conn.commit()
    finally:
        conn.close()


# --- Интроспекция -----------------------------------------------------------
def list_tables(db_path=None):
    """Список таблиц и их SQL-определений (то, что злоумышленник tries вытащить)."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        ).fetchall()
        return [{"type": r["type"], "name": r["name"], "sql": r["sql"]} for r in rows]
    finally:
        conn.close()


def describe(db_path=None):
    """Человекочитаемое описание цели атаки: таблицы, колонки, пример данных."""
    conn = get_connection(db_path)
    try:
        users = [
            {"id": r["id"], "username": r["username"], "role": r["role"]}
            for r in conn.execute("SELECT id, username, role FROM users ORDER BY id")
        ]
        secrets = [
            {"id": r["id"], "owner": r["owner"], "preview": r["content"][:12] + "..."}
            for r in conn.execute("SELECT id, owner, content FROM secrets ORDER BY id")
        ]
        tables = list_tables(db_path)
        return {
            "users": users,
            "secrets": secrets,
            "tables": tables,
            "notes": [
                "Пароли в лаборатории хранятся в открытом виде — это сделано "
                "намеренно, чтобы изолированно показать принцип SQL Injection.",
                "В реальных системах пароли хранят только в виде стойких хэшей.",
            ],
        }
    finally:
        conn.close()


def secret_value(db_path=None, row=1):
    """Значение секрета по индексу (для blind-извлечения)."""
    conn = get_connection(db_path)
    try:
        r = conn.execute(
            "SELECT content FROM secrets ORDER BY id LIMIT 1 OFFSET ?", (row - 1,)
        ).fetchone()
        return r["content"] if r else None
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"[lab] База инициализирована: {os.path.abspath(DB_PATH)}")
