"""Пакет лаборатории SQL Injection.

Состав:
    db         — работа с SQLite (схема, сид, интроспекция)
    security   — очистка и нормализация пользовательского ввода
    analyzer   — разбор сгенерированного SQL и детекция сигналов инъекции
    payloads   — каталог демонстрационных техник
    routes     — Flask-роуты (main / vulnerable / secure)
"""

from . import analyzer, db, payloads, security  # noqa: F401

__all__ = ["analyzer", "db", "payloads", "security"]
