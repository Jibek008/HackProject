"""Конфигурация лаборатории.

Все настройки читаются из переменных окружения, но значения по умолчанию
намеренно «безопасные»: сервер поднимается только на ``127.0.0.1`` и никогда
не выходит в локальную сеть. Для учебной лаборатории это обязательное условие.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# --- Сеть -------------------------------------------------------------------
# По умолчанию — только loopback. Лаборатория не должна быть доступна из сети.
HOST = os.environ.get("LAB_HOST", "127.0.0.1")
PORT = _env_int("LAB_PORT", 5000)
DEBUG = os.environ.get("LAB_DEBUG", "0") == "1"

# --- Пути -------------------------------------------------------------------
DB_PATH = os.environ.get("LAB_DB_PATH", os.path.join(BASE_DIR, "lab.db"))

# --- Ограничения ввода ------------------------------------------------------
# Максимальная длина одного введённого значения (символы).
MAX_INPUT_LEN = _env_int("LAB_MAX_INPUT_LEN", 128)
# Максимальная длина всего тела запроса (байт).
MAX_CONTENT_LENGTH = _env_int("LAB_MAX_CONTENT_LENGTH", 16 * 1024)
# Максимальное число шагов при посимвольном извлечении флага.
MAX_EXTRACT_STEPS = _env_int("LAB_MAX_EXTRACT_STEPS", 64)
# Верхняя граница объёма "тяжёлой" работы для time-based демонстрации.
# 100_000_000 -> примерно 300-350 мс на этой машине. Больше ставить нельзя:
# лаборатория должна отвечать быстро и не подвисать во время защиты.
MAX_TIME_WORKLOAD = _env_int("LAB_MAX_TIME_WORKLOAD", 100_000_000)
# Порог, выше которого задержка считается "обнаружимой" в time-based тесте.
TIME_DELTA_THRESHOLD_MS = _env_float("LAB_TIME_DELTA_MS", 50.0)

# --- Секреты ----------------------------------------------------------------
# Только вымышленные значения для демонстрации. Реальных данных в проекте нет.
LAB_NAME = "SQL Injection Lab"
LAB_VERSION = "2.0"
