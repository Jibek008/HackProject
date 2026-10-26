"""Flask-роуты лаборатории.

    main        — главная страница, справочные эндпоинты
    vulnerable  — небезопасная реализация (только для учебной демонстрации)
    secure      — защищённая реализация (рекомендуемый образец)
"""

from . import main, secure, vulnerable  # noqa: F401

__all__ = ["main", "secure", "vulnerable"]
