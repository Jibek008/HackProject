"""Обработка пользовательского ввода.

Здесь собраны те «гигиенические» меры, которые применяются к вводу в обоих
режимах лаборатории:

* приведение к строке;
* обрезка по максимальной длине;
* нормализация управляющих символов.

Важный момент: **ни одна из этих мер не защищает от SQL Injection**. Это
показано в лаборатории напрямую — payload вида ``student' OR '1'='1' --``
проходит все проверки целиком и всё равно меняет семантику запроса.
Единственная настоящая защита — параметризация (см. ``lab/routes/secure.py``).
"""

from config import MAX_CONTENT_LENGTH, MAX_INPUT_LEN

# Управляющие символы, которые не несут смысла для демонстрации,
# но мешают читаемости вывода.
_CONTROL_MAP = {
    0x00: "",
    0x08: "",
    0x09: " ",
    0x0A: " ",
    0x0D: " ",
    0x0C: "",
}


def clean(value, max_len=MAX_INPUT_LEN):
    """Привести ввод к безопасному строковому значению.

    Возвращает строку длиной не более ``max_len``. ``None`` превращается в
    пустую строку, нестроковые значения — в их строковое представление.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.translate(_CONTROL_MAP)
    return value[:max_len]


def is_empty(value):
    """Пустое ли значение (после очистки)."""
    return not clean(value).strip()


def truncate_for_display(value, limit=80):
    """Обрезать значение для показа в интерфейсе."""
    value = clean(value)
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def mask_secret(value):
    """Замаскировать значение пароля для показа в интерфейсе.

    Пароль не должен возвращаться клиенту даже в демонстрационных целях:
    сам факт того, что значение ушло параметром, показывает плейсхолдер
    ``?`` и сам анализатор. Содержимое при этом не нужно.
    """
    if not value:
        return ""
    return "•" * min(len(value), 12)


def credentials_from_request(request, max_len=MAX_INPUT_LEN):
    """Достать из JSON-тела пару логин/пароль.

    Любой некорректный ввод (не-JSON, не-словарь, отсутствие полей)
    приводит к пустым строкам, а не к исключению.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    return clean(data.get("username"), max_len), clean(data.get("password"), max_len)


def field_from_request(request, name, max_len=MAX_INPUT_LEN, default=""):
    """Достать одно строковое поле из JSON-тела запроса."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return default
    return clean(data.get(name, default), max_len)


def request_too_large(request, limit=MAX_CONTENT_LENGTH):
    """Проверить, не превышает ли тело запроса допустимый размер."""
    length = request.content_length or 0
    return length > limit
