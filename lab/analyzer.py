"""Разбор SQL и детекция признаков инъекции.

Это «мозг» наглядности лаборатории. Модуль решает две задачи:

1. **Сегментация.** Разбирает готовый SQL на куски двух типов: ``code``
   (написанная разработчиком часть) и ``input`` (попавший в запрос ввод
   пользователя). Интерфейс подсвечивает их разными цветами, и студент
   видит физическую границу между «кодом» и «данными».

2. **Детекция сигналов.** Находит в пользовательском вводе характерные
   конструкции: закрытие кавычки, тавтологию, комментарий, ``UNION``,
   blind-условие, time-based, stacked-запрос, подзапрос, обращение к
   метаданным схемы. Каждый сигнал получает человекочитаемое объяснение.

Анализатор работает **на стороне сервера**, чтобы один и тот же движок
показывал одинаковую картину в браузере, в тестах и в документации.
"""

import re

# --- Шаблоны запросов --------------------------------------------------------
# {username} и {password} — подставляемые значения.
VULNERABLE_TEMPLATE = (
    "SELECT id, username, role FROM users "
    "WHERE username = '{username}' AND password = '{password}'"
)
SECURE_SQL = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --- Сегментация -------------------------------------------------------------
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")


def build_segments(template, values):
    """Разбить шаблон SQL на части ``code`` / ``input``.

    ``values`` — словарь ``{имя_поля: значение}``.
    Возвращает список сегментов с ключами ``kind``, ``text`` и, для ввода,
    ``field`` и ``length``.
    """
    segments = []
    pos = 0
    for match in _PLACEHOLDER_RE.finditer(template):
        if match.start() > pos:
            segments.append({"kind": "code", "text": template[pos : match.start()]})
        name = match.group(1)
        value = values.get(name, "")
        segments.append(
            {
                "kind": "input",
                "text": value,
                "field": name,
                "length": len(value),
            }
        )
        pos = match.end()
    if pos < len(template):
        segments.append({"kind": "code", "text": template[pos:]})
    return segments


def build_secure_segments(username, password):
    """Сегменты для параметризованного запроса.

    Вместо подставленного значения в тексте стоит плейсхолдер ``?`` —
    это и есть визуальное доказательство, что данные не смешаны с кодом.
    """
    return [
        {"kind": "code", "text": "SELECT id, username, role FROM users WHERE username = "},
        {"kind": "param", "text": "?", "field": "username", "value": username},
        {"kind": "code", "text": " AND password = "},
        {"kind": "param", "text": "?", "field": "password", "value": password},
    ]


# --- Детекция сигналов ------------------------------------------------------
# SQL-литерал: в кавычках, причём закрывающая кавычка может отсутствовать —
# в полном запросе её доставит шаблон, а не сам пользовательский ввод.
_LITERAL = r"""'(?:[^']*)'?|"(?:[^"]*)"?|\d+"""

_TAUTOLOGY_RE = re.compile(
    r"(?i)\bor\s+(?P<a>" + _LITERAL + r")\s*(?:=|<>|!=)\s*(?P<b>" + _LITERAL + r")"
)
_COMMENT_RE = re.compile(r"(?i)(--|#|/\*)")
_UNION_RE = re.compile(r"(?i)\bunion\b[\s\S]{0,200}?\bselect\b")
_SUBQUERY_RE = re.compile(r"(?i)\(\s*select\b")
_TIME_RE = re.compile(r"(?i)(sleep\s*\(|pg_sleep|randomblob\s*\(|waitfor\s+delay|benchmark\s*\()")
_SCHEMA_RE = re.compile(
    r"(?i)(sqlite_master|sqlite_temp_master|information_schema|sysobjects|"
    r"pg_catalog|pg_tables|all_tables|dba_users)"
)
_COMPARISON_RE = re.compile(r"(?i)(=|<>|!=|\blike\b|<|>)")
_STACKED_RE = re.compile(r"(?i);\s*(select|insert|update|delete|drop|create|alter|pragma)\b")


def _unquote(literal):
    """Снять кавычки с SQL-литерала.

    Закрывающая кавычка может отсутствовать (её подставит шаблон запроса),
    поэтому снимается только реально присутствующая пара кавычек.
    """
    if len(literal) >= 2 and literal[0] == literal[-1] and literal[0] in "'\"":
        return literal[1:-1]
    if len(literal) >= 1 and literal[0] in "'\"":
        return literal[1:]
    if len(literal) >= 1 and literal[-1] in "'\"":
        return literal[:-1]
    return literal


def _match_value(regex, text):
    """Вернуть первое совпадение или None."""
    m = regex.search(text)
    return m.group(0) if m else None


def detect_signals(text, field="username"):
    """Найти признаки инъекции в строке пользовательского ввода.

    Возвращает список сигналов — словарей с ключами ``id``, ``title``,
    ``detail``, ``severity``, ``evidence``.
    """
    if not text:
        return []

    signals = []
    lowered = text.lower()

    # 1. Закрытие строкового литерала кавычкой.
    quote_count = text.count("'")
    if quote_count:
        signals.append(
            {
                "id": "quote_terminator",
                "title": "Закрытие строкового литерала кавычкой",
                "detail": (
                    f"В поле «{field}» встречено кавычек: {quote_count}. "
                    "В уязвимом запросе значение подставляется внутрь "
                    "строки в кавычках, поэтому лишняя кавычка закрывает "
                    "литерал раньше времени, и всё, что идёт после неё, "
                    "СУБД читает уже как SQL-код, а не как данные."
                ),
                "severity": "high",
                "evidence": "'",
            }
        )

    # 2. Тавтология вида OR '1'='1' / OR 1=1.
    taut = None
    for m in _TAUTOLOGY_RE.finditer(text):
        if _unquote(m.group("a")) == _unquote(m.group("b")):
            taut = m.group(0)
            break
    if taut:
        signals.append(
            {
                "id": "tautology",
                "title": "Тавтология — условие всегда истинно",
                "detail": (
                    f"Найден фрагмент «{taut}». Такое условие истинно при любых "
                    "данных, поэтому проверка пароля теряет смысл: достаточно "
                    "одной константы, чтобы обойти авторизацию."
                ),
                "severity": "critical",
                "evidence": taut,
            }
        )

    # 3. Комментарий, отсекающий остаток запроса.
    comment = _match_value(_COMMENT_RE, text)
    if comment:
        signals.append(
            {
                "id": "comment",
                "title": "Комментарий отсекает остаток запроса",
                "detail": (
                    f"Найден «{comment}». Комментарий заставляет СУБД "
                    "проигнорировать всё, что идёт после него, — например "
                    "проверку пароля. Это классический приём, чтобы "
                    "«выключить» часть WHERE-условия."
                ),
                "severity": "high",
                "evidence": comment,
            }
        )

    # 4. UNION SELECT.
    union = _match_value(_UNION_RE, text)
    if union:
        signals.append(
            {
                "id": "union_select",
                "title": "UNION SELECT — подмена результата запроса",
                "detail": (
                    "UNION присоединяет к результату вторую выборку. Число "
                    "колонок должно совпадать, поэтому атакующий может "
                    "подставить свою — например, выбрать данные из другой "
                    "таблицы вместо колонки role."
                ),
                "severity": "critical",
                "evidence": union[:120],
            }
        )

    # 5. Blind-условие с подзапросом.
    if _SUBQUERY_RE.search(text) and _COMPARISON_RE.search(text):
        signals.append(
            {
                "id": "boolean_blind",
                "title": "Boolean blind — сравнение с подзапросом",
                "detail": (
                    "Ввод содержит подзапрос и сравнение. Ответ приложения "
                    "не содержит данных напрямую, но его можно угадывать "
                    "посимвольно: true или false — это один бит информации, "
                    "которого достаточно, чтобы восстановить значение "
                    "тайно хранимых данных."
                ),
                "severity": "high",
                "evidence": text[:120],
            }
        )

    # 6. Time-based.
    timing = _match_value(_TIME_RE, text)
    if timing:
        signals.append(
            {
                "id": "time_based",
                "title": "Time-based — воздействие на время ответа",
                "detail": (
                    f"Найден вызов «{timing}». Если вставленное выражение "
                    "выполняется, сервер отвечает медленнее. По разнице "
                    "времени можно извлекать данные, не получая их "
                    "в ответе напрямую."
                ),
                "severity": "high",
                "evidence": timing,
            }
        )

    # 7. Stacked-запрос.
    stacked = _match_value(_STACKED_RE, text)
    if stacked:
        signals.append(
            {
                "id": "stacked_query",
                "title": "Stacked query — попытка выполнить второй запрос",
                "detail": (
                    "После «;» можно попытаться запустить ещё один оператор. "
                    "В этой лаборатории драйвер sqlite3 такие цепочки "
                    "блокирует, и это само по себе является частью защиты."
                ),
                "severity": "medium",
                "evidence": stacked,
            }
        )

    # 8. Обращение к метаданным схемы.
    schema = _match_value(_SCHEMA_RE, text)
    if schema:
        signals.append(
            {
                "id": "schema_disclosure",
                "title": "Раскрытие схемы базы данных",
                "detail": (
                    f"Найдено «{schema}». Эти служебные таблицы содержат "
                    "описание всех объектов БД: имена таблиц, колонок и "
                    "их типы. Это первая ступень разведки перед кражей данных."
                ),
                "severity": "high",
                "evidence": schema,
            }
        )

    # 9. Прямое извлечение секретов.
    if union and "secrets" in lowered:
        signals.append(
            {
                "id": "data_exfiltration",
                "title": "Кража данных из таблицы secrets",
                "detail": (
                    "Через UNION вытаскиваются содержимое таблицы secrets — "
                    "в этой лаборатории там лежат учебные флаги. В реальном "
                    "приложении на этом месте обычно крадут пароли, токены "
                    "или персональные данные."
                ),
                "severity": "critical",
                "evidence": "secrets",
            }
        )

    signals.sort(key=lambda s: -SEVERITY_ORDER.get(s["severity"], 0))
    return signals


def verdict_for(signals):
    """Итоговый вердикт по списку сигналов."""
    if any(s["severity"] == "critical" for s in signals):
        return "dangerous", "Обнаружена критическая конструкция: ввод меняет смысл запроса."
    if any(s["severity"] == "high" for s in signals):
        return "dangerous", "Обнаружены признаки инъекции: ввод может изменить смысл запроса."
    if signals:
        return "suspicious", "Есть необычные конструкции — стоит проверить ввод вручную."
    return "safe", "Признаков инъекции не обнаружено: ввод выглядит как обычное значение."


def analyze(username, password, parameterized=False):
    """Полный разбор пары «логин/пароль».

    ``parameterized=True`` означает, что запрос выполняется параметризованно.
    В этом случае сигналы в самом вводе остаются, но их действие
    нейтрализуется — об этом прямо говорится в ``summary``.
    """
    signals = detect_signals(username, "username") + detect_signals(password, "password")
    signals.sort(key=lambda s: -SEVERITY_ORDER.get(s["severity"], 0))
    verdict, summary = verdict_for(signals)

    if parameterized and signals:
        summary = (
            "Инъекционные конструкции во вводе присутствуют, но запрос "
            "параметризован: значения передаются отдельно от SQL и "
            "интерпретируются как данные. Конструкция ищется буквально и "
            "ничего не меняет в логике запроса."
        )
    elif parameterized:
        summary = (
            "Признаков инъекции нет, а значения всё равно передаются "
            "параметрами — это гарантирует защиту даже от неожиданного ввода."
        )

    return {
        "verdict": verdict,
        "summary": summary,
        "signals": signals,
        "signal_count": len(signals),
        "max_severity": signals[0]["severity"] if signals else "none",
        "parameterized": parameterized,
    }


def explain_outcome(mode, row_count, success, bypassed):
    """Объяснить результат выполнения запроса простым языком."""
    if bypassed:
        return (
            "Авторизация обойдена: запрос вернул "
            f"{row_count} записей, хотя вход должен был проверять одну "
            "учётную запись. Условие WHERE было изменено вводом."
        )
    if mode == "secure" and success:
        return (
            "Вход выполнен: найдена ровно одна запись. Ввод был передан "
            "параметром и проверен как обычное значение."
        )
    if success:
        return "Вход выполнен: найдена ровно одна подходящая запись."
    if row_count == 0:
        return (
            "Совпадений нет: введённые логин и пароль не соответствуют "
            "ни одной записи в базе."
        )
    return (
        f"Найдено {row_count} записей — аномалия подавлена: доступ "
        "не предоставляется."
    )
