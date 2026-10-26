/* ==========================================================================
   Модуль «Отчёт».
   Собирает из журнала экспериментов готовый фрагмент Markdown для
   лабораторной работы: можно скопировать в буфер или скачать файлом.
   ========================================================================== */

(function () {
    'use strict';

    window.LabModules = window.LabModules || {};

    const KIND_TITLES = {
        compare: 'Сравнение двух режимов',
        demo: 'Демонстрация входа',
        technique: 'Эксперимент по технике',
        analysis: 'Статический разбор ввода',
        quiz: 'Вопрос квиза',
    };

    function today() {
        const d = new Date();
        const p = (n) => String(n).padStart(2, '0');
        return p(d.getDate()) + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear();
    }

    function escapeInline(text) {
        return String(text === null || text === undefined ? '' : text)
            .replace(/`/g, "'")
            .replace(/\r?\n/g, ' ');
    }

    function buildMarkdown() {
        const journal = Lab.journal || [];
        const lines = [];

        lines.push('# Отчёт по лабораторной работе: SQL Injection');
        lines.push('');
        lines.push('**Дата:** ' + today());
        lines.push('**Среда:** локальная лаборатория SQL Injection Lab (Flask + SQLite, 127.0.0.1)');
        lines.push('**Данные:** вымышленные, реальных учётных записей в лаборатории нет.');
        lines.push('');

        lines.push('## 1. Цель работы');
        lines.push('');
        lines.push('На практике показать механизм SQL Injection и способ защиты от него — ' +
            'параметризованные запросы. Работа выполнена в специально созданной ' +
            'лаборатории, где один и тот же ввод отправляется в уязвимый и в защищённый ' +
            'обработчики.');
        lines.push('');

        lines.push('## 2. Теоретическая часть');
        lines.push('');
        lines.push('SQL-инъекция возникает, когда пользовательские данные попадают в текст ' +
            'SQL-запроса и становятся его частью. Классический пример — конкатенация:');
        lines.push('');
        lines.push('```sql');
        lines.push("SELECT id, username, role FROM users WHERE username = '<ввод>' AND password = '<ввод>'");
        lines.push('```');
        lines.push('');
        lines.push('Если ввод содержит кавычку, он закрывает строковый литерал, и всё, ' +
            'что идёт дальше, СУБД читает уже как код. Защита строится на разделении ' +
            'кода и данных: SQL-шаблон с плейсхолдерами отправляется отдельно от ' +
            'значений, и тогда параметр не может изменить структуру запроса.');
        lines.push('');

        const experiments = journal.filter((item) => item.kind !== 'quiz');
        const quizzes = journal.filter((item) => item.kind === 'quiz');

        lines.push('## 3. Выполненные эксперименты');
        lines.push('');

        if (!experiments.length) {
            lines.push('_Эксперименты пока не проводились — выполните несколько сценариев ' +
                'в разделах «Сравнение», «Дополнительные техники» или «Мастер демонстрации»._');
            lines.push('');
        } else {
            experiments.forEach((item, index) => {
                lines.push('### 3.' + (index + 1) + ' ' + (KIND_TITLES[item.kind] || item.title));
                lines.push('');
                lines.push('- **Режим:** ' + escapeInline(item.mode || '—'));
                if (item.input) {
                    lines.push('- **Ввод:** `' + escapeInline(item.input) + '`');
                }
                if (item.result) {
                    lines.push('- **Результат:** ' + escapeInline(item.result));
                }
                if (item.sql) {
                    lines.push('- **Сформированный запрос:**');
                    lines.push('');
                    lines.push('```sql');
                    lines.push(item.sql);
                    lines.push('```');
                }
                if (item.detail) {
                    lines.push('- **Комментарий:** ' + escapeInline(item.detail));
                }
                lines.push('');
            });
        }

        if (quizzes.length) {
            lines.push('## 4. Проверка понимания');
            lines.push('');
            quizzes.forEach((item) => {
                lines.push('- ' + escapeInline(item.input) + ' — **' +
                    escapeInline(item.result) + '**');
            });
            lines.push('');
        }

        lines.push('## ' + (quizzes.length ? 5 : 4) + '. Выводы');
        lines.push('');
        lines.push('1. В уязвимом режиме ввод меняет смысл запроса: проверка пароля ' +
            'отключается тавтологией или комментарием, а через UNION можно вывести ' +
            'данные другой таблицы.');
        lines.push('2. Blind-техники работают даже тогда, когда вывод данных недоступен: ' +
            'по одному биту на запрос восстанавливается значение целиком.');
        lines.push('3. В защищённом режиме ни один из применённых способов не даёт ' +
            'эффекта: значения передаются параметрами и остаются данными.');
        lines.push('4. Главный вывод: уязвимость создаёт не «неаккуратный ввод», ' +
            'а способ сборки запроса. Параметризация устраняет класс атак целиком, ' +
            'а не отдельные payload\'ы.');
        lines.push('');
        lines.push('---');
        lines.push('');
        lines.push('_Отчёт сформирован автоматически интерфейсом SQL Injection Lab._');

        return lines.join('\n');
    }

    function refresh() {
        const preview = document.getElementById('reportPreview');
        if (!preview) return;
        const markdown = buildMarkdown();
        preview.textContent = markdown;
        return markdown;
    }

    function copy() {
        const markdown = buildMarkdown();
        const done = () => Lab.log('ok', 'отчёт скопирован в буфер обмена');
        const fail = () => Lab.log('err', 'не удалось скопировать отчёт');

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(markdown).then(done, fail);
            return;
        }
        const area = document.createElement('textarea');
        area.value = markdown;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try {
            document.execCommand('copy');
            done();
        } catch (err) {
            fail();
        }
        document.body.removeChild(area);
    }

    function download() {
        const markdown = buildMarkdown();
        const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'sqli-lab-report.md';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        Lab.log('ok', 'отчёт сохранён: sqli-lab-report.md');
    }

    function init() {
        refresh();

        const copyBtn = document.getElementById('reportCopy');
        if (copyBtn) copyBtn.addEventListener('click', copy);

        const downloadBtn = document.getElementById('reportDownload');
        if (downloadBtn) downloadBtn.addEventListener('click', download);

        const clearBtn = document.getElementById('reportClear');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                Lab.journal.length = 0;
                refresh();
                Lab.log('info', 'журнал экспериментов очищен');
            });
        }
    }

    window.LabModules.report = {
        init: init,
        refresh: refresh,
        buildMarkdown: buildMarkdown,
    };
})();
