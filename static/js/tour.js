/* ==========================================================================
   Модуль «Мастер демонстрации».
   Восемь шагов, которые проходят лабораторию целиком: от легитимного входа
   до автоматического извлечения секрета. Каждый шаг можно выполнить прямо
   в панели — запрос уходит в API, ответ показывается рядом с объяснением.
   ========================================================================== */

(function () {
    'use strict';

    window.LabModules = window.LabModules || {};

    const STEPS = [
        {
            title: 'Цель атаки',
            text: 'В базе три демонстрационные учётные записи и таблица secrets ' +
                'с учебными флагами. Сначала посмотрите, что именно лежит в базе, — ' +
                'это и есть разведка перед атакой.',
            goal: 'Откройте раздел «Цель атаки» и посмотрите состав таблиц.',
            section: '#target',
        },
        {
            title: 'Легитимный вход',
            text: 'Правильный логин и правильный пароль. Оба обработчика ведут себя ' +
                'одинаково — пока разницы нет.',
            goal: 'Сравните оба режима на корректных учётных данных.',
            section: '#compare',
            fill: { form: 'cmp', username: 'student', password: 'lab_pass_123' },
            demo: (Lab) => demoCompare(Lab, 'student', 'lab_pass_123'),
        },
        {
            title: 'Как собирается запрос',
            text: 'Слева SQL строится конкатенацией — ввод попадает внутрь строки ' +
                'в кавычках. Справа тот же ввод передаётся параметром. Обратите ' +
                'внимание на подсветку: красное — данные пользователя.',
            goal: 'Посмотрите сформированный SQL в обоих режимах.',
            section: '#demos',
            fill: { form: 'vuln', username: 'student', password: 'lab_pass_123' },
            demo: (Lab) => demoLogin(Lab, 'vulnerable', 'student', 'lab_pass_123'),
        },
        {
            title: 'Классический обход',
            text: 'Кавычка закрывает строковый литерал, условие OR становится ' +
                'истинным всегда, а комментарий отсекает проверку пароля. ' +
                'Пароль «anything» неверный — но вход выполняется.',
            goal: 'Проверьте, что уязвимый режим пускает внутрь при неверном пароле.',
            section: '#demos',
            fill: { form: 'vuln', username: "student' OR '1'='1' --", password: 'anything' },
            demo: (Lab) => demoLogin(Lab, 'vulnerable', "student' OR '1'='1' --", 'anything'),
        },
        {
            title: 'Тот же ввод — другой результат',
            text: 'Теперь тот же самый ввод отправляется в защищённый обработчик. ' +
                'Строка ищется буквально, условие OR так и остаётся текстом. ' +
                'Это и есть разница между уязвимостью и защитой.',
            goal: 'Убедитесь, что защищённый режим отказал в доступе.',
            section: '#demos',
            fill: { form: 'sec', username: "student' OR '1'='1' --", password: 'anything' },
            demo: (Lab) => demoLogin(Lab, 'secure', "student' OR '1'='1' --", 'anything'),
        },
        {
            title: 'Кража данных через UNION',
            text: 'UNION присоединяет вторую выборку. Число колонок совпадает — ' +
                'поэтому вместо роли пользователя в выдаче оказывается содержимое ' +
                'таблицы secrets.',
            goal: 'Посмотрите, как учебный флаг появляется прямо в ответе.',
            section: '#techniques',
            fill: { form: 'vuln', username: "' UNION SELECT id, owner, content FROM secrets --", password: 'x' },
            demo: (Lab) => demoLogin(Lab, 'vulnerable', "' UNION SELECT id, owner, content FROM secrets --", 'x'),
        },
        {
            title: 'Blind-канал: true или false',
            text: 'Когда вывод данных недоступен, остаётся один бит за запрос: ' +
                'истинно условие или ложно. В защищённом режиме условие передано ' +
                'параметром и всегда ложно.',
            goal: 'Сравните ответ уязвимого и защищённого обработчиков.',
            section: '#techniques',
            demo: (Lab) => demoBlind(Lab),
        },
        {
            title: 'Автоматическое извлечение',
            text: 'Лаборатория собирает значение посимвольно: по одному биту на ' +
                'запрос. Такой перебор и есть настоящий blind — и он полностью ' +
                'восстанавливает секрет.',
            goal: 'Запустите извлечение и посмотрите, как собирается значение.',
            section: '#techniques',
            demo: (Lab) => demoExtract(Lab),
        },
    ];

    let current = 0;

    /* --- Демонстрации для шагов ------------------------------------------------ */
    function resultBox(title, body, tone) {
        return '<div class="out-block ' + (tone ? 'is-' + tone : '') + '">' +
            '<h5>' + Lab.esc(title) + '</h5>' + body + '</div>';
    }

    function sqlSnippet(sql) {
        return '<div class="sql-view"><span class="s-code">'
            + Lab.esc(Lab.shortSql(sql, 400)) + '</span></div>';
    }

    async function demoCompare(Lab, username, password) {
        const vuln = await Lab.api('/api/vulnerable/login', {
            method: 'POST', body: { username: username, password: password },
        });
        const sec = await Lab.api('/api/secure/login', {
            method: 'POST', body: { username: username, password: password },
        });
        const v = vuln.data || {};
        const s = sec.data || {};
        const body =
            '<p>Небезопасный режим: <b>' + (v.success ? 'вход выполнен' : 'отказ') +
            '</b>, строк — ' + Lab.esc(v.row_count) + '.</p>' +
            '<p>Защищённый режим: <b>' + (s.success ? 'вход выполнен' : 'отказ') +
            '</b>, строк — ' + Lab.esc(s.row_count) + '.</p>' +
            sqlSnippet((v.sql || {}).raw);
        return resultBox('Результат сравнения', body);
    }

    async function demoLogin(Lab, mode, username, password) {
        const res = await Lab.api('/api/' + mode + '/login', {
            method: 'POST', body: { username: username, password: password },
        });
        const d = res.data || {};
        const tone = d.bypassed ? 'vuln' : (d.success ? 'sec' : '');
        const body =
            '<p><b>Ответ:</b> ' + Lab.esc(d.message || '') + '</p>' +
            '<p>Строк получено: <b>' + Lab.esc(d.row_count) + '</b>.</p>' +
            ((d.analysis || {}).summary
                ? '<p>' + Lab.esc(d.analysis.summary) + '</p>' : '') +
            sqlSnippet((d.sql || {}).raw);
        return resultBox(mode === 'secure' ? 'Защищённый режим' : 'Небезопасный режим', body, tone);
    }

    async function demoBlind(Lab) {
        const vuln = await Lab.api('/api/vulnerable/blind', {
            method: 'POST', body: { condition: '1=1' },
        });
        const sec = await Lab.api('/api/secure/blind', {
            method: 'POST', body: { condition: '1=1' },
        });
        const v = vuln.data || {};
        const s = sec.data || {};
        const body =
            '<p>Условие <code>1=1</code>.</p>' +
            '<p>Небезопасный режим: <b>' + (v.result ? 'истина' : 'ложь') +
            '</b> — условие стало частью SQL.</p>' +
            '<p>Защищённый режим: <b>' + (s.result ? 'истина' : 'ложь') +
            '</b> — условие искалось как обычная строка.</p>';
        return resultBox('Blind-проба', body);
    }

    async function demoExtract(Lab) {
        const res = await Lab.api('/api/vulnerable/extract', {
            method: 'POST', body: { row: 1, max_steps: 64 },
        });
        const d = res.data || {};
        const extraction = d.extraction || {};
        const log = extraction.log || [];
        const tail = log.slice(-8).map((item) =>
            '<div><span class="probe">проба ' + Lab.esc(item.position) + ':</span> ' +
            Lab.esc(item.condition) + ' → <span class="ok">' +
            Lab.esc(item.char) + '</span></div>').join('');
        const body =
            '<p>Восстановленное значение: <b>' +
            Lab.esc(extraction.value || '(не найдено)') + '</b></p>' +
            '<p>Потрачено запросов: <b>' + Lab.esc(extraction.steps || 0) + '</b>.</p>' +
            '<div class="extract-log">' + (tail || 'Журнал пуст.') + '</div>';
        return resultBox('Извлечение секрета', body, extraction.value ? 'vuln' : '');
    }

    /* --- Отрисовка шагов --------------------------------------------------------- */
    function renderStepList() {
        const list = document.getElementById('tourSteps');
        if (!list) return;
        list.innerHTML = STEPS.map((step, index) =>
            '<li data-index="' + index + '">' + Lab.esc(step.title) + '</li>').join('');
        Array.from(list.querySelectorAll('li')).forEach((item) => {
            item.addEventListener('click', () => {
                current = Number(item.dataset.index);
                render();
            });
        });
    }

    function fillForms(step) {
        if (!step.fill) return;
        const map = {
            cmp: ['cmpUser', 'cmpPass'],
            vuln: ['vulnUser', 'vulnPass'],
            sec: ['secUser', 'secPass'],
        };
        const ids = map[step.fill.form];
        if (!ids) return;
        const u = document.getElementById(ids[0]);
        const p = document.getElementById(ids[1]);
        if (u) u.value = step.fill.username;
        if (p) p.value = step.fill.password;
    }

    async function render() {
        const step = STEPS[current];
        const list = document.getElementById('tourSteps');
        const hint = document.getElementById('tourHint');
        const label = document.getElementById('tourStepLabel');
        const bar = document.getElementById('tourProgress');
        const prev = document.getElementById('tourPrev');
        const next = document.getElementById('tourNext');

        if (list) {
            Array.from(list.querySelectorAll('li')).forEach((item, index) => {
                item.classList.toggle('is-active', index === current);
                item.classList.toggle('is-done', index < current);
            });
        }
        if (label) label.textContent = 'Шаг ' + (current + 1) + ' из ' + STEPS.length;
        if (bar) bar.style.width = ((current + 1) / STEPS.length * 100) + '%';
        if (prev) prev.disabled = current === 0;
        if (next) next.textContent = current === STEPS.length - 1 ? 'Готово ✓' : 'Далее →';

        fillForms(step);

        if (hint) {
            hint.innerHTML =
                '<h4>' + Lab.esc(step.title) + '</h4>' +
                '<p>' + Lab.esc(step.text) + '</p>' +
                '<div class="tour-goal"><b>Что сделать:</b> ' + Lab.esc(step.goal) + '</div>' +
                (step.demo
                    ? '<div class="form-actions"><button type="button" class="btn btn-primary" ' +
                      'id="tourRun">Показать результат</button></div>' +
                      '<div id="tourResult"></div>'
                    : '');
        }

        const run = document.getElementById('tourRun');
        if (run) {
            run.addEventListener('click', async () => {
                const target = document.getElementById('tourResult');
                if (target) target.innerHTML = '<div class="loader">Выполняю запрос…</div>';
                try {
                    const html = await step.demo(Lab);
                    if (target) target.innerHTML = html;
                } catch (err) {
                    if (target) target.innerHTML = '<div class="loader">Ошибка: '
                        + Lab.esc(err.message) + '</div>';
                }
            });
        }

        if (step.section) {
            const target = document.querySelector(step.section);
            if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    function init() {
        const Lab = window.Lab;
        renderStepList();

        const prev = document.getElementById('tourPrev');
        const next = document.getElementById('tourNext');
        if (prev) {
            prev.addEventListener('click', () => {
                if (current > 0) { current -= 1; render(); }
            });
        }
        if (next) {
            next.addEventListener('click', () => {
                if (current < STEPS.length - 1) {
                    current += 1;
                    render();
                } else {
                    Lab.log('info', 'мастер демонстрации пройден');
                    const box = document.getElementById('tourHint');
                    if (box) {
                        box.insertAdjacentHTML('beforeend',
                            '<div class="tour-goal" style="margin-top:12px"><b>Поздравляем.</b> ' +
                            'Теперь попробуйте собрать отчёт в разделе «Отчёт» — ' +
                            'все эксперименты уже записаны в журнал.</div>');
                    }
                }
            });
        }

        render();
    }

    window.LabModules.tour = { init: init, steps: STEPS };
})();
