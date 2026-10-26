/* ==========================================================================
   Модуль «Дополнительные техники».
   UNION, blind (boolean и автоматическое извлечение), error-based и
   time-based. Каждый сценарий выполняется в обоих режимах, чтобы разница
   была видна сразу.
   ========================================================================== */

(function () {
    'use strict';

    window.LabModules = window.LabModules || {};

    function out(name) {
        return document.querySelector('[data-out="' + name + '"]');
    }

    function block(title, body, tone) {
        return '<div class="out-block ' + (tone ? 'is-' + tone : '') + '">' +
            '<h5>' + Lab.esc(title) + '</h5>' + body + '</div>';
    }

    function sqlSnippet(sql) {
        if (!sql) return '';
        return '<div class="sql-view"><span class="s-code">'
            + Lab.esc(Lab.shortSql(sql, 400)) + '</span></div>';
    }

    function formValues(form) {
        const username = form.querySelector('[name="username"]');
        const password = form.querySelector('[name="password"]');
        return {
            username: username ? username.value : '',
            password: password ? password.value : 'x',
        };
    }

    /* --- UNION ---------------------------------------------------------------- */
    async function runUnion(form, mode) {
        const box = out('union');
        const values = formValues(form);
        box.innerHTML = '<div class="loader">Выполняю запрос…</div>';

        const res = await Lab.api('/api/' + mode + '/login', {
            method: 'POST',
            body: { username: values.username, password: values.password },
        });
        const d = res.data || {};
        const analysis = d.analysis || {};

        let body =
            '<p><b>Ответ:</b> ' + Lab.esc(d.message || '') + '</p>' +
            '<p>Строк получено: <b>' + Lab.esc(d.row_count) + '</b></p>' +
            (analysis.summary ? '<p>' + Lab.esc(analysis.summary) + '</p>' : '') +
            sqlSnippet((d.sql || {}).raw);

        const rows = d.rows || [];
        if (rows.length) {
            body += '<div class="rows-wrap" id="unionRows"></div>';
        }
        box.innerHTML = block(
            mode === 'secure' ? 'Защищённый режим' : 'Небезопасный режим',
            body,
            mode === 'secure' ? 'sec' : 'vuln'
        );
        if (rows.length) Lab.renderRows(document.getElementById('unionRows'), rows);

        Lab.record({
            kind: 'technique',
            title: 'UNION-подстановка',
            mode: mode,
            input: values.username,
            result: d.message || '',
            sql: (d.sql || {}).raw || '',
            detail: analysis.summary || '',
        });
    }

    /* --- Error-based ----------------------------------------------------------- */
    async function runError(form, mode) {
        const box = out('error');
        const values = formValues(form);
        box.innerHTML = '<div class="loader">Выполняю запрос…</div>';

        const res = await Lab.api('/api/' + mode + '/error', {
            method: 'POST',
            body: { username: values.username, password: values.password },
        });
        const d = res.data || {};
        const leaked = d.leaked;

        const body =
            '<p><b>Что вернуло приложение:</b> ' + Lab.esc(d.message || '') + '</p>' +
            '<p>Детали ошибки утекли: <b>' + (leaked ? 'ДА' : 'нет') + '</b>.</p>' +
            (d.error
                ? '<div class="sql-view"><span class="s-input">' +
                  Lab.esc(Lab.shortSql(d.error, 300)) + '</span></div>'
                : '') +
            sqlSnippet((d.sql || {}).raw);

        box.innerHTML = block(
            mode === 'secure' ? 'Защищённый режим' : 'Небезопасный режим',
            body,
            mode === 'secure' ? 'sec' : 'vuln'
        );

        Lab.record({
            kind: 'technique',
            title: 'Error-based утечка',
            mode: mode,
            input: values.username,
            result: leaked ? 'детали ошибки раскрыты' : 'детали ошибки скрыты',
            sql: (d.sql || {}).raw || '',
            detail: d.message || '',
        });
    }

    /* --- Blind-проба ------------------------------------------------------------ */
    async function runBlind() {
        const box = out('blind');
        const condition = document.getElementById('blindCond').value;
        box.innerHTML = '<div class="loader">Выполняю пробы…</div>';

        const vuln = await Lab.api('/api/vulnerable/blind', {
            method: 'POST', body: { condition: condition },
        });
        const sec = await Lab.api('/api/secure/blind', {
            method: 'POST', body: { condition: condition },
        });
        const v = vuln.data || {};
        const s = sec.data || {};

        const body =
            '<p>Условие: <code>' + Lab.esc(condition) + '</code></p>' +
            '<p>Небезопасный режим: <b>' + (v.result ? 'истина' : 'ложь') +
            '</b> — условие выполнено как часть SQL.</p>' +
            '<p>Защищённый режим: <b>' + (s.result ? 'истина' : 'ложь') +
            '</b> — условие передано параметром и осталось данными.</p>' +
            sqlSnippet((v.sql || {}).raw);

        box.innerHTML = block('Blind-проба: true/false', body);

        Lab.record({
            kind: 'technique',
            title: 'Blind-проба условия',
            mode: 'vulnerable + secure',
            input: condition,
            result: 'уязвимый: ' + (v.result ? 'истина' : 'ложь') +
                ' · защищённый: ' + (s.result ? 'истина' : 'ложь'),
            sql: (v.sql || {}).raw || '',
            detail: 'Один запрос — один бит информации.',
        });
    }

    /* --- Автоизвлечение ------------------------------------------------------------ */
    async function runExtract() {
        const box = out('extract');
        box.innerHTML = '<div class="loader">Перебираю символы…</div>';

        const vuln = await Lab.api('/api/vulnerable/extract', {
            method: 'POST', body: { row: 1, max_steps: 64 },
        });
        const sec = await Lab.api('/api/secure/extract', {
            method: 'POST', body: { row: 1, max_steps: 64 },
        });
        const v = vuln.data || {};
        const s = sec.data || {};
        const extraction = v.extraction || {};
        const log = extraction.log || [];

        const tail = log.slice(-10).map((item) =>
            '<div><span class="probe">символ ' + Lab.esc(item.position) + ':</span> ' +
            Lab.esc(item.condition) + ' → <span class="ok">' +
            Lab.esc(item.char) + '</span></div>').join('');

        const body =
            '<p>Восстановленное значение: <b>' +
            Lab.esc(extraction.value || '(не найдено)') + '</b></p>' +
            '<p>Потрачено запросов: <b>' + Lab.esc(extraction.steps || 0) + '</b> · ' +
            'в защищённом режиме: <b>' + Lab.esc((s.extraction || {}).steps || 0) + '</b> ' +
            'и результат пуст.</p>' +
            '<div class="extract-log">' + (tail || 'Журнал проб пуст.') + '</div>';

        box.innerHTML = block('Посимвольное извлечение', body,
            extraction.value ? 'vuln' : 'sec');

        Lab.record({
            kind: 'technique',
            title: 'Автоизвлечение секрета (blind)',
            mode: 'vulnerable',
            input: 'SUBSTR(...) = символ',
            result: 'извлечено: ' + (extraction.value || '(нет)') +
                ' за ' + (extraction.steps || 0) + ' запросов',
            sql: (v.sql || {}).raw || '',
            detail: 'В защищённом режиме секрет не восстанавливается.',
        });
    }

    /* --- Time-based ----------------------------------------------------------------- */
    async function runTime() {
        const box = out('time');
        const workload = Number(document.getElementById('timeWorkload').value || 0);
        box.innerHTML = '<div class="loader">Измеряю задержку…</div>';

        const vuln = await Lab.api('/api/vulnerable/time', {
            method: 'POST', body: { workload: workload },
        });
        const sec = await Lab.api('/api/secure/time', {
            method: 'POST', body: { workload: workload },
        });
        const v = vuln.data || {};
        const s = sec.data || {};
        const vt = v.timing || {};
        const st = s.timing || {};

        const body =
            '<div class="out-metrics">' +
            '<div><span>уязвимый, база: </span><b>' + Lab.esc(vt.baseline_ms) + ' мс</b></div>' +
            '<div><span>уязвимый, с нагрузкой: </span><b>' + Lab.esc(vt.payload_ms) + ' мс</b></div>' +
            '<div><span>разница: </span><b>' + Lab.esc(vt.delta_ms) + ' мс</b></div>' +
            '<div><span>порог: </span><b>' + Lab.esc(vt.threshold_ms) + ' мс</b></div>' +
            '</div>' +
            '<p style="margin-top:12px">Небезопасный режим: <b>' +
            (vt.detectable ? 'задержка измерима' : 'задержка не выделяется') + '</b>.</p>' +
            '<p>Защищённый режим: разница <b>' + Lab.esc(st.delta_ms) + ' мс</b> — ' +
            (st.detectable ? 'заметна' : 'нагрузка не выполнялась, это данные') + '.</p>' +
            sqlSnippet((v.sql || {}).raw);

        box.innerHTML = block('Замер задержки ответа', body);

        Lab.record({
            kind: 'technique',
            title: 'Time-based замер',
            mode: 'vulnerable + secure',
            input: 'workload = ' + workload,
            result: 'разница в уязвимом режиме: ' + vt.delta_ms + ' мс',
            sql: (v.sql || {}).raw || '',
            detail: 'В защищённом режиме выражение из ввода не исполняется.',
        });
    }

    /* --- Инициализация --------------------------------------------------------------- */
    function init() {
        Lab.$$('.tech-form').forEach((form) => {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                const submitter = event.submitter;
                const mode = submitter && submitter.value === 'secure' ? 'secure' : 'vulnerable';
                const tech = form.dataset.tech;
                if (tech === 'union') runUnion(form, mode);
                if (tech === 'error') runError(form, mode);
            });
        });

        const blindBtn = document.getElementById('blindProbe');
        if (blindBtn) blindBtn.addEventListener('click', runBlind);

        const extractBtn = document.getElementById('blindExtract');
        if (extractBtn) extractBtn.addEventListener('click', runExtract);

        const timeBtn = document.getElementById('timeRun');
        if (timeBtn) timeBtn.addEventListener('click', runTime);
    }

    window.LabModules.techniques = { init: init };
})();
