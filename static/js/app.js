/* ==========================================================================
   SQL Injection Lab — ядро интерфейса.
   Общие утилиты, работа с API, журнал экспериментов, консоль, тема,
   формы сравнения и подробных демонстраций, каталог техник, схема БД.
   ========================================================================== */

(function () {
    'use strict';

    /* --- Общее состояние ---------------------------------------------------- */
    const Lab = {
        journal: [],        // журнал экспериментов (для отчёта)
        payloads: [],       // каталог техник с сервера
        modules: window.LabModules || {},  // подключённые модули интерфейса
    };
    window.Lab = Lab;

    /* --- Мелкие утилиты ------------------------------------------------------ */
    const $ = (sel, root) => (root || document).querySelector(sel);
    const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

    function esc(value) {
        return String(value === null || value === undefined ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function el(id) {
        return document.getElementById(id);
    }

    function nowStamp() {
        const d = new Date();
        const p = (n) => String(n).padStart(2, '0');
        return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    }

    function shortSql(text, limit) {
        const s = String(text || '');
        return s.length > limit ? s.slice(0, limit) + '…' : s;
    }

    /* --- Консоль запросов ---------------------------------------------------- */
    function logConsole(kind, message) {
        const box = el('consoleBox');
        if (!box) return;
        const line = document.createElement('span');
        line.className = 'c-line';
        line.innerHTML =
            '<span class="c-time">[' + esc(nowStamp()) + ']</span> ' +
            '<span class="c-' + esc(kind) + '">' + esc(message) + '</span>';
        box.appendChild(line);
        box.scrollTop = box.scrollHeight;
    }

    /* --- Обращение к API ----------------------------------------------------- */
    async function api(path, options) {
        const opts = options || {};
        const method = opts.method || 'GET';
        const started = performance.now();
        let response;
        try {
            response = await fetch(path, {
                method: method,
                headers: opts.body ? { 'Content-Type': 'application/json' } : {},
                body: opts.body ? JSON.stringify(opts.body) : undefined,
            });
        } catch (err) {
            logConsole('err', method + ' ' + path + ' → сетевая ошибка: ' + err.message);
            return { ok: false, status: 0, data: { message: 'Сервер недоступен.' } };
        }
        const ms = (performance.now() - started).toFixed(0);
        let data = null;
        try {
            data = await response.json();
        } catch (err) {
            data = { message: 'Некорректный ответ сервера.' };
        }
        const mark = response.ok ? 'ok' : 'err';
        logConsole(
            mark,
            method + ' ' + path + ' → ' + response.status + ' (' + ms + ' мс)'
        );
        return { ok: response.ok, status: response.status, data: data || {} };
    }

    /* --- Отрисовка SQL с подсветкой ------------------------------------------ */
    function renderSql(container, sqlBlock) {
        if (!container) return;
        const block = sqlBlock || {};
        const segments = block.segments || [];
        if (!segments.length) {
            container.innerHTML = '<span class="s-code">' + esc(block.raw || '') + '</span>';
            return;
        }
        let html = '';
        segments.forEach((seg) => {
            const text = esc(seg.text === undefined ? '' : seg.text);
            if (seg.kind === 'input') {
                html += '<span class="s-input" title="ввод пользователя в поле '
                    + esc(seg.field || '') + '">' + text + '</span>';
            } else if (seg.kind === 'param') {
                const title = seg.value === undefined ? '' : esc(seg.value);
                html += '<span class="s-param" title="значение параметра: ' + title + '">'
                    + text + '</span>';
            } else {
                html += '<span class="s-code">' + text + '</span>';
            }
        });
        html +=
            '<div class="sql-legend">' +
            '<span><i class="legend-code"></i>код разработчика</span>' +
            '<span><i class="legend-input"></i>ввод пользователя</span>' +
            '<span><i class="legend-param"></i>параметр ?</span>' +
            '</div>';
        container.innerHTML = html;
    }

    /* --- Отрисовка вердикта -------------------------------------------------- */
    const VERDICT_STYLE = {
        dangerous: ['is-danger', 'Опасный ввод'],
        suspicious: ['is-warn', 'Подозрительный ввод'],
        safe: ['is-safe', 'Безопасно'],
        blind: ['is-danger', 'Канал blind работает'],
        leak: ['is-danger', 'Утечка данных'],
        delay: ['is-warn', 'Задержка ответа'],
        blocked: ['is-safe', 'Атака заблокирована'],
        info: ['is-info', 'Справочно'],
    };

    function renderVerdict(container, data) {
        if (!container) return;
        const analysis = (data && data.analysis) || {};
        const verdict = analysis.verdict || 'info';
        const style = VERDICT_STYLE[verdict] || VERDICT_STYLE.info;
        container.className = 'verdict is-visible ' + style[0];
        const meta = [];
        if (analysis.signal_count !== undefined) {
            meta.push('сигналов: ' + analysis.signal_count);
        }
        if (analysis.max_severity && analysis.max_severity !== 'none') {
            meta.push('макс. серьёзность: ' + analysis.max_severity);
        }
        if (analysis.parameterized !== undefined) {
            meta.push(analysis.parameterized ? 'запрос параметризован' : 'запрос собран конкатенацией');
        }
        if (data && data.bypassed) meta.push('обход авторизации подтверждён');
        if (data && data.explanation) meta.push(data.explanation);

        container.innerHTML =
            '<b>' + esc(style[1]) + '</b>' +
            esc(analysis.summary || '') +
            (meta.length
                ? '<div class="verdict-meta">' + esc(meta.join(' · ')) + '</div>'
                : '');
    }

    /* --- Отрисовка сигналов ---------------------------------------------------- */
    function renderSignals(container, analysis) {
        if (!container) return;
        const signals = (analysis && analysis.signals) || [];
        if (!signals.length) {
            container.innerHTML = '<div class="signal sev-info">' +
                '<div class="signal-head"><span class="signal-title">Сигналы не обнаружены</span>' +
                '<span class="signal-sev">info</span></div>' +
                '<div class="signal-detail">Во вводе нет характерных конструкций. ' +
                'Это не гарантия безопасности — гарантию даёт только параметризация.</div></div>';
            return;
        }
        container.innerHTML = signals.map((s) =>
            '<div class="signal sev-' + esc(s.severity) + '">' +
            '<div class="signal-head">' +
            '<span class="signal-title">' + esc(s.title) + '</span>' +
            '<span class="signal-sev">' + esc(s.severity) + '</span>' +
            '</div>' +
            '<div class="signal-detail">' + esc(s.detail) + '</div>' +
            (s.evidence
                ? '<div class="signal-evidence">' + esc(shortSql(s.evidence, 160)) + '</div>'
                : '') +
            '</div>'
        ).join('');
    }

    /* --- Отрисовка строк результата ------------------------------------------- */
    const COLUMN_LABELS = {
        id: 'id',
        username: 'username',
        role: 'role',
        owner: 'owner',
        content: 'content',
        preview: 'preview',
    };

    function renderRows(container, rows) {
        if (!container) return;
        if (!rows || !rows.length) {
            container.innerHTML = '<table class="rows"><tbody>' +
                '<tr><td class="empty">Строк нет — запрос ничего не вернул.</td></tr>' +
                '</tbody></table>';
            return;
        }
        const keys = Object.keys(rows[0]);
        const head = '<tr>' + keys.map((k) =>
            '<th>' + esc(COLUMN_LABELS[k] || k) + '</th>').join('') + '</tr>';
        const body = rows.map((row) =>
            '<tr>' + keys.map((k) => {
                const value = row[k] === null || row[k] === undefined ? '' : String(row[k]);
                const cls = value.indexOf('FLAG{') === 0 ? 'flag' : '';
                return '<td class="' + cls + '">' + esc(value) + '</td>';
            }).join('') + '</tr>'
        ).join('');
        container.innerHTML = '<table class="rows"><thead>' + head + '</thead><tbody>'
            + body + '</tbody></table>';
    }

    /* --- Журнал экспериментов ------------------------------------------------ */
    function record(entry) {
        Lab.journal.push({
            time: nowStamp(),
            kind: entry.kind || 'experiment',
            title: entry.title || 'Эксперимент',
            mode: entry.mode || '',
            input: entry.input || '',
            result: entry.result || '',
            sql: entry.sql || '',
            detail: entry.detail || '',
        });
        if (Lab.modules.report && Lab.modules.report.refresh) {
            Lab.modules.report.refresh();
        }
    }

    /* --- Тема ------------------------------------------------------------------ */
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        Lab.theme = theme;
        try {
            localStorage.setItem('sqli-theme', theme);
        } catch (err) { /* localStorage может быть недоступен — не критично */ }
    }

    function initTheme() {
        let saved = null;
        try {
            saved = localStorage.getItem('sqli-theme');
        } catch (err) { saved = null; }
        applyTheme(saved || 'dark');
        const toggle = el('themeToggle');
        if (toggle) {
            toggle.addEventListener('click', () => {
                applyTheme(Lab.theme === 'dark' ? 'light' : 'dark');
                logConsole('info', 'тема: ' + Lab.theme);
            });
        }
    }

    /* --- Подсветка активного пункта меню -------------------------------------- */
    function initNavSpy() {
        const links = $$('.nav-link');
        const sections = links
            .map((a) => document.querySelector(a.getAttribute('href')))
            .filter(Boolean);
        if (!sections.length || !('IntersectionObserver' in window)) return;

        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) return;
                links.forEach((a) => {
                    a.classList.toggle('is-active',
                        a.getAttribute('href') === '#' + entry.target.id);
                });
            });
        }, { rootMargin: '-45% 0px -50% 0px', threshold: 0 });

        sections.forEach((s) => observer.observe(s));
    }

    /* --- Схема базы ------------------------------------------------------------- */
    async function loadSchema() {
        const block = el('schemaBlock');
        if (!block) return;
        const res = await api('/api/schema');
        if (!res.ok) {
            block.innerHTML = '<div class="loader">Не удалось загрузить схему: '
                + esc(res.data.message || '') + '</div>';
            return;
        }
        const data = res.data;
        let html = '<div class="schema-tables">';

        html += '<div class="schema-table"><h4>users — учётные записи</h4><table><tbody>';
        data.users.forEach((u) => {
            html += '<tr><td class="col-name">' + esc(u.username) + '</td>' +
                '<td class="col-type">' + esc(u.role) + '</td>' +
                '<td class="col-note">id=' + esc(u.id) + '</td></tr>';
        });
        html += '</tbody></table></div>';

        html += '<div class="schema-table"><h4>secrets — учебные секреты</h4><table><tbody>';
        data.secrets.forEach((s) => {
            html += '<tr><td class="col-name">' + esc(s.owner) + '</td>' +
                '<td class="col-type">' + esc(s.preview) + '</td>' +
                '<td class="col-note">id=' + esc(s.id) + '</td></tr>';
        });
        html += '</tbody></table></div>';

        html += '</div>';

        html += '<div class="out-block"><h5>Структура, которую можно раскрыть инъекцией</h5>';
        data.tables.forEach((t) => {
            html += '<p><code>' + esc(t.name) + '</code> — ' + esc(t.sql) + '</p>';
        });
        html += '</div>';

        html += '<div class="out-block"><h5>Важно</h5><ul class="list">';
        (data.notes || []).forEach((n) => { html += '<li>' + esc(n) + '</li>'; });
        html += '</ul></div>';

        block.innerHTML = html;
    }

    /* --- Каталог техник ---------------------------------------------------------- */
    async function loadPayloads() {
        const grid = el('payloadGrid');
        if (!grid) return;
        const res = await api('/api/payloads');
        if (!res.ok) {
            grid.innerHTML = '<div class="loader">Каталог недоступен.</div>';
            return;
        }
        Lab.payloads = res.data.payloads || [];
        grid.innerHTML = Lab.payloads.map((p) =>
            '<button type="button" class="payload-card" data-payload-id="' + esc(p.id) + '">' +
            '<div class="pc-head">' +
            '<span class="pc-tech">' + esc(p.technique) + '</span>' +
            '<span class="badge badge-' + esc(p.severity === 'critical' ? 'vuln' : 'warn') + '">'
            + esc(p.severity) + '</span>' +
            '</div>' +
            '<h4>' + esc(p.title) + '</h4>' +
            '<div class="pc-code">' + esc(p.username) + '</div>' +
            '<p>' + esc(p.summary) + '</p>' +
            '<div class="pc-why"><b>Что увидим:</b> ' + esc(p.why) + '</div>' +
            '<div class="pc-why"><b>Ожидаемый исход (уязвимый):</b> ' + esc(p.expected_description) + '</div>' +
            '</button>'
        ).join('');

        $$('.payload-card', grid).forEach((card) => {
            card.addEventListener('click', () => {
                const item = Lab.payloads.find((p) => p.id === card.dataset.payloadId);
                if (!item) return;
                fillCompare(item.username, item.password);
                logConsole('info', 'выбрана техника: ' + item.id);
                const target = el('compare');
                if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        });
    }

    function payloadById(id) {
        return Lab.payloads.find((p) => p.id === id) || null;
    }

    function fillCompare(username, password) {
        const u = el('cmpUser');
        const p = el('cmpPass');
        if (u) u.value = username;
        if (p) p.value = password;
    }

    /* --- Сравнение двух режимов --------------------------------------------------- */
    async function runCompare(username, password) {
        const box = el('compareResult');
        if (!box) return;
        box.innerHTML = '<div class="loader">Выполняю оба запроса…</div>';

        const vuln = await api('/api/vulnerable/login', {
            method: 'POST',
            body: { username: username, password: password },
        });
        const sec = await api('/api/secure/login', {
            method: 'POST',
            body: { username: username, password: password },
        });

        const v = vuln.data || {};
        const s = sec.data || {};

        const cell = (value, cls) => '<td class="' + (cls || '') + '">' + value + '</td>';
        const yesNo = (flag) => flag
            ? '<span class="result-yes">ДА</span>'
            : '<span class="result-no">нет</span>';

        let html = '<table class="compare-table"><thead><tr>' +
            '<th>Параметр</th><th>Небезопасный режим</th><th>Защищённый режим</th>' +
            '</tr></thead><tbody>';

        html += '<tr><td>Результат</td>' +
            cell(yesNo(v.success), 'cell-vuln') +
            cell(yesNo(s.success), 'cell-sec') + '</tr>';

        html += '<tr><td>Строк получено</td>' +
            cell(esc(v.row_count), 'cell-vuln') +
            cell(esc(s.row_count), 'cell-sec') + '</tr>';

        html += '<tr><td>Обход авторизации</td>' +
            cell(v.bypassed ? '<span class="result-yes">подтверждён</span>' : '<span class="result-no">нет</span>', 'cell-vuln') +
            cell('<span class="result-no">невозможен</span>', 'cell-sec') + '</tr>';

        html += '<tr><td>Сигналов в разборе</td>' +
            cell(esc((v.analysis || {}).signal_count), 'cell-vuln') +
            cell(esc((s.analysis || {}).signal_count), 'cell-sec') + '</tr>';

        html += '<tr><td>Сформированный запрос</td>' +
            cell('<code>' + esc(shortSql((v.sql || {}).raw, 220)) + '</code>', 'cell-vuln') +
            cell('<code>' + esc(shortSql((s.sql || {}).raw, 220)) + '</code>', 'cell-sec') + '</tr>';

        html += '<tr><td>Вывод</td>' +
            cell(esc(v.message || ''), 'cell-vuln') +
            cell(esc(s.message || ''), 'cell-sec') + '</tr>';

        html += '</tbody></table>';

        html += '<div class="grid-2" style="margin-top:16px">';
        html += '<div><h4 class="section-title" style="font-size:16px">Небезопасный режим — строки</h4>' +
            '<div class="rows-wrap" id="cmpVulnRows"></div></div>';
        html += '<div><h4 class="section-title" style="font-size:16px">Защищённый режим — строки</h4>' +
            '<div class="rows-wrap" id="cmpSecRows"></div></div>';
        html += '</div>';

        box.innerHTML = html;
        renderRows(el('cmpVulnRows'), v.rows || []);
        renderRows(el('cmpSecRows'), s.rows || []);

        record({
            kind: 'compare',
            title: 'Сравнение режимов',
            mode: 'vulnerable + secure',
            input: username + ' / ' + password,
            result: 'уязвимый: ' + (v.success ? 'вход выполнен' : 'отказ') +
                ' · защищённый: ' + (s.success ? 'вход выполнен' : 'отказ'),
            sql: (v.sql || {}).raw || '',
            detail: 'Сравнение отправляет один и тот же ввод в оба обработчика.',
        });
    }

    function initCompare() {
        const form = el('compareForm');
        if (form) {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                const username = el('cmpUser').value;
                const password = el('cmpPass').value;
                runCompare(username, password);
            });
        }
        const payloadBtn = el('cmpPayload');
        if (payloadBtn) {
            payloadBtn.addEventListener('click', () => {
                const item = payloadById('classic_or_bypass');
                if (item) fillCompare(item.username, item.password);
            });
        }
        const resetBtn = el('cmpReset');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                fillCompare('', '');
                const box = el('compareResult');
                if (box) box.innerHTML = '';
            });
        }
    }

    /* --- Подробные демонстрации ---------------------------------------------------- */
    async function runDemo(mode, username, password) {
        const prefix = mode === 'secure' ? 'sec' : 'vuln';
        const sqlBox = el(prefix + 'Sql');
        const verdictBox = el(prefix + 'Verdict');
        const signalsBox = el(prefix + 'Signals');
        const rowsBox = el(prefix + 'RowsWrap');

        const res = await api('/api/' + mode + '/login', {
            method: 'POST',
            body: { username: username, password: password },
        });
        const data = res.data || {};

        renderSql(sqlBox, data.sql);
        renderVerdict(verdictBox, data);
        renderSignals(signalsBox, data.analysis);
        renderRows(rowsBox, data.rows || []);

        record({
            kind: 'demo',
            title: mode === 'secure' ? 'Защищённый вход' : 'Небезопасный вход',
            mode: mode,
            input: username + ' / ' + password,
            result: data.message || '',
            sql: (data.sql || {}).raw || '',
            detail: (data.analysis || {}).summary || '',
        });
        return data;
    }

    function initDemos() {
        const vulnForm = el('vulnForm');
        if (vulnForm) {
            vulnForm.addEventListener('submit', (event) => {
                event.preventDefault();
                runDemo('vulnerable', vulnForm.username.value, vulnForm.password.value);
            });
        }
        const secForm = el('secForm');
        if (secForm) {
            secForm.addEventListener('submit', (event) => {
                event.preventDefault();
                runDemo('secure', secForm.username.value, secForm.password.value);
            });
        }
        $$('[data-payload]').forEach((button) => {
            button.addEventListener('click', () => {
                const item = payloadById(button.dataset.payload);
                if (!item) return;
                const form = button.closest('form');
                if (form) {
                    form.username.value = item.username;
                    form.password.value = item.password;
                }
                logConsole('info', 'подставлен payload: ' + item.id);
            });
        });
    }

    /* --- Вкладки -------------------------------------------------------------------- */
    function initTabs() {
        $$('.tab').forEach((tab) => {
            tab.addEventListener('click', () => {
                const name = tab.dataset.tab;
                $$('.tab').forEach((t) => t.classList.toggle('is-active', t === tab));
                $$('.tab-panel').forEach((p) => {
                    p.classList.toggle('is-active', p.dataset.panel === name);
                });
            });
        });
    }

    /* --- Кнопки «вставить payload» в формах техник ---------------------------------- */
    function initTechPrefill() {
        $$('.tech-form').forEach((form) => {
            const button = form.querySelector('[data-payload]');
            if (!button) return;
            button.addEventListener('click', () => {
                const item = payloadById(button.dataset.payload);
                if (!item) return;
                form.username.value = item.username;
                form.password.value = item.password;
            });
        });
    }

    /* --- Инициализация ---------------------------------------------------------------- */
    function init() {
        initTheme();
        initNavSpy();
        initTabs();
        initCompare();
        initDemos();
        initTechPrefill();

        const consoleClear = el('consoleClear');
        if (consoleClear) {
            consoleClear.addEventListener('click', () => {
                const box = el('consoleBox');
                if (box) box.innerHTML = '';
            });
        }

        Object.keys(Lab.modules).forEach((key) => {
            const mod = Lab.modules[key];
            if (mod && typeof mod.init === 'function') {
                try {
                    mod.init();
                } catch (err) {
                    logConsole('err', 'модуль ' + key + ': ' + err.message);
                }
            }
        });

        loadSchema();
        loadPayloads();
        logConsole('info', 'интерфейс загружен');
    }

    // Публичный интерфейс модулей.
    Lab.api = api;
    Lab.log = logConsole;
    Lab.esc = esc;
    Lab.el = el;
    Lab.$$ = $$;
    Lab.renderSql = renderSql;
    Lab.renderVerdict = renderVerdict;
    Lab.renderSignals = renderSignals;
    Lab.renderRows = renderRows;
    Lab.record = record;
    Lab.payloadById = payloadById;
    Lab.fillCompare = fillCompare;
    Lab.runDemo = runDemo;
    Lab.nowStamp = nowStamp;
    Lab.shortSql = shortSql;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
