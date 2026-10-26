/* ==========================================================================
   Модуль «Анализатор ввода».
   Статический разбор пользовательского ввода: какие конструкции найдены,
   как выглядел бы уязвимый запрос. Обращение к базе при этом не происходит.
   ========================================================================== */

(function () {
    'use strict';

    window.LabModules = window.LabModules || {};

    const OUT = '[data-out="analyze"]';

    function out() {
        return document.querySelector(OUT);
    }

    async function analyze(username, password) {
        const Lab = window.Lab;
        const box = out();
        if (!box) return;

        box.innerHTML = '<div class="loader">Разбираю ввод…</div>';

        const res = await Lab.api('/api/analyze', {
            method: 'POST',
            body: { username: username, password: password },
        });
        const data = res.data || {};
        const analysis = data.analysis || {};
        const preview = data.sql_preview || {};

        let html = '';

        html += '<div class="out-block"><h5>Итог разбора</h5>';
        html += '<p><b>Вердикт:</b> ' + Lab.esc(analysis.verdict || 'info') + '</p>';
        html += '<p>' + Lab.esc(analysis.summary || '') + '</p>';
        html += '<div class="out-metrics">' +
            '<div><span>сигналов: </span><b>' + Lab.esc(analysis.signal_count || 0) + '</b></div>' +
            '<div><span>макс. серьёзность: </span><b>' + Lab.esc(analysis.max_severity || 'none') + '</b></div>' +
            '</div></div>';

        html += '<div class="out-block"><h5>Как выглядел бы уязвимый запрос</h5>' +
            '<div class="sql-view"><span class="s-code">' + Lab.esc(preview.raw || '') + '</span></div>' +
            '<p style="margin-top:10px">' + Lab.esc(preview.note || '') + '</p></div>';

        box.innerHTML = html;

        const signalsBox = document.createElement('div');
        signalsBox.className = 'signals';
        box.appendChild(signalsBox);
        Lab.renderSignals(signalsBox, analysis);

        Lab.record({
            kind: 'analysis',
            title: 'Статический разбор ввода',
            mode: 'analyzer',
            input: username + ' / ' + password,
            result: 'сигналов: ' + (analysis.signal_count || 0),
            sql: preview.raw || '',
            detail: analysis.summary || '',
        });
    }

    function init() {
        const form = document.getElementById('analyzeForm');
        if (form) {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                analyze(
                    document.getElementById('anaUser').value,
                    document.getElementById('anaPass').value
                );
            });
        }

        const clear = document.getElementById('anaClear');
        if (clear) {
            clear.addEventListener('click', () => {
                document.getElementById('anaUser').value = '';
                document.getElementById('anaPass').value = '';
                const box = out();
                if (box) box.innerHTML = '';
            });
        }
    }

    window.LabModules.analyzer = { init: init, analyze: analyze };
})();
