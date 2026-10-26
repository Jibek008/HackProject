/* ==========================================================================
   Модуль «Проверь, что понял».
   Шесть вопросов по материалу лаборатории. Ответ проверяется сразу,
   результат попадает в журнал экспериментов.
   ========================================================================== */

(function () {
    'use strict';

    window.LabModules = window.LabModules || {};

    const QUESTIONS = [
        {
            q: 'Что происходит, если в уязвимом режиме ввести student\' OR \'1\'=\'1\' -- ?',
            options: [
                'Приложение отклонит ввод как некорректный',
                'Авторизация обходится: условие всегда истинно, а комментарий отсекает проверку пароля',
                'Пароль будет подменён на значение из базы',
                'Запрос вернёт ошибку синтаксиса',
            ],
            correct: 1,
            why: 'Кавычка закрывает строковый литерал, OR \'1\'=\'1\' делает предикат ' +
                'истинным всегда, а -- отсекает оставшуюся часть запроса вместе с ' +
                'проверкой пароля.',
        },
        {
            q: 'Почему параметризованный запрос устойчив к тому же вводу?',
            options: [
                'Он экранирует все опасные символы',
                'Он удаляет из ввода SQL-конструкции',
                'Значение передаётся отдельно от SQL-кода и потому остаётся данными',
                'Он шифрует ввод перед отправкой',
            ],
            correct: 2,
            why: 'СУБД сначала разбирает шаблон запроса, а потом подставляет ' +
                'значения. Они не могут изменить структуру запроса — это и есть ' +
                'разделение кода и данных.',
        },
        {
            q: 'Что произойдёт, если условие 1=1 передать защищённому обработчику как параметр?',
            options: [
                'Условие выполнится и вернёт истину',
                'Условие станет частью WHERE и вернёт истину',
                'Условие будет искаться как обычная строка и даст ложь',
                'Приложение вернёт ошибку',
            ],
            correct: 2,
            why: 'Параметр не может стать предикатом: он сравнивается со ' +
                'значением поля как строка. Поэтому канал blind закрыт.',
        },
        {
            q: 'Как называется техника, при которой атакующий узнаёт символ за символом по ответу true/false?',
            options: [
                'UNION-based',
                'Error-based',
                'Boolean blind',
                'Time-based',
            ],
            correct: 2,
            why: 'Boolean blind использует один бит информации на запрос. ' +
                'Собрав достаточно битов, атакующий восстанавливает значение целиком.',
        },
        {
            q: 'Зачем в конце инъекции ставят комментарий?',
            options: [
                'Чтобы замаскировать длину ввода',
                'Чтобы отсечь остаток запроса — например, проверку пароля',
                'Чтобы ускорить выполнение',
                'Чтобы закрыть соединение с базой',
            ],
            correct: 1,
            why: 'Комментарий заставляет СУБД игнорировать всё, что идёт после ' +
                'него. В SQLite поддерживаются -- и /* */, а # — это синтаксис MySQL.',
        },
        {
            q: 'В лаборатории пароли хранятся в открытом виде. Почему?',
            options: [
                'Чтобы показать, что так делают в реальных системах',
                'Чтобы упростить отладку демонстрации',
                'Чтобы изолированно показать принцип инъекции, не отвлекаясь на хэширование',
                'Чтобы база открывалась быстрее',
            ],
            correct: 2,
            why: 'В настоящих системах пароли хранят только в виде стойких ' +
                'хэшей (bcrypt, argon2). Открытый вид — исключительно для ' +
                'наглядности лаборатории.',
        },
    ];

    let answered = {};

    function render() {
        const block = document.getElementById('quizBlock');
        if (!block) return;

        block.innerHTML = QUESTIONS.map((item, index) =>
            '<div class="quiz-item" data-index="' + index + '">' +
            '<h4>' + Lab.esc(item.q) + '</h4>' +
            '<div class="quiz-options">' +
            item.options.map((opt, optIndex) =>
                '<label class="quiz-opt">' +
                '<input type="radio" name="q' + index + '" value="' + optIndex + '">' +
                '<span>' + Lab.esc(opt) + '</span></label>').join('') +
            '</div>' +
            '<div class="form-actions">' +
            '<button type="button" class="btn btn-primary" data-check="' + index + '">Проверить</button>' +
            '</div>' +
            '<div class="quiz-feedback"><b></b> <span></span></div>' +
            '</div>'
        ).join('');

        Lab.$$('[data-check]', block).forEach((button) => {
            button.addEventListener('click', () => check(Number(button.dataset.check)));
        });
    }

    function check(index) {
        const item = QUESTIONS[index];
        const block = document.getElementById('quizBlock');
        const card = block.querySelector('.quiz-item[data-index="' + index + '"]');
        const chosen = card.querySelector('input[type="radio"]:checked');

        if (!chosen) {
            Lab.log('warn', 'квиз: не выбран ответ');
            return;
        }

        const value = Number(chosen.value);
        const ok = value === item.correct;
        const firstTry = !(index in answered);
        answered[index] = firstTry ? (ok ? 'correct' : 'wrong') : answered[index];

        card.classList.remove('is-correct', 'is-wrong');
        card.classList.add(ok ? 'is-correct' : 'is-wrong');

        const feedback = card.querySelector('.quiz-feedback');
        feedback.innerHTML = '<b>' + (ok ? 'Верно' : 'Неверно') + '</b> <span>'
            + Lab.esc(item.why) + '</span>';

        updateScore();
        Lab.record({
            kind: 'quiz',
            title: 'Вопрос квиза #' + (index + 1),
            mode: 'quiz',
            input: item.q,
            result: ok ? 'верно' : 'неверно',
            detail: item.why,
        });
    }

    function updateScore() {
        const scoreEl = document.getElementById('quizScore');
        if (!scoreEl) return;
        const total = QUESTIONS.length;
        const correct = Object.keys(answered).filter((k) => answered[k] === 'correct').length;
        scoreEl.textContent = 'Пройдено: ' + correct + ' из ' + total;
    }

    function init() {
        render();
        updateScore();

        const reset = document.getElementById('quizReset');
        if (reset) {
            reset.addEventListener('click', () => {
                answered = {};
                render();
                updateScore();
                Lab.log('info', 'квиз сброшен');
            });
        }
    }

    window.LabModules.quiz = { init: init, questions: QUESTIONS };
})();
