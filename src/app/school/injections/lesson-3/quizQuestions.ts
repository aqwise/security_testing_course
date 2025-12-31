export const quizQuestions = [
    {
        question: "Что такое HTML Injection?",
        answers: [
            "Уязвимость, позволяющая внедрять произвольный HTML-код в веб-страницу",
            "Внедрение SQL-кода",
            "Внедрение CSS-стилей",
            "Внедрение команд сервера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Чем HTML Injection отличается от XSS?",
        answers: [
            "HTML Injection не подразумевает выполнение JavaScript (обычно), только изменение структуры/контента, хотя XSS часто использует HTML инъекцию как вектор",
            "Ничем",
            "HTML Injection опаснее",
            "XSS это только для CSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой основной риск HTML Injection?",
        answers: [
            "Фишинг (подмена форм входа), дефейс, социальная инженерия",
            "RCE",
            "DDoS",
            "SQLi"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Dangling Markup Injection'?",
        answers: [
            "Техника кражи данных (например, CSRF токенов) путем внедрения незакрытого тега (например, <img src='...), который 'поглощает' часть страницы до следующей кавычки",
            "Инъекция висячих указателей",
            "Удаление разметки",
            "Срочная разметка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой тег наиболее часто используется для фишинга в HTML Injection?",
        answers: [
            "<form> (создание поддельной формы входа)",
            "<div>",
            "<span>",
            "<br>"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Если фильтр вырезает <script>, это защищает от HTML Injection?",
        answers: [
            "Нет, можно внедрить другие теги (img, a, h1, form), которые меняют контент, даже без JS",
            "Да, полностью",
            "Только в Firefox",
            "Только в Chrome"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Content Spoofing'?",
        answers: [
            "Подмена содержимого страницы (текста, картинок) для обмана пользователя, часто через HTML Injection",
            "Спуфинг IP",
            "Спуфинг MAC",
            "Подмена DNS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать HTML Injection для кражи паролей?",
        answers: [
            "Да, перекрыв оригинальную форму входа своей (через CSS/HTML) и отправляя данные на сервер атакующего",
            "Нет",
            "Только если пароль '12345'",
            "Только в IE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В каком контексте чаще всего встречается HTML Injection?",
        answers: [
            "В отображении пользовательского ввода (комментарии, профили, сообщения) без кодирования спецсимволов HTML",
            "В базе данных",
            "В логах сервера",
            "В DNS записях"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие символы критичны для HTML Injection?",
        answers: [
            "<, >, \", ', &",
            "Только .",
            "Только ,",
            "Только ;"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от HTML Injection?",
        answers: [
            "HTML-кодирование (HTML Entity Encoding) всех пользовательских данных перед выводом",
            "Шифрование данных",
            "Использование HTTPS",
            "Запрет использования интернета"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает функция `htmlspecialchars()` в PHP?",
        answers: [
            "Преобразует спецсимволы (<, >, &, \") в HTML-сущности (&lt;, &gt; и т.д.), предотвращая интерпретацию как тегов",
            "Удаляет теги",
            "Выполняет HTML",
            "Красит HTML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Attribute Injection'?",
        answers: [
            "Внедрение в значение атрибута (например, class='...'), позволяющее добавить свои события (onmouseover) или стили, если кавычка не экранирована",
            "Внедрение атрибутов бога",
            "Инъекция в URL",
            "Инъекция в Cookie"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли HTML Injection работать в Email?",
        answers: [
            "Да, HTML-письма могут исполнять внедренный HTML (и иногда JS, хотя почтовые клиенты стараются это блокировать)",
            "Нет, Email это текст",
            "Только в Outlook",
            "Только в Gmail"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как называлась старая атака, похожая на HTMLi, но использующая <frame>?",
        answers: [
            "Frame Injection / Frame Phishing",
            "Frame Rate",
            "Frame Buffer",
            "Frame Work"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему `strip_tags()` в PHP может быть опасен?",
        answers: [
            "Он может удалять теги некорректно или оставлять содержимое тегов (например, скрипты внутри), или быть обойдён специально сформированным HTML",
            "Он удаляет весь текст",
            "Он удаляет базу",
            "Он безопасен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой HTTP заголовок помогает смягчить последствия HTML Injection (ограничивая источники контента)?",
        answers: [
            "Content-Security-Policy (CSP)",
            "X-Frame-Options",
            "Set-Cookie",
            "Host"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что будет, если внедрить `<meta http-equiv='refresh' content='0;url=http://evil.com'>`?",
        answers: [
            "Браузер перенаправит пользователя на evil.com (Open Redirect через HTMLi)",
            "Ничего",
            "Ошибка 404",
            "Скачается файл"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать `<iframe>` при HTML Injection?",
        answers: [
            "Да, для загрузки внешнего контента (например, фишинговой страницы) внутри легитимной",
            "Нет, iframe запрещен везде",
            "Только видео",
            "Только аудио"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind HTML Injection'?",
        answers: [
            "Когда результат внедрения не виден атакующему сразу (например, в логах админа или письме в техподдержку)",
            "Невидимый текст",
            "Инъекция для слепых",
            "Слуховая инъекция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент можно использовать для обнаружения HTML Injection?",
        answers: [
            "Burp Suite (Scanner, Repeater), OWASP ZAP",
            "Калькулятор",
            "Блокнот",
            "Paint"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли Markdown уязвимым к HTML Injection?",
        answers: [
            "Да, если парсер Markdown разрешает 'сырой' HTML (raw HTML) и не санитайзит его",
            "Нет, Markdown безопасен",
            "Только жирный текст",
            "Только курсив"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как безопасно разрешить пользователю форматировать текст?",
        answers: [
            "Использовать безопасный подмножество (например, BBCode) или санитайзеры HTML (DOMPurify) с белым списком тегов",
            "Разрешить всё",
            "Запретить всё",
            "Использовать eval()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `target='_blank'` уязвимым в ссылках (Tabnabbing)?",
        answers: [
            "Если нет `rel='noopener noreferrer'`, новая вкладка может получить доступ к `window.opener` и перенаправить родительскую страницу на фишинг",
            "Ничего",
            "Открывает 2 вкладки",
            "Закрывает браузер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли CSS быть использован для эксфильтрации данных при HTML Injection?",
        answers: [
            "Да, через CSS Injection (например, селекторы атрибутов и background-image запросы) - 'CSS Exfiltration'",
            "Нет, CSS только для красоты",
            "Только в IE6",
            "Только цвет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Clickjacking'?",
        answers: [
            "Атака, использующая iframe и прозрачные слои для перехвата кликов. Не совсем HTMLi, но часто связана с внедрением UI",
            "Кража кликов мышкой",
            "Быстрый клик",
            "Клик по рекламе"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой тег позволяет встраивать SVG графику?",
        answers: [
            "<svg>",
            "<canvas>",
            "<paint>",
            "<draw>"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выполнить JS внутри <svg>?",
        answers: [
            "Да, SVG поддерживает <script> и события (onload, onclick)",
            "Нет",
            "Только если картинка черно-белая",
            "Только через CSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Polyglot' в контексте HTML/XSS?",
        answers: [
            "Строка, которая является валидной в разных контекстах (HTML, JS атрибут, URL) и срабатывает как инъекция везде",
            "Переводчик",
            "Много языков",
            "Словарь"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить поле на HTML Injection?",
        answers: [
            "Ввести <h1>Test</h1> (или подобное) и посмотреть, отрендерится ли заголовок или отобразятся теги текстом",
            "Ввести 123",
            "Ввести SQL",
            "Ввести пробел"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Self-XSS' (или Self-HTML-Injection)?",
        answers: [
            "Инъекция, которая срабатывает только у самого атакующего (например, ввод в консоль или локальное поле). Часто используется для социальной инженерии ('вставь этот код в консоль')",
            "XSS против себя",
            "Автоматический XSS",
            "XSS без браузера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли HTML Injection в PDF генераторе быть опасной?",
        answers: [
            "Да, часто приводит к SSRF (через <img> или css) или чтению локальных файлов (LFI) при генерации PDF на сервере",
            "Нет, PDF это картинка",
            "Только текст",
            "Только шрифт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой тег `<base>` делает?",
        answers: [
            "Задает базовый URL для всех относительных ссылок на странице. Инъекция `<base href='http://evil.com'>` может перенаправить все скрипты и картинки на сервер атакующего",
            "Делает шрифт жирным",
            "Создает базу данных",
            "Ничего"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать `<object>` или `<embed>` для HTML Injection?",
        answers: [
            "Да, они могут загружать Flash, PDF или другие плагины, потенциально выполняя скрипты",
            "Нет, они устарели",
            "Только для аудио",
            "Только для видео"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `<math>` тег?",
        answers: [
            "MathML тег, который в некоторых браузерах может использоваться для обхода фильтров XSS",
            "Математика",
            "Калькулятор",
            "Числа"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как работает атака через `<textarea>`?",
        answers: [
            "Если внедрить `</textarea><script>...`, можно выйти из textarea и выполнить код",
            "Писать много текста",
            "Переполнение буфера",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Mutation XSS' (mXSS)?",
        answers: [
            "XSS, который возникает после того, как браузер (или библиотека типа innerHTML) 'нормализует' или изменяет 'сломанный' HTML, превращая его в рабочий вектор",
            "XSS мутантов",
            "Генетический XSS",
            "XSS Людей Икс"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Помогает ли WAF против всех HTML Injections?",
        answers: [
            "Нет, WAF можно обойти, а логика приложения может требовать HTML (например, CMS)",
            "Да, всегда",
            "Только дорогой WAF",
            "Только облачный"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `<noscript>`?",
        answers: [
            "Тег, содержимое которого отображается, если JS отключен. Вектор для фишинга пользователей без JS (редко)",
            "Нет скриптов",
            "Скрипт запуска",
            "Комментарий"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли через HTML Injection украсть CSRF токен?",
        answers: [
            "Да, с помощью Dangling Markup (незакрытые теги, поглощающие контент до следующей кавычки, включая токен)",
            "Нет",
            "Только если токен в URL",
            "Только в Cookie"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой атрибут в `<img>` выполняет JS при ошибке загрузки?",
        answers: [
            " onerror",
            " onload",
            " onclick",
            " onfail"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `javascript:` псевдо-протокол?",
        answers: [
            "Позволяет выполнять JS в `href` или `src` атрибутах (например, <a href='javascript:alert(1)'>)",
            "Протокол Java",
            "Протокол JSON",
            "Протокол JQuery"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой кодировкой можно попытаться обойти фильтры?",
        answers: [
            "URL encoding, HTML Entities, Hex encoding, Unicode escapes",
            "MP3",
            "AVI",
            "ZIP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Request smuggling'?",
        answers: [
            "Атака на рассинхронизацию frontend и backend серверов при обработке HTTP запросов. Не HTMLi, но может вести к XSS/HTMLi",
            "Контрабанда запросов",
            "Быстрые запросы",
            "Сжатие запросов"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить HTML в заголовки ответа?",
        answers: [
            "Нет, HTML в теле. В заголовках это HTTP Response Splitting (если удастся внедрить CRLF и начать тело раньше)",
            "Да, всегда",
            "Только в Server",
            "Только в Date"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить Cookie от XSS/HTMLi (кражи)?",
        answers: [
            "Флаг HttpOnly (запрещает доступ к куке через JS) и Secure (только HTTPS)",
            "Пароль на куку",
            "Шифрование куки",
            "Не использовать куки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что если приложение просто удаляет слово `<script>`?",
        answers: [
            "Можно использовать `<scr<script>ipt>` (если удаляется один раз) или другие теги (img, body)",
            "Защита надежна",
            "Ничего нельзя сделать",
            "Можно плакать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `DOMPurify`?",
        answers: [
            "Популярная библиотека для санитайзинга HTML в браузере (защита от DOM XSS/HTMLi)",
            "Очиститель дома",
            "Вирус",
            "Игра"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить HTML через имя файла при загрузке?",
        answers: [
            "Да, если имя файла отображается на странице без экранирования",
            "Нет",
            "Только в Windows",
            "Только в Linux"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Alt Text Injection'?",
        answers: [
            "Внедрение в атрибут alt картинки",
            "Альтернативный текст",
            "Клавиша Alt",
            "Другой текст"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить HTMLi в параметре URL?",
        answers: [
            "Изменить значение параметра на HTML теги и посмотреть исходный код ответа",
            "Перезагрузить страницу",
            "Нажать F5",
            "Очистить кэш"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Влияет ли doctype на HTML Injection?",
        answers: [
            "Может влиять на Quirks Mode, но инъекция работает независимо",
            "Да, запрещает инъекцию",
            "Нет",
            "Только HTML5 безопасен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Meta Tag Injection'?",
        answers: [
            "Внедрение или манипуляция <meta> тегами (CSP, refresh, referrer)",
            "Мета-вселенная",
            "Мета-данные",
            "Мета-анализ"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли HTML Injection вызвать скачивание файла?",
        answers: [
            "Да, через `<meta http-equiv='refresh' ...>` или iframe на скачивание",
            "Нет",
            "Только вирус",
            "Только музыку"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делать, если `alert()` заблокирован?",
        answers: [
            "Использовать `confirm()`, `prompt()` или `print()` для Proof of Concept",
            "Сдаться",
            "Использовать `console.log()`",
            "Ничего"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить HTML в JSON ответ?",
        answers: [
            "Если JSON отображается как HTML (Content-Type: text/html) или вставляется в DOM через innerHTML - да",
            "Нет, JSON безопасен",
            "Только XML",
            "Только CSV"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Reverse Tabnabbing'?",
        answers: [
            "То же что Tabnabbing (атака через window.opener)",
            "Обратная табуляция",
            "Закрытие вкладки",
            "Открытие окна"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'RPO (Relative Path Overwrite)'?",
        answers: [
            "Атака, использующая относительные пути для загрузки CSS/JS, позволяющая внедрять стили или скрипты через HTML Injection",
            "Перезапись пути",
            "Относительный путь",
            "Робот"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как использовать RPO?",
        answers: [
            "Заставить браузер загрузить текущую страницу как CSS файл, внедрив туда CSS payload",
            "Удалить CSS",
            "Загрузить картинку",
            "Сменить путь"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли HTML Injection быть persistent (хранимой)?",
        answers: [
            "Да, Stored HTML Injection",
            "Нет, только Reflected",
            "Только в RAM",
            "Только в кэше"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В каких полях часто бывает HTML Injection?",
        answers: [
            "Комментарии, отзывы, био профиля, сообщения форума",
            "Пароль (скрыт)",
            "ID сессии",
            "Timestamp"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Sandbox' атрибут в iframe?",
        answers: [
            "Ограничивает возможности контента в iframe (запрещает скрипты, формы, same-origin), хорошая защита при вставке стороннего контента",
            "Песочница для игр",
            "Режим отладки",
            "Инструмент разработчика"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли обойти Sandbox?",
        answers: [
            "Если разрешены 'allow-scripts' и 'allow-same-origin' одновременно - защита ослаблена, но прямой обход зависит от конфигурации",
            "Да, всегда",
            "Нет, никогда",
            "Легко"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Для чего нужен `X-Content-Type-Options: nosniff`?",
        answers: [
            "Запрещает браузеру угадывать MIME-тип. Защищает от атак, когда HTML загружается как картинка или скрипт",
            "Запрещает сниффинг",
            "Запрещает скачивание",
            "Ускоряет загрузку"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SSTI' и как она связана с HTMLi?",
        answers: [
            "Server-Side Template Injection. Может приводить к HTML Injection и RCE, так как шаблонизатор рендерит ввод",
            "Стиль",
            "Шаблон",
            "Инъекция сервера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить SSTI?",
        answers: [
            "Ввести `{{7*7}}` или `${7*7}`. Если отобразится 49 — это SSTI",
            "Ввести HTML",
            "Ввести SQL",
            "Ввести текст"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Client-Side Template Injection' (CSTI)?",
        answers: [
            "Инъекция в шаблоны на клиенте (Angular, Vue, React). Может вести к XSS",
            "То же что SSTI",
            "Инъекция клиента",
            "Инъекция шаблона"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "AngularJS (старый) уязвим к CSTI?",
        answers: [
            "Да, через {{...}} выражения в старых версиях можно исполнять JS (sandbox escape)",
            "Нет",
            "Только новые версии",
            "Только React"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить React от XSS/HTMLi?",
        answers: [
            "React автоматически экранирует данные в JSX. Опасно только использование `dangerouslySetInnerHTML` или внедрение в `href` (javascript:)",
            "React не защищает",
            "Использовать jQuery",
            "Не использовать JSX"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `v-html` в Vue.js?",
        answers: [
            "Выводит 'сырой' HTML. Потенциально опасно (XSS/HTMLi), если данные от пользователя",
            "Выводит текст",
            "Экранирует HTML",
            "Удаляет HTML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая кодировка используется в URL?",
        answers: [
            "Percent-encoding (%20, %3C...)",
            "Base64",
            "Hex",
            "Binary"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Double Encoding'?",
        answers: [
            "Двойное кодирование (например %253C для <). Используется для обхода WAF, который декодирует только один раз",
            "Двойная защита",
            "Двойной клик",
            "Ошибка кодировки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Null Byte Injection' (%00)?",
        answers: [
            "Вставка нулевого байта. В старых системах (C-based) обрывает строку. Может помочь обойти фильтры расширений файлов",
            "Нулевая инъекция",
            "Пустая инъекция",
            "Байт код"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем опасность внедрения `<link rel='stylesheet'>`?",
        answers: [
            "Загрузка вредоносного CSS, который может менять вид страницы или эксфильтрировать данные",
            "Улучшение дизайна",
            "Ускорение сайта",
            "Нет опасности"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Canonical' тег?",
        answers: [
            "<link rel='canonical'>. Указывает поисковикам основную версию страницы. Инъекция может испортить SEO",
            "Каноническая инъекция",
            "Церковный тег",
            "Главный тег"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли инжектировать в комментарии HTML `<!-- -->`?",
        answers: [
            "Да, если удастся закрыть комментарий `-->` и начать свой HTML",
            "Нет, комментарии игнорируются",
            "Только в XML",
            "Только в JS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'HPP' (HTTP Parameter Pollution) в контексте HTMLi?",
        answers: [
            "Передача нескольких параметров с одним именем. Может запутать WAF или приложение и пропустить инъекцию",
            "Загрязнение HTML",
            "Протокол параметров",
            "High Performance PHP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить, фильтрует ли приложение кавычки?",
        answers: [
            "Ввести `'` и `\"` и посмотреть исходный код (превратились ли они в &apos; / &quot;)",
            "Ввести текст",
            "Нажать Enter",
            "Спросить админа"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что значит 'Sink' в контексте DOM XSS/HTMLi?",
        answers: [
            "Функция или объект DOM (точка исполнения), куда попадают данные и где происходит инъекция (например, innerHTML)",
            "Раковина",
            "Точка входа (Source)",
            "Корабль"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что значит 'Source' в контексте DOM XSS/HTMLi?",
        answers: [
            "Источник данных (например, location.search, cookies), откуда берутся небезопасные данные",
            "Исходный код",
            "Ресурс",
            "Соус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `innerText` безопасным?",
        answers: [
            "Да, он интерпретирует содержимое как текст, а не HTML. (В отличие от innerHTML)",
            "Нет",
            "Только в IE",
            "Только в Chrome"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `textContent` безопасным?",
        answers: [
            "Да, аналогично innerText, вставляет только текст",
            "Нет",
            "Иногда",
            "Зависит от браузера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'MIME Sniffing'?",
        answers: [
            "Попытка браузера определить тип файла по содержимому (ignoring Content-Type). Опасно для HTMLi в загрузках",
            "Нюханье трафика",
            "Тип файла",
            "MIME код"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как предотвратить фишинг через `window.opener`?",
        answers: [
            "Добавлять `rel='noopener noreferrer'` ко всем ссылкам с `target='_blank'`",
            "Не использовать ссылки",
            "Не открывать окна",
            "Использовать JS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Чем опасен тег `<applet>` (устаревший)?",
        answers: [
            "За запускал Java апплеты, полный доступ к системе (RCE) в старых браузерах",
            "Ничем",
            "Рисовал графики",
            "Играл музыку"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить HTML через `User-Agent`?",
        answers: [
            "Да, если User-Agent отображается в админке или логах без экранирования (Blind HTMLi/XSS)",
            "Нет",
            "Только в мобильных",
            "Только в десктопах"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'WAF'?",
        answers: [
            "Web Application Firewall. Фильтрует входящий трафик, блокируя известные атаки",
            "Web Application Form",
            "Wide Are Fuzzing",
            "Wireless Access File"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как WAF может заблокировать HTML Payload?",
        answers: [
            "По сигнатурам (наличие тегов <script>, on* событий, javascript:)",
            "По IP",
            "По времени",
            "По размеру"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Obfuscation'?",
        answers: [
            "Запутывание кода (payload) для обхода сигнатур WAF (смена регистра, лишние пробелы, кодирование)",
            "Сжатие",
            "Шифрование",
            "Удаление"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Работает ли HTML Injection в HTTPS?",
        answers: [
            "Да, HTTPS защищает транспорт, но не контент. Инъекция происходит на уровне приложения",
            "Нет",
            "Только часть",
            "Зашифрованно"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `document.cookie`?",
        answers: [
            "Свойство JS для доступа к кукам. Цель кражи при XSS/HTMLi",
            "Документ с едой",
            "Файл настроек",
            "Кэш"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем разница между `urlencode` и `htmlentities`?",
        answers: [
            "urlencode для URL параметров (%XX), htmlentities для HTML контента (&entity;)",
            "Нет разницы",
            "Одно для PHP, другое для JS",
            "Одно шифрует, другое нет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить HTML через QR код?",
        answers: [
            "Да, если сканер или приложение отображает содержимое QR кода как HTML",
            "Нет",
            "Только картинку",
            "Только ссылку"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли HTML Injection уязвимостью высокого риска?",
        answers: [
            "Зависит от контекста. Обычно Medium (фишинг), но может стать High с XSS",
            "Всегда Critical",
            "Всегда Low",
            "Info"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой статус код HTTP часто возвращается при Reflected инъекции?",
        answers: [
            "200 OK (страница вернулась с пейлоадом)",
            "500 Error",
            "404 Not Found",
            "403 Forbidden"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить HTML через имя Wi-Fi сети (SSID)?",
        answers: [
            "Да, известные атаки на дашборды роутеров или телефонов, отображающие SSID как HTML",
            "Нет",
            "Только WPA2",
            "Только 5GHz"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Payload'?",
        answers: [
            "Вредоносные данные (код), отправляемые для эксплуатации уязвимости",
            "Загрузка",
            "Платная нагрузка",
            "Вес"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент автоматизации есть в Kali Linux для XSS/HTMLi?",
        answers: [
            "XSSer",
            "HTMLer",
            "Injector",
            "PwnBuilder"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Нужна ли аутентификация для эксплуатации Reflected HTML Injection?",
        answers: [
            "Не обязательно, можно атаковать аутентифицированную жертву, отправив ей ссылку (CSRF-like вектор)",
            "Да, всегда",
            "Нет, жертва не нужна",
            "Нужен пароль"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое SOP (Same Origin Policy)?",
        answers: [
            "Политика браузера, запрещающая скриптам с одного источника (origin) читать данные с другого. XSS/HTMLi позволяет обойти это, выполняясь в контексте жертвы",
            "Суп",
            "Стандарт",
            "Протокол"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Origin'?",
        answers: [
            "Комбинация Протокола, Домена и Порта (например, https://example.com:443)",
            "Только домен",
            "Только IP",
            "Страна"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как CSP может блокировать inline скрипты?",
        answers: [
            "По умолчанию CSP запрещает inline скрипты и `eval()`, если не указано 'unsafe-inline' или nonce/hash",
            "Блокирует интернет",
            "Блокирует всё",
            "Не блокирует"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Nonce' в CSP?",
        answers: [
            "Случайное одноразовое число, которое должно совпадать в заголовке CSP и в атрибуте тега <script>, чтобы он выполнился",
            "Никто",
            "Ошибка",
            "Пароль"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли HTML Injection в странице 404 быть опасным?",
        answers: [
            "Да, если страница 404 отображает URL запроса без экранирования (Reflected HTMLi в странице ошибки)",
            "Нет, это ошибка",
            "Редко",
            "Только для админа"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Browser XSS Filter' (Auditor)?",
        answers: [
            "Встроенный в браузер (Chrome/IE старые версии) механизм блокировки подозрительных запросов. Сейчас в основном удален или не используется, полагаясь на CSP",
            "Антивирус",
            "Плагин",
            "Сайт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему Browser XSS Auditors были удалены?",
        answers: [
            "Они создавали новые уязвимости (XS-Leak) и ложные срабатывания, CSP считается лучшим решением",
            "Они замедляли работу",
            "Они были платными",
            "Никто не знает"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выполнить XSS через CSS `expression()`?",
        answers: [
            "Только в очень старых Internet Explorer (IE7 и ниже)",
            "Да, везде",
            "В Chrome",
            "В Firefox"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Relative URL'?",
        answers: [
            "URL без указания протокола и домена (например, /images/logo.png).",
            "Родственный URL",
            "Полный URL",
            "Быстрый URL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как использовать `<base>` для атаки на Relative URL?",
        answers: [
            "Изменяя `<base href>`, атакующий заставляет браузер загружать скрипты с его сервера вместо локальных путей",
            "Никак",
            "Меняя цвет",
            "Меняя шрифт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Script Gadgets'?",
        answers: [
            "Легитимный JS код на странице (библиотеки, фреймворки), который можно 'заставить' выполнить вредоносное действие через манипуляцию DOM (HTML Injection)",
            "Гаджеты для скриптов",
            "Телефоны",
            "Роботы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `innerHTML` единственным опасным sink?",
        answers: [
            "Нет, также outerHTML, document.write, document.writeln, и jQuery .html()",
            "Да",
            "Только innerText",
            "Только value"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делать при обнаружении HTML Injection?",
        answers: [
            "Сообщить разработчикам, продемонстрировать PoC (alert или html формат), предложить экранирование",
            "Ничего",
            "Взломать сайт",
            "Опубликовать везде"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой флаг куки защищает от передачи по HTTP?",
        answers: [
            "Secure",
            "HttpOnly",
            "SameSite",
            "Domain"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SameSite' атрибут куки?",
        answers: [
            "Защищает от CSRF, ограничивая передачу кук при кросс-сайтовых запросах (Strict, Lax, None)",
            "Тот же сайт",
            "Защита от XSS",
            "Защита от SQLi"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Помогает ли SameSite от XSS?",
        answers: [
            "Нет, если XSS выполняется на том же домене, он может читать/использовать куки независимо от SameSite",
            "Да, полностью",
            "Частично",
            "Только Lax"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что самое важное в демонстрации уязвимости (Reporting)?",
        answers: [
            "Четкие шаги воспроизведения, влияние (Impact) и рекомендации по исправлению",
            "Красивые картинки",
            "Сложные слова",
            "Объем текста"
        ],
        correctAnswerIndex: 0
    }
];
