export const quizQuestions = [
    {
        question: "Что такое Injection (Инъекция)?",
        answers: [
            "Уязвимость, возникающая когда недоверенные данные отправляются интерпретатору как часть команды или запроса",
            "Укол шприцом",
            "Лечение вирусов",
            "Вставка картинки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какое место занимают Инъекции в OWASP Top 10 (2021)?",
        answers: [
            "A03: Injection",
            "A01: Broken Access Control",
            "A07: Identification and Authentication Failures",
            "Больше не входят в топ"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой основной принцип защиты от Инъекций?",
        answers: [
            "Разделение данных и кода (команд)",
            "Использование фаервола",
            "Скрытие кода",
            "Использование антивируса"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Untrusted Data' (Недоверенные данные)?",
        answers: [
            "Любые данные, поступающие от пользователя или внешней системы (HTTP запросы, файлы, базы данных)",
            "Данные от хакеров",
            "Данные без подписи",
            "Данные errors"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Влияет ли Инъекция на Конфиденциальность (Confidentiality)?",
        answers: [
            "Да, можно прочитать данные, к которым нет доступа (например, dump базы данных)",
            "Нет",
            "Только на целостность",
            "Только на доступность"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Влияет ли Инъекция на Целостность (Integrity)?",
        answers: [
            "Да, можно изменить или удалить данные",
            "Нет",
            "Только на чтение",
            "Только на доступность"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Влияет ли Инъекция на Доступность (Availability)?",
        answers: [
            "Да, можно удалить данные или вызвать отказ в обслуживании (DoS)",
            "Нет",
            "Только на чтение",
            "Только на запись"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое LDAP Injection?",
        answers: [
            "Инъекция в запросы к службе каталогов LDAP (Lightweight Directory Access Protocol), позволяющая обойти аутентификацию или получить данные о пользователях",
            "Инъекция в лампу",
            "Инъекция в монитор",
            "Инъекция в принтер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое CRLF Injection?",
        answers: [
            "Вставка символов возврата каретки (CR) и перевода строки (LF) для манипуляции HTTP заголовками (HTTP Response Splitting) или логами",
            "Инъекция цвета",
            "Инъекция шрифта",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Input Validation'?",
        answers: [
            "Проверка входных данных на соответствие ожидаемому формату, типу, длине и диапазону значений",
            "Удаление данных",
            "Шифрование данных",
            "Сжатие данных"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что лучше: 'Allow list' (White list) или 'Block list' (Black list)?",
        answers: [
            "Allow list (Белый список) — разрешать только заведомо правильные значения. Черные списки часто можно обойти",
            "Block list — блокировать плохие слова",
            "Оба одинаковы",
            "Ничего не использовать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Output Encoding'?",
        answers: [
            "Преобразование данных перед выводом в определенный контекст (HTML, JS, CSS, URL), чтобы они воспринимались как данные, а не код",
            "Кодирование видео",
            "Архивация",
            "Перевод на другой язык"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SMTP Injection'?",
        answers: [
            "Внедрение команд SMTP для отправки спама или поддельных писем через уязвимую форму",
            "Инъекция СМС",
            "Инъекция почтальона",
            "Инъекция марки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SSI Injection'?",
        answers: [
            "Server-Side Includes Injection. Позволяет выполнять команды на сервере в страницах .shtml",
            "SSL инъекция",
            "SSH инъекция",
            "Start Injection"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'XPath Injection'?",
        answers: [
            "Инъекция в запросы XPath при работе с XML данными. Похожа на SQLi, но для XML баз данных",
            "Инъекция пути",
            "Инъекция координат",
            "Инъекция карты"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли найти Инъекции автоматизированными сканерами?",
        answers: [
            "Да, DAST (Dynamic Application Security Testing) инструменты (OWASP ZAP, Burp Suite Pro, Acunetix) хорошо находят базовые инъекции",
            "Нет, только вручную",
            "Только SAST",
            "Только фаззингом"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SAST' и находит ли он инъекции?",
        answers: [
            "Static Application Security Testing (анализ кода). Находит потенциальные места, где недоверенные данные попадают в опасные функции (Taint Analysis)",
            "Быстрый тест",
            "Медленный тест",
            "Тест на людях"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Source' и 'Sink' в Taint Analysis?",
        answers: [
            "Source — источник данных (ввод пользователя), Sink — опасная функция (sql query, system), использующая данные. Если есть путь от Source к Sink без санитизации — это уязвимость",
            "Вода и раковина",
            "Начало и конец",
            "Причина и следствие"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли WAF решением проблемы Инъекций?",
        answers: [
            "Нет, WAF — это 'Defense in Depth' (эшелонированная защита). Он может блокировать атаки, но уязвимость в коде остается",
            "Да, полностью",
            "Иногда",
            "Только от SQLi"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Polyglot payloads'?",
        answers: [
            "Специально составленные строки, которые являются валидным вектором атаки в разных контекстах (SQLi, XSS, и т.д.) одновременно",
            "Многоязычные люди",
            "Переводчики",
            "Словари"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind Injection' (Слепая инъекция)?",
        answers: [
            "Тип инъекции, когда приложение не возвращает ошибку или данные напрямую, но результат выполнения можно определить по косвенным признакам (задержка, другой ответ)",
            "Инъекция в слепую зону",
            "Инъекция без монитора",
            "Ошибка доступа"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Second Order Injection'?",
        answers: [
            "Когда вредоносные данные сохраняются (например, в БД), а срабатывают позже, при их извлечении и использовании в другом месте",
            "Инъекция второго уровня",
            "Двойная инъекция",
            "Повторная инъекция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли быть инъекция в файл настроек (Config)?",
        answers: [
            "Да, если приложение позволяет пользователю влиять на файлы конфигурации (например, через LFI или запись файлов)",
            "Нет",
            "Только в .ini",
            "Только в .xml"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Template Injection' (SSTI)?",
        answers: [
            "Внедрение в шаблонизаторы (Jinja2, FreeMarker, Twig), позволяющее выполнять код на сервере",
            "Шаблон сайта",
            "Шаблон документа",
            "Инъекция стиля"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как тестировать на инъекции (Fuzzing)?",
        answers: [
            "Отправлять различные спецсимволы ', \", ;, |, &, <, > и наблюдать за реакцией приложения (ошибки, задержки, аномалии)",
            "Читать код",
            "Смотреть в монитор",
            "Писать письма"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Host Header Injection'?",
        answers: [
            "Манипуляция заголовком Host может привести к отравлению кеша (Cache Poisoning), генерации неправильных ссылок сброса пароля или SSRF",
            "Инъекция хостинга",
            "Смена хостера",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем опасность 'CSV Injection' (Formula Injection)?",
        answers: [
            "Если данные экспортируются в CSV/Excel, и ячейка начинается с =, Excel может выполнить формулу (DDE), что приведет к RCE на компьютере жертвы",
            "Инъекция в таблицу",
            "Сортировка таблицы",
            "Удаление таблицы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от CSV Injection?",
        answers: [
            "Экранировать (добавлять ' перед) ячейки, начинающиеся с =, +, -, @ при экспорте",
            "Не использовать Excel",
            "Не использовать CSV",
            "Удалить формулы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли инъекция произойти через имя файла?",
        answers: [
            "Да, если имя файла не валидируется и попадает в командную строку или SQL запрос",
            "Нет",
            "Только в Linux",
            "Только в Windows"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Mass Assignment' (Массовое присвоение)?",
        answers: [
            "Уязвимость, когда фреймворк автоматически привязывает параметры запроса к полям объекта, позволяя перезаписать защищенные поля (isAdmin=true). Не совсем инъекция, но близко",
            "Массовая рассылка",
            "Массовый взлом",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Parameter Pollution'?",
        answers: [
            "Передача нескольких параметров с одним именем. Может использоваться для обхода WAF или внутренней логики приложения",
            "Загрязнение параметров",
            "Много параметров",
            "Очистка параметров"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли Buffer Overflow типом инъекции?",
        answers: [
            "Технически это проблема работы с памятью, но часто эксплуатируется через инъекцию 'слишком длинных данных' для перезаписи стека и выполнения Shellcode",
            "Нет",
            "Да",
            "Иногда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Shellcode'?",
        answers: [
            "Машинный код (payload), который выполняется после эксплуатации уязвимости (обычно запускает shell)",
            "Код оболочки",
            "Скрипт",
            "Пароль"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Format String Injection'?",
        answers: [
            "Уязвимость в функциях типа printf(user_input) в Си, позволяющая читать/писать память стека (%x, %n)",
            "Форматирование диска",
            "Форматирование текста",
            "Смена формата"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой принцип безопасности нарушает Инъекция?",
        answers: [
            "Trust boundaries violation (Нарушение границ доверия) — смешивание данных и управляющих команд",
            "Принцип открытости",
            "Принцип закрытости",
            "Принцип скорости"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Code Injection'?",
        answers: [
            "Общий термин, когда приложение выполняет произвольный программный код (PHP, Python, Java), введенный пользователем (например, через eval())",
            "Инъекция кода доступа",
            "Инъекция ДНК",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Чем отличается Remote File Inclusion (RFI) от Injection?",
        answers: [
            "RFI — это специфика, где 'инъекция' идет через подключение удаленного файла (include), который исполняется",
            "Ничем",
            "RFI безопаснее",
            "RFI быстрее"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Argument Injection'?",
        answers: [
            "Возможность добавлять аргументы к команде (например, в sendmail), но не выполнять новые команды",
            "Спор с аргументами",
            "Логическая инъекция",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему важно проверять Content-Type?",
        answers: [
            "Неверная обработка Content-Type может привести к тому, что файл будет интерпретирован как скрипт или XML, вызывая XSS или XXE",
            "Для красоты",
            "Для скорости",
            "Просто так"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Email Injection' (Mail Header Injection)?",
        answers: [
            "Вставка дополнительных заголовков (Bcc, Cc) в функцию отправки почты для рассылки спама",
            "Инъекция в письмо",
            "Вирус в письме",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли инъекция быть в названии Wi-Fi сети?",
        answers: [
            "Да, если устройство некорректно отображает SSID (например, XSS или Command Injection в админке роутера)",
            "Нет",
            "Только в 5G",
            "Только в Bluetooth"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли инъекция быть в QR коде?",
        answers: [
            "Да, QR код — это просто данные. Если сканер уязвим (SQLi, XSS, Command Injection), он сработает",
            "Нет",
            "Только ссылка",
            "Только картинка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Obj Injection' (PHP Object Injection)?",
        answers: [
            "Эксплуатация unserialize() с пользовательскими данными, приводящая к выполнению магических методов (__destruct, __wakeup) и gadget chains",
            "Инъекция объекта",
            "Создание объекта",
            "Удаление объекта"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от Object Injection?",
        answers: [
            "Не использовать unserialize() для недоверенных данных. Использовать JSON",
            "Использовать serialize()",
            "Использовать XML",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Hibernate Injection' (HQL Injection)?",
        answers: [
            "SQL-подобная инъекция, но в HQL (Hibernate Query Language). Позволяет манипулировать объектами базы данных",
            "Спящая инъекция",
            "Зимняя инъекция",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'JPQL Injection'?",
        answers: [
            "Инъекция в Java Persistence Query Language. Аналогично SQLi",
            "Инъекция Java",
            "Инъекция Query",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'EL Injection' (Expression Language)?",
        answers: [
            "Внедрение в язык выражений (JSP, JSF, Spring), позволяющее выполнять Java методы (RCE)",
            "Инъекция электричества",
            "Инъекция испанского",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'OGNL Injection'?",
        answers: [
            "Инъекция в Object-Graph Navigation Language (используется в Struts 2). Часто приводит к RCE",
            "Инъекция графа",
            "Инъекция объекта",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SpEL Injection'?",
        answers: [
            "Spring Expression Language Injection. Позволяет выполнять произвольный код в Spring приложениях",
            "Инъекция весны",
            "Инъекция пружины",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'MVEL Injection'?",
        answers: [
            "Инъекция в MVFLEX Expression Language. Аналогично другим EL инъекциям, ведет к RCE",
            "Инъекция кино",
            "Инъекция Marvel",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В каких файлах часто находят инъекции?",
        answers: [
            "Логи, XML, JSON, конфиги, изображения (Exif данные)",
            "Только .exe",
            "Только .txt",
            "Только .bat"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Log4Shell' (CVE-2021-44228)?",
        answers: [
            "Уязвимость JNDI Injection в библиотеке Log4j. Позволяет RCE через запись специальной строки в лог (${jndi:ldap://...})",
            "Шелл в логах",
            "Ошибка логирования",
            "Вирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'JNDI Injection'?",
        answers: [
            "Java Naming and Directory Interface. Позволяет загружать удаленные объекты (классы) через LDAP/RMI, что ведет к RCE",
            "Инъекция имен",
            "Инъекция директорий",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как работает атака через EXIF данные?",
        answers: [
            "В метаданные изображения (Exif) внедряется payload (XSS, PHP код). Если сервер читает/отображает их без обработки — атака успешна",
            "Через пиксели",
            "Через цвет",
            "Через размер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'IMAP/SMTP Injection'?",
        answers: [
            "Инъекция в команды почтовых серверов. Может позволить читать чужую почту или отправлять спам",
            "Инъекция карты",
            "Инъекция протокола",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли 'Late Static Binding' в PHP привести к проблемам?",
        answers: [
            "Само по себе нет, но особенности языка могут использоваться в сложных цепочках эксплуатации (gadgets)",
            "Да, всегда",
            "Нет, никогда",
            "Только в PHP 5"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Type Juggling' (манипуляция типами)?",
        answers: [
            "Особенность PHP (слабая типизация), когда сравнение == дает неожиданные результаты (0 == 'string'). Используется для обхода проверок (auth bypass)",
            "Жонглирование",
            "Типография",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли Type Juggling инъекцией?",
        answers: [
            "Нет, это логическая уязвимость, но часто используется вместе с инъекциями или для их достижения",
            "Да",
            "Иногда",
            "Всегда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Parameter Tampering'?",
        answers: [
            "Изменение параметров URL, форм или куки для влияния на логику (цена, права доступа)",
            "Тампер",
            "Взлом параметров",
            "Удаление параметров"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'IDOR' (Insecure Direct Object Reference)?",
        answers: [
            "Доступ к объекту по ID без проверки прав. Часто путают с инъекцией, но это Access Control. Хотя SQLi может помочь найти IDOR",
            "Инъекция ID",
            "Прямая ссылка",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Client-side Injection'?",
        answers: [
            "Инъекции, выполняемые в браузере (XSS, HTMLi, CSTI)",
            "Инъекция клиента",
            "Укол клиента",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Server-side Injection'?",
        answers: [
            "Инъекции, выполняемые на сервере (SQLi, Commandi, LDAPi, XXE)",
            "Инъекция сервера",
            "Укол сервера",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой самый опасный вид инъекции?",
        answers: [
            "Обычно Command Injection (RCE), так как дает полный контроль над сервером",
            "XSS",
            "HTMLi",
            "SQLi (хотя тоже критично)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Zero-day Injection'?",
        answers: [
            "Инъекция, использующая неизвестную ранее уязвимость (0-day)",
            "Инъекция нуля",
            "Инъекция дня",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как снизить Surface Area (Поверхность атаки) для инъекций?",
        answers: [
            "Уменьшить количество точек входа, отключить ненужные сервисы, удалить неиспользуемый код и функции",
            "Уменьшить экран",
            "Уменьшить клавиатуру",
            "Уменьшить интернет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Fuzzing'?",
        answers: [
            "Метод тестирования, заключающийся в подаче на вход программы случайных, невалидных или неожиданных данных для вызова сбоев (и поиска уязвимостей)",
            "Пушистик",
            "Фаз",
            "Шум"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие инструменты используют для фаззинга веб-приложений?",
        answers: [
            "Wfuzz, FFUF, Burp Intruder, ZAP Fuzzer",
            "Notepad",
            "Word",
            "Excel"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Canonicalization' issues?",
        answers: [
            "Проблемы при приведении данных к каноническому виду. Например, декодирование URL дважды может позволить протащить инъекцию через фильтр (%2527 -> %27 -> ')",
            "Канонизация",
            "Церковь",
            "Правила"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Unicode Transformation' issues?",
        answers: [
            "Некоторые символы Unicode при приведении к ASCII или lowercase могут превращаться в опасные (например, 'Kelvin sign' K -> k, или 'long s' -> s), обходя фильтры",
            "Юникод",
            "Трансформеры",
            "Кодировка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'HPP' (HTTP Parameter Pollution)?",
        answers: [
            "Атака, использующая особенности обработки дублирующихся параметров разными серверами (WAF видит первый, сервер берет второй)",
            "Загрязнение HTTP",
            "Протокол загрязнения",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Clickjacking'?",
        answers: [
            "UI Redressing атака. Не инъекция, но часто тестируется вместе",
            "Клик",
            "Джекинг",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить базу данных от SQLi, если нельзя использовать ORM/Prepared Statements (легаси)?",
        answers: [
            "Строгая валидация типов (is_numeric) и экранирование спецсимволов (mysql_real_escape_string) для каждого параметра. Но это рискованно",
            "Никак",
            "Надеяться на лучшее",
            "Отключить БД"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Least Privilege Principle'?",
        answers: [
            "Предоставление минимально необходимых прав пользователю или процессу. Смягчает последствия успешной инъекции",
            "Минимум прав",
            "Максимум прав",
            "Средние права"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Defense in Depth'?",
        answers: [
            "Многоуровневая защита (Валидация + WAF + Least Privilege + Patching + Monitoring)",
            "Глубокая защита",
            "Защита в глубине",
            "Один слой защиты"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Security misconfiguration'?",
        answers: [
            "Небезопасные настройки (дефолтные пароли, включенные дебаг-режимы), которые могут облегчить эксплуатацию инъекций",
            "Ошибка конфигурации",
            "Сломанный конфиг",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как обновления (Patch management) помогают от инъекций?",
        answers: [
            "Исправляют известные уязвимости в платформе и библиотеках",
            "Делают интерфейс лучше",
            "Ускоряют работу",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Bug Bounty'?",
        answers: [
            "Программа вознаграждения исследователей за найденные уязвимости",
            "Охота на жуков",
            "Деньги за баги",
            "Благотворительность"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Penetration Testing'?",
        answers: [
            "Имитация кибератаки на систему для поиска уязвимостей",
            "Тест на проникновение",
            "Пентест",
            "Взлом"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Кто такой 'Ethical Hacker'?",
        answers: [
            "Специалист, который легально ищет уязвимости для их устранения",
            "Добрый хакер",
            "Белая шляпа",
            "Все варианты"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "Что такое 'CVE'?",
        answers: [
            "Common Vulnerabilities and Exposures — база данных общеизвестных уязвимостей",
            "Код ошибки",
            "Сертификат",
            "Лицензия"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'CWE'?",
        answers: [
            "Common Weakness Enumeration — классификация типов уязвимостей (слабостей)",
            "Слабость",
            "Ошибка",
            "Каталог"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой CWE соответствует SQL Injection?",
        answers: [
            "CWE-89",
            "CWE-79",
            "CWE-20",
            "CWE-1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой CWE соответствует XSS?",
        answers: [
            "CWE-79",
            "CWE-89",
            "CWE-20",
            "CWE-1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'CVSS'?",
        answers: [
            "Common Vulnerability Scoring System — система оценки критичности уязвимостей (0-10)",
            "Оценка",
            "Баллы",
            "Рейтинг"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой балл CVSS обычно у RCE?",
        answers: [
            "9.0 - 10.0 (Critical)",
            "5.0",
            "2.0",
            "0"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что означают метрики AV:N, AC:L, PR:N, UI:N в CVSS?",
        answers: [
            "Network (удаленно), Low Complexity (легко), Privileges None (без прав), User Interaction None (жертва не нужна) — идеальные условия для хакера",
            "Сложно",
            "Локально",
            "С правами"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind SQL Injection'?",
        answers: [
            "Когда база данных не возвращает ошибки или данные, но реагирует по разному (True/False) на запросы",
            "Слепой SQL",
            "SQL без монитора",
            "SQL для админа"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Boolean-based Blind SQLi'?",
        answers: [
            "Атака, основанная на анализе ответа (страница загрузилась или нет/другой контент) при условии True или False",
            "SQL с булевой алгеброй",
            "SQL с логикой",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Time-based Blind SQLi'?",
        answers: [
            "Атака, основанная на задержке ответа (SLEEP, WAITFOR DELAY). Если сервер 'завис', значит условие True",
            "SQL со временем",
            "Быстрый SQL",
            "Медленный SQL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Risk Assessment'?",
        answers: [
            "Процесс идентификации, анализа и оценки рисков (Risk = Probability * Impact)",
            "Риск менеджмент",
            "Страхование",
            "Аудит"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Threat Modeling'?",
        answers: [
            "Процесс моделирования угроз (STRIDE, PASTA) на этапе проектирования, чтобы найти уязвимости архитектурно (в том числе места возможных инъекций)",
            "Рисование угроз",
            "Дизайн",
            "Моделирование одежды"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что означает буква 'I' (Information Disclosure) в STRIDE?",
        answers: [
            "Раскрытие информации. Инъекции часто ведут к этому",
            "Интернет",
            "Инъекция",
            "Интеграция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что означает буква 'E' (Elevation of Privilege) в STRIDE?",
        answers: [
            "Повышение привилегий. Инъекции могут позволить стать админом",
            "Элеватор",
            "Исполнение",
            "Ошибка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Secure SDLC'?",
        answers: [
            "Secure Software Development Life Cycle — внедрение безопасности на всех этапах разработки (от требований до деплоя)",
            "Безопасная жизнь",
            "Цикл разработки",
            "Методология"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'DevSecOps'?",
        answers: [
            "Культура и практики интеграции безопасности (Security) в DevOps процессы (CI/CD, автоматизация)",
            "Разработчики и Операторы",
            "Секретный отдел",
            "Новый язык"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как CI/CD помогает бороться с инъекциями?",
        answers: [
            "Автоматический запуск SAST/DAST сканеров и тестов при каждом коммите",
            "Не помогает",
            "Делает быстрее",
            "Деплоит код"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Shift Left' security?",
        answers: [
            "Перенос проверок безопасности на более ранние этапы (влево по временной шкале) — к разработчикам",
            "Сдвиг влево",
            "Поворот налево",
            "Политика"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли обучение разработчиков мерой защиты?",
        answers: [
            "Да, одна из самых эффективных. Разработчики должны знать, как писать безопасный код",
            "Нет",
            "Пустая трата времени",
            "Иногда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Root Cause Analysis'?",
        answers: [
            "Анализ корневой причины инцидента. Почему произошла инъекция? (не было валидации, старая либа и т.д.)",
            "Анализ корней",
            "Анализ админа",
            "Поиск виновных"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Virtual Patching'?",
        answers: [
            "Использование WAF правил для блокировки эксплойтов уязвимости, пока код не исправлен разработчиками",
            "Виртуальный пластырь",
            "Виртуальная реальность",
            "Патч корд"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли инъекция произойти через сторонний API?",
        answers: [
            "Да, если мы доверяем данным от API и не проверяем их (Third-party trust issue)",
            "Нет, API безопасны",
            "Только от Google",
            "Только от Facebook"
        ],
        correctAnswerIndex: 0
    }
];
