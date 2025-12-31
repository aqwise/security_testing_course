export const quizQuestions = [
    {
        question: "Что такое SQL Injection?",
        answers: [
            "Уязвимость, позволяющая выполнение произвольных SQL команд в базе данных приложения",
            "Внедрение JavaScript в базу данных",
            "Атака на стиль сайта",
            "Ошибка компиляции SQL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ часто используется для проверки SQL Injection (одинарная кавычка)?",
        answers: [
            "'",
            "\"",
            "`",
            "|"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает tautology (тавтология) в SQL инъекции, например ' OR 1=1 --?",
        answers: [
            "Делает условие всегда истинным (True), позволяя обойти аутентификацию или вернуть все записи",
            "Удаляет базу данных",
            "Вызывает ошибку синтаксиса",
            "Зашифровывает данные"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой оператор используется в Union-based SQLi для объединения результатов?",
        answers: [
            "UNION",
            "JOIN",
            "MERGE",
            "LINK"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что необходимо для успешной UNION-based атаки?",
        answers: [
            "Одинаковое количество колонок и совместимые типы данных в объединяемых запросах",
            "Знание пароля админа",
            "Отключенный WAF",
            "Использование HTTPS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как узнать количество колонок в запросе (Union-based)?",
        answers: [
            "Используя ORDER BY X (увеличивая X пока не будет ошибки) или UNION SELECT NULL, NULL...",
            "Спросить у админа",
            "Посмотреть исходный код страницы",
            "Использовать grep"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Blind SQL Injection?",
        answers: [
            "Атака, при которой приложение не возвращает данные базы данных напрямую в ответе",
            "Атака в темноте",
            "Слепая печать SQL команд",
            "Атака на невидимые поля"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие два подтипа Blind SQL Injection существуют?",
        answers: [
            "Boolean-based (по поведению/контенту) и Time-based (по задержкам)",
            "GET-based и POST-based",
            "Fast и Slow",
            "Light и Dark"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая функция вызывает задержку в MySQL?",
        answers: [
            "SLEEP()",
            "WAIT()",
            "DELAY()",
            "PAUSE()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая функция вызывает задержку в PostgreSQL?",
        answers: [
            "pg_sleep()",
            "sleep()",
            "wait_for()",
            "timeout()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая команда вызывает задержку в MSSQL?",
        answers: [
            "WAITFOR DELAY '0:0:5'",
            "SLEEP(5)",
            "PG_SLEEP(5)",
            "TIMEOUT 5"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Error-based SQL Injection?",
        answers: [
            "Получение данных из сообщений об ошибках базы данных, которые выводятся пользователю",
            "Внедрение ошибок в базу",
            "Удаление логов ошибок",
            "DDoS атака"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ используется для комментариев в MySQL?",
        answers: [
            "# или -- (с пробелом)",
            "//",
            "<!--",
            ";"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ используется для комментариев в MSSQL?",
        answers: [
            "--",
            "#",
            "//",
            "%%"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как в MySQL узнать версию базы данных?",
        answers: [
            "SELECT @@version или SELECT version()",
            "SELECT info()",
            "SHOW VER",
            "GET VERSION"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как в Oracle узнать версию базы данных?",
        answers: [
            "SELECT banner FROM v$version",
            "SELECT version()",
            "SELECT @@version",
            "SHOW VERSION"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Second-Order SQL Injection'?",
        answers: [
            "Внедренный payload сохраняется в базе (например, при регистрации), а срабатывает позже при его использовании в другом запросе",
            "Двойная инъекция",
            "Инъекция второго уровня",
            "Атака через два прокси"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая защита от SQL Injection является наиболее эффективной?",
        answers: [
            "Использование параметризованных запросов (Prepared Statements)",
            "Экранирование кавычек",
            "WAF",
            "Скрытие ошибок"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли WAF панацеей от SQL Injection?",
        answers: [
            "Нет, WAF можно обойти (например, используя кодировки, различные техники обфускации)",
            "Да, WAF блокирует 100% атак",
            "Только если он дорогой",
            "Только от MySQL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'sqlmap'?",
        answers: [
            "Автоматизированный инструмент для поиска и эксплуатации SQL инъекций",
            "Карта SQL серверов",
            "Учебник по SQL",
            "Вирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой флаг sqlmap используется для дампу всей базы данных?",
        answers: [
            "--dump-all или --dump",
            "--get-data",
            "--hack",
            "--extract"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой флаг sqlmap позволяет получить shell (os-shell)?",
        answers: [
            "--os-shell",
            "--cmd",
            "--terminal",
            "--root"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли читать файлы через SQL Injection в MySQL?",
        answers: [
            "Да, если есть права FILE и secure_file_priv не ограничивает (функция load_file())",
            "Нет",
            "Всегда",
            "Только картинки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как записать файл на сервер через SQL Injection в MySQL?",
        answers: [
            "SELECT ... INTO OUTFILE 'path'",
            "WRITE_FILE()",
            "SAVE 'path'",
            "UPLOAD ..."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Out-of-Band (OOB) SQL Injection'?",
        answers: [
            "Техника, когда данные передаются через канал, отличный от того, по которому пришел запрос (например, DNS или HTTP запрос, инициированный базой)",
            "Внеплановая инъекция",
            "Инъекция вне диапазона",
            "Бандитская инъекция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая функция в Oracle может использоваться для OOB (DNS)?",
        answers: [
            "UTL_HTTP.REQUEST или UTL_INADDR.GET_HOST_ADDRESS",
            "DNS_REQUEST",
            "PING",
            "CONNECT"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая хранимая процедура MSSQL позволяет выполнять команды ОС (если включена)?",
        answers: [
            "xp_cmdshell",
            "exec_cmd",
            "run_os",
            "system"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как включить xp_cmdshell, если есть права sa?",
        answers: [
            "sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
            "ENABLE xp_cmdshell",
            "START xp_cmdshell",
            "Нельзя включить"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SQL HPP' (HTTP Parameter Pollution)?",
        answers: [
            "Техника обхода WAF путем передачи нескольких параметров с одинаковым именем (id=1&id=operator), где WAF проверяет один, а приложение берет другой",
            "Загрязнение базы",
            "HTML Programming",
            "Hypertext Protocol"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как объединить строки в Oracle?",
        answers: [
            "|| (двойная черта)",
            "+",
            "CONCAT()",
            "&"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как объединить строки в MSSQL?",
        answers: [
            "+",
            "||",
            "JOIN",
            "UNION"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает функция `GROUP_CONCAT` в MySQL?",
        answers: [
            "Объединяет значения из нескольких строк в одну строку (удобно для извлечения всех таблиц одним запросом)",
            "Группирует файлы",
            "Удаляет дубликаты",
            "Сортирует данные"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая база данных по умолчанию в PHP+Apache (LAMP)?",
        answers: [
            "Обычно MySQL / MariaDB",
            "Oracle",
            "PostgreSQL",
            "MongoDB"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Stacked Queries'?",
        answers: [
            "Выполнение нескольких SQL запросов за раз, разделенных точкой с запятой (;). Позволяет INSERT/UPDATE/DELETE/DROP",
            "Запросы в стеке",
            "Медленные запросы",
            "Очередь запросов"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Поддерживает ли PHP/MySQL (mysqli, mysql_query) Stacked Queries по умолчанию?",
        answers: [
            "Нет, обычно execute() или query() выполняют только один запрос. multi_query() нужен для Stacked, что редко используется",
            "Да, всегда",
            "Только в PHP 5",
            "Только в Windows"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В какой базе данных таблица с пользователями часто называется 'dual' (используется для SELECT 'x' FROM dual)?",
        answers: [
            "Oracle",
            "MySQL",
            "MSSQL",
            "PostgreSQL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как получить список таблиц в MySQL?",
        answers: [
            "SELECT table_name FROM information_schema.tables",
            "SHOW TABLES",
            "Оба варианта (второй специфичен для CLI/MySQL)",
            "LIST TABLES"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Можно ли использовать SQL Injection для обхода OTP (One Time Password)?",
        answers: [
            "Если проверка OTP делается SQL запросом (редко), то да. Обычно SQLi помогает обойти пароль (Login Bypass)",
            "Да, всегда",
            "Нет, OTP не связан с БД",
            "SQLi ломает телефон"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Boolean inference'?",
        answers: [
            "Вывод информации true/false на основе реакции приложения (изменился контент или нет)",
            "Логический вывод Шерлока",
            "Ошибка Boolean",
            "Тип переменной"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой пейлоад `' OR '1'='1` делает?",
        answers: [
            "Возвращает True (строковое сравнение)",
            "Ошибку",
            "False",
            "Null"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем опасность использования dynamic SQL в хранимых процедурах?",
        answers: [
            "Если параметры конкатенируются внутрь EXEC(@sql), это создает уязвимость SQLi даже внутри процедуры",
            "Это замедляет работу",
            "Это переполняет память",
            "Нет опасности"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое SQL truncation attack?",
        answers: [
            "Атака, использующая обрезание длинных строк базой данных (например, регистрация 'admin...[spaces]...x' который обрезается до 'admin')",
            "Удаление таблиц",
            "Обрезание проводов",
            "Сжатие данных"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от LIKE-инъекций (когда пользователь вводит % или _)?",
        answers: [
            "Экранировать спецсимволы LIKE (%, _, [) вручную, так как prepared statements их не экранируют (они считаются данными)",
            "Ничего не делать",
            "Запретить поиск",
            "Удалить LIKE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли найти SQLi в заголовке Cookie?",
        answers: [
            "Да, если приложение использует данные из Cookie в SQL запросе без санитизации",
            "Нет, Cookie не идут в БД",
            "Только в User-Agent",
            "Только в Referer"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ используется для конкатенации в PostgreSQL?",
        answers: [
            "||",
            "+",
            "CONCAT",
            "&"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `SELECT * FROM users WHERE username = '$user' AND password = '$pass'` уязвимым?",
        answers: [
            "Отсутствие экранирования $user и $pass",
            "Использование SELECT *",
            "Использование AND",
            "Имя таблицы users"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как выглядит типичный Blind Time-based payload для MSSQL?",
        answers: [
            "'; WAITFOR DELAY '0:0:5'--",
            "' SLEEP(5)--",
            "' pg_sleep(5)--",
            "' OR sleep(5)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'NoSQL Injection'?",
        answers: [
            "Инъекция в NoSQL базы данных (MongoDB, и т.д.), использующая особенности их синтаксиса (например, $ne, $where)",
            "SQL инъекция без SQL",
            "Новая SQL инъекция",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать SQLi для повышения привилегий в ОС?",
        answers: [
            "Да, через xp_cmdshell (MSSQL) или UDF (MySQL) или другие механизмы",
            "Нет",
            "Только до админа сайта",
            "Только до модератора"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `CAST()` и `CONVERT()`?",
        answers: [
            "Функции преобразования типов, часто используемые в Error-based SQLi для вызова ошибки несоответствия типов",
            "Функции шифрования",
            "Функции видео",
            "Функции аудио"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как получить имя текущего пользователя в MySQL?",
        answers: [
            "user() или system_user() или current_user()",
            "get_user()",
            "whoami",
            "me()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как получить имя текущего пользователя в MSSQL?",
        answers: [
            "user_name() или system_user",
            "get_user()",
            "whoami",
            "me()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как закодировать payload, чтобы обойти простых фильтров (например, пробелы)?",
        answers: [
            "Использовать комментарии /**/ вместо пробелов",
            "Использовать Tab",
            "Использовать Enter",
            "Все перечисленное"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "Что такое `information_schema`?",
        answers: [
            "Стандартная база данных (метаданные), содержащая информацию о всех таблицах и колонках (MySQL, PostgreSQL, MSSQL)",
            "Схема для информации",
            "Секретная таблица",
            "Файл настроек"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В какой таблице information_schema лежат имена колонок?",
        answers: [
            "columns",
            "tables",
            "schemata",
            "fields"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `Limit 0,1` в MySQL?",
        answers: [
            "Возвращает первую запись",
            "Возвращает 0 записей",
            "Возвращает последнюю запись",
            "Удаляет запись"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Time-based extraction'?",
        answers: [
            "Посимвольное извлечение данных путем измерения задержек (если символ верный — задержка)",
            "Извлечение времени",
            "Быстрое извлечение",
            "Медленное извлечение"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему важно санитайзить Input во всех полях?",
        answers: [
            "Потому что любое поле, попадающее в SQL запрос, потенциально уязвимо",
            "Для красоты",
            "Чтобы было чисто",
            "Требование заказчика"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли ORDER BY быть уязвимым?",
        answers: [
            "Да, параметры сортировки часто подставляются динамически и не могут быть параметризованы стандартными placeholders",
            "Нет",
            "Редко",
            "Только DESC"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить ORDER BY от инъекций?",
        answers: [
            "Использовать белый список разрешенных колонок для сортировки",
            "Prepared statements",
            "Экранирование",
            "Удаление пробелов"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `HAVING` инъекция?",
        answers: [
            "Инъекция в секцию HAVING запроса (обычно используется для фильтрации сгруппированных данных)",
            "Инъекция владения",
            "Инъекция having fun",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать шестнадцатеричное (HEX) кодирование для строковых литералов в MySQL?",
        answers: [
            "Да, например 0x414243 вместо 'ABC' (помогает обойти филь фильтр кавычек)",
            "Нет",
            "Только в Oracle",
            "Только для чисел"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как можно использовать `Unclosed Quotation Mark` ошибку?",
        answers: [
            "Чтобы понять, что инъекция возможна (Error-based detection)",
            "Чтобы закрыть кавычку",
            "Чтобы сломать сервер",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind SQLi с условными ошибками'?",
        answers: [
            "Техника, когда мы вызываем ошибку (например, деление на ноль) если условие истинно, и различаем состояния по наличию ошибки 500",
            "Слепые ошибки",
            "Случайные ошибки",
            "Ошибки валидации"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент помогает перехватывать запросы для ручного тестирования SQLi?",
        answers: [
            "Burp Suite Proxy (Repeater)",
            "Wireshark",
            "Nmap",
            "Ping"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `ascii()` или `char()` функции?",
        answers: [
            "Возвращают ASCII код символа или символ по коду. Важны для посимвольного перебора в Blind SQLi",
            "Рисуют ASCII арт",
            "Кодируют в Base64",
            "Шифруют"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `substring()`?",
        answers: [
            "Функция извлечения подстроки. Критична для Blind SQLi (извлечекать по 1 символу)",
            "Функция метро",
            "Подписка",
            "Замена строки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как выглядит payload для проверки числового поля `id=1`?",
        answers: [
            "id=1 AND 1=1 (True) и id=1 AND 1=0 (False)",
            "id=1'",
            "id='1'",
            "id=one"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Polyglot' payload?",
        answers: [
            "Универсальный payload, который работает в разных контекстах (закрывает разные кавычки, комментарии) и часто сразу выполняет XSS/SQLi",
            "Многоязычный человек",
            "Словарь",
            "Переводчик"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли SQL инъекция привести к XSS?",
        answers: [
            "Да, если данные из БД выводятся на страницу без фильтрации (Reflected/Stored XSS через SQLi)",
            "Нет",
            "Редко",
            "Только в IE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Inline SQL Injection'?",
        answers: [
            "Инъекция, которая встраивается в существующий запрос, не прерывая его (используя UNION или subqueries)",
            "Инъекция в линию",
            "Инъекция CSS",
            "Быстрая инъекция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить код на PHP (PDO) от SQLi?",
        answers: [
            "$stmt = $pdo->prepare('SELECT * FROM t WHERE id = :id'); $stmt->execute(['id' => $id]);",
            "mysql_query(\"SELECT ... $id\")",
            "addslashes($id)",
            "htmlspecialchars($id)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Блокирует ли HTTPS SQL инъекции?",
        answers: [
            "Нет, HTTPS шифрует канал, но сервер получает payload в открытом виде после расшифровки SSL",
            "Да, полностью",
            "Частично",
            "Только POST запросы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие привилегии нужны для `xp_cmdshell`?",
        answers: [
            "Sysadmin (sa) или явное разрешение (proxy credential)",
            "User",
            "Guest",
            "Public"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли найти SQLi в JSON данных?",
        answers: [
            "Да, если сервер парсит JSON и подставляет значения в SQL",
            "Нет, JSON безопасен",
            "Только в XML",
            "Только в YAML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой риск несет SQLi в UPDATE запросе?",
        answers: [
            "Изменение данных (паролей, балансов, прав)",
            "Только чтение",
            "Никакого",
            "Ускорение работы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое плагин `sqlmap` для Burp?",
        answers: [
            "CO2 (или аналоги), позволяющий генерировать команду sqlmap из запроса в Burp",
            "Java плагин",
            "Python скрипт",
            "Скин для Burp"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая БД использует `pg_sleep()`?",
        answers: [
            "PostgreSQL",
            "MySQL",
            "Oracle",
            "SQLite"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить длину пароля в Blind SQLi?",
        answers: [
            "AND length(password) > 5 ... (перебором)",
            "AND password = 5",
            "length()",
            "count()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Literal' в SQL?",
        answers: [
            "Фиксированное значение (строка, число), которое не должно интерпретироваться как команда",
            "Литература",
            "Переменная",
            "Функция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Нужно ли экранировать входные данные для NoSQL?",
        answers: [
            "Да, или использовать безопасные API, так как NoSQL тоже подвержен инъекциям",
            "Нет",
            "Иногда",
            "NoSQL не нужна защита"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент для статического анализа (SAST) находит SQLi?",
        answers: [
            "SonarQube, Checkmarx, Coverity",
            "Notepad++",
            "Chrome DevTools",
            "Paint"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `extractvalue()` в MySQL?",
        answers: [
            "Функция для работы с XML, часто используемая для Error-based SQLi (возвращает ошибку XPath с данными)",
            "Извлечение ценности",
            "Распаковка архива",
            "Функция джекпот"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `xmltype` в Oracle?",
        answers: [
            "Тип данных XML, также используется для Error-based векторов",
            "Тип файла",
            "Тип браузера",
            "Тип клавиатуры"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как избежать SQLi в Python (Django)?",
        answers: [
            "Использовать ORM (MyModel.objects.filter(name=...)), избегая raw() запросов с форматированием строк",
            "Использовать f-strings везде",
            "Не использовать Django",
            "Отключить базу"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `db.execute(f'SELECT * FROM users WHERE id={id}')` уязвимым кодом?",
        answers: [
            "Да, это прямая интерполяция строки (f-string) — классическая SQLi",
            "Нет",
            "Только в Java",
            "Только в PHP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Mass Assignment' и связано ли оно с SQLi?",
        answers: [
            "Уязвимость привязки параметров объекта, не SQLi, но часто рядом. SQLi это про парсинг запроса",
            "Массовая рассылка",
            "Массовое удаление",
            "Нет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли SQLi в INSERT запросе быть опасной?",
        answers: [
            "Да, можно внедрить подзапрос для получения данных и сохранения их в поле, которое потом увидит атакующий",
            "Нет, INSERT только пишет",
            "Редко",
            "Только для админов"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Parameter Sniffing'?",
        answers: [
            "Особенность оптимизатора SQL Server, не уязвимость безопасности напрямую",
            "Нюхание параметров",
            "Перехват трафика",
            "Тип инъекции"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая функция в PHP экранирует спецсимволы для MySQL (устаревшая)?",
        answers: [
            "mysql_escape_string / mysql_real_escape_string",
            "escape_sql",
            "safe_sql",
            "clean()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему `driver={SQL Server}` в connection string может быть вектором?",
        answers: [
            "Это не вектор, это конфигурация ODBC/ADO",
            "Это уязвимость",
            "Это ошибка",
            "Это эксплойт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой порт по умолчанию у MySQL?",
        answers: [
            "3306",
            "1433",
            "5432",
            "1521"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой порт по умолчанию у MSSQL?",
        answers: [
            "1433",
            "3306",
            "5432",
            "80"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой порт по умолчанию у PostgreSQL?",
        answers: [
            "5432",
            "3306",
            "1433",
            "8080"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить `LIMIT` и `OFFSET` в SQL?",
        answers: [
            "Приводить к integer (intval) перед подстановкой, так как там ожидаются только числа",
            "Экранировать кавычки",
            "Взять в кавычки",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `UNION ALL`?",
        answers: [
            "Объединение без удаления дубликатов (быстрее и часто используется в SQLi)",
            "Объединение всех стран",
            "Команда удаления",
            "Фильтр"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем разница между `UNION` и `UNION ALL` при атаке?",
        answers: [
            "UNION удаляет дубликаты (может скрыть данные), UNION ALL показывает всё",
            "Никакой",
            "UNION только для MySQL",
            "UNION ALL только для Oracle"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли SQLi произойти в `DELETE` запросе?",
        answers: [
            "Да, например в WHERE clause: DELETE FROM logs WHERE id = $id",
            "Нет",
            "Только если удаляется вся таблица",
            "Редко"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Существует ли SQLi в GraphQL?",
        answers: [
            "Да, если GraphQL резолверы используют небезопасные SQL запросы под капотом",
            "Нет, GraphQL это не SQL",
            "GraphQL сам по себе SQL",
            "Только в Apollo"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind SQL Injection via HTTP Headers'?",
        answers: [
            "Инъекция через заголовки (User-Agent, X-Forwarded-For), которые логируются или используются в БД",
            "Инъекция в тело ответа",
            "Инъекция в URL",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить уязвимость, если приложение ничего не выводит?",
        answers: [
            "Time-based (задержки) или OOB (DNS запросы)",
            "Посмотреть код",
            "Угадать",
            "Попросить доступ"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Wide Charset SQL Injection'?",
        answers: [
            "Использование многобайтовых кодировок (GBK и т.д.) для 'съедания' экранирующего слэша",
            "Широкая инъекция",
            "Инъекция шрифтов",
            "Инъекция ширины"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как работает атака с `GBK` кодировкой?",
        answers: [
            "Символ 0xbf + слэш (0x5c) интерпретируются как один иероглиф, оставляя кавычку незакрытой",
            "Она удаляет базу",
            "Она меняет язык",
            "Она красит сайт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'SQL Truncation'?",
        answers: [
            "Когда БД обрезает данные, превышающие размер колонки (может использоваться для обхода проверок)",
            "Сжатие SQL",
            "Архивация SQL",
            "Удаление SQL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как предотвратить SQL Truncation?",
        answers: [
            "Включить Strict Mode в БД (STRICT_ALL_TABLES в MySQL) и валидировать длину ввода на сервере",
            "Увеличить диск",
            "Удалить колонки",
            "Ничего"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать SQLi для DoS?",
        answers: [
            "Да, через тяжелые запросы (BENCHMARK(), декартовы произведения) или блокировки",
            "Нет",
            "Только сетью",
            "Только пингом"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `BENCHMARK()` в MySQL?",
        answers: [
            "Функция выполнения выражения N раз, используется для Time-based атак и нагрузочного DoS",
            "Тест скорости",
            "Бенчмарк процессора",
            "Утилита"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить приложение от автоматических сканеров SQLi?",
        answers: [
            "WAF, Rate Limiting, Captcha (меры по затруднению сканирования), но главное — устранить уязвимости в коде",
            "Отключить сайт",
            "Сменить IP",
            "Использовать VPN"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли смена имен таблиц защитой от SQLi?",
        answers: [
            "Нет, это Security through Obscurity. Имена можно узнать через information_schema или Brute-force",
            "Да, надежной",
            "Иногда",
            "Да, если имена длинные"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `sqlmap --wizard`?",
        answers: [
            "Интерактивный режим для новичков",
            "Магический режим",
            "Режим волшебника",
            "Режим бога"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "SQL Injection находится в OWASP Top 10?",
        answers: [
            "Да, в категории A03: Injection",
            "Нет",
            "Был, но убрали",
            "Только в Top 5"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какое главное правило защиты от всех инъекций?",
        answers: [
            "Никогда не доверяй пользовательскому вводу (Input Validation + Output Encoding + Parameterization)",
            "Используй антивирус",
            "Используй Linux",
            "Не используй базы данных"
        ],
        correctAnswerIndex: 0
    }
];
