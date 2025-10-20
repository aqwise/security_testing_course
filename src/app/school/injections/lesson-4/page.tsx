'use client';

import React from 'react';
import { ContentPageLayout } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink } from 'lucide-react';
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
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="pt-6">
            <P className="text-sm">
              <strong>Источник материала:</strong> Данный урок основан на материалах из{' '}
              <a 
                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4038983727/SQL+Injection" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                Confluence (Innowise Group) <ExternalLink className="ml-1 h-3 w-3" />
              </a>
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Теория</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <H3>Что такое SQL-инъекция?</H3>
            <P>
              Это одна из самых опасных уязвимостей веб-приложений. Она позволяет злоумышленнику выполнять запросы 
              к базе данных сайта, а в некоторых случаях — записывать/читать данные в файловую систему с правами 
              сервера базы данных, изменять записи в таблицах и даже полностью удалять базу данных. Проще говоря, 
              SQL-инъекция — это атака на базу данных, которая позволяет выполнить действие, не запланированное её создателем.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Пять основных причин SQL-инъекции</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ol className="list-decimal pl-6 space-y-2">
              <li>Динамическое построение SQL-запросов</li>
              <li>Некорректная обработка исключений</li>
              <li>Некорректная обработка специальных символов</li>
              <li>Некорректная обработка типов данных</li>
              <li>Небезопасная конфигурация СУБД</li>
            </ol>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Основные виды SQL Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <H3>1. Внутриканальные (In-band)</H3>
              <P>
                Результат приходит в ответе тем же каналом (один запрос – один ответ):
              </P>
              <ul className="list-disc pl-6 mb-3 space-y-2">
                <li>
                  <strong>Error-based</strong> – В случае этой атаки сканер заменяет или добавляет в уязвимый параметр 
                  синтаксически неправильное выражение, после чего парсит HTTP-ответ (заголовки и тело) в поиске ошибок DBMS, 
                  в которых содержалась бы заранее известная инъецированная последовательность символов и где-то "рядом" вывод 
                  на интересующий нас подзапрос. Эта техника работает только тогда, когда веб-приложение по каким-то причинам 
                  (чаще всего в целях отладки) раскрывает ошибки DBMS.
                </li>
                <li>
                  <strong>Union-based</strong> – через <code className="bg-muted px-1 py-0.5 rounded">UNION SELECT</code> оператор — 
                  вставляем свои колонки, получаем данные и т.д.
                </li>
              </ul>
            </div>

            <div>
              <H3>2. Инференциальная или дедуктивная (Inferential)</H3>
              <P>
                Результат не возвращается напрямую:
              </P>
              <ul className="list-disc pl-6 mb-3 space-y-2">
                <li>
                  <strong>Boolean-based</strong> — запрос возвращает true/false; мы отличаем по содержимому страницы. 
                  Например страница логинки, если креды совпадают, то тело ответа – <code className="bg-muted px-1 py-0.5 rounded">1</code>. 
                  Если нет – <code className="bg-muted px-1 py-0.5 rounded">0</code>. Подставляем математический оператор{' '}
                  <code className="bg-muted px-1 py-0.5 rounded">AND 1=0</code> c правильными кредами – в ответе будет{' '}
                  <code className="bg-muted px-1 py-0.5 rounded">0</code>. Потому что, <code className="bg-muted px-1 py-0.5 rounded">1</code> не 
                  может равняться <code className="bg-muted px-1 py-0.5 rounded">0</code>. И наоборот.
                </li>
                <li>
                  <strong>Time-based</strong> — вызываем <code className="bg-muted px-1 py-0.5 rounded">SLEEP(10)</code> /{' '}
                  <code className="bg-muted px-1 py-0.5 rounded">pg_sleep(10)</code> (<em>в зависимости от типа БД свои операторы</em>) 
                  и измеряем задержку ответа (<em>в Repeater внизу справа</em>). То есть, вставили пейлоад, поставили задержку 
                  на <code className="bg-muted px-1 py-0.5 rounded">10 секунд</code> – сервер отвечает на наш запрос{' '}
                  <code className="bg-muted px-1 py-0.5 rounded">10 секунд</code>.
                </li>
              </ul>
            </div>

            <div>
              <H3>3. Out-of-band (OOB)</H3>
              <P>
                БД сам инициирует соединение к внешнему ресурсу <strong>(DNS/HTTP)</strong>. Сложный вид атаки и очень редко 
                встречающийся в реальной жизни. Но на PortSwigger есть несколько задач.
              </P>
            </div>

            <div>
              <H3>4. Second-order</H3>
              <P>
                Полезная нагрузка сохраняется в БД и выполняется позже в другом контексте. Например загружаем файл с <strong>SQL Payload</strong>, 
                а потом мы или кто-то другой его вызывает и он выполняется. Как в примере с <strong>XSS</strong> в{' '}
                <strong>svg</strong> файле в конце статьи.
              </P>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Процесс эксплуатации SQL инъекции</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ol className="list-decimal pl-6 space-y-2">
              <li>Выявление SQL-инъекции;</li>
              <li>Определения типа и версии СУБД;</li>
              <li>Определения имени пользователя и его привилегий;</li>
              <li>Повышения привилегий;</li>
              <li>Эксплуатации уязвимости.</li>
            </ol>
            <P>
              Мы разберемся в первых двух пунктах, они необходимы для того чтобы доказать факт наличия уязвимости. 
              На текущем этапе этого достаточно для заведения баг репорта.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Определение типа и версии СУБД</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Без знания типа и версии СУБД невозможно эксплуатировать SQL-инъекцию и корректно сформировать запрос, 
              который вернет нужную информацию из БД. Это очень важно, не закрытая <code className="bg-muted px-1 py-0.5 rounded">"</code> или{' '}
              <code className="bg-muted px-1 py-0.5 rounded">+</code> не в том месте, может повлиять на интерпритатор и как это будет выполненно или не выполненно БД.
            </P>
            <P>
              Первое, что необходимо сделать – определить используемую для построения web-приложения инфраструктуру и технологию. 
              Например, если применяется технология <strong>ASP.Net</strong> и <strong>IIS</strong>, то, скорее всего, 
              в качестве СУБД используется <strong>Microsoft SQL Server</strong>. Конечно, полностью полагаться на данную информацию нельзя.
            </P>
            <P>
              Если web-приложение выводит сообщение о возникшем исключении при работе с СУБД, можно легко определить тип СУБД. 
              Сообщение об ошибке, начинающееся со слова <code className="bg-muted px-1 py-0.5 rounded">ORA</code>, говорит об 
              использовании <strong>СУБД Oracle</strong>.
            </P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`ORA01773: may not specify column datatypes in this CREATE TABLE`}
              </pre>
            </div>
            <P>
              Поскольку каждая СУБД по разному обрабатывает конкатенацию строк, по этому признаку можно судить о типе СУБД.
            </P>

            <H3>Способ 1:</H3>
            <P>
              Тип БД можно определить по сообщениям об ошибке разные БД имеют разные сообщения об ошибках:
            </P>
            <ol className="list-decimal pl-6 space-y-2">
              <li>
                <strong>Ожидаемый результат для MySQL:</strong>
                <div className="bg-muted p-4 rounded-md mt-2 overflow-x-auto">
                  <pre className="text-sm">
{`Query failed: You have an error in your SQL syntax; check the manual that 
corresponds to your MySQL server version for the right syntax to use near '' at line 1`}
                  </pre>
                </div>
              </li>
              <li>
                <strong>Ожидаемый результат для Oracle:</strong>
                <div className="bg-muted p-4 rounded-md mt-2 overflow-x-auto">
                  <pre className="text-sm">
{`ORA-00933: SQL command not properly ended`}
                  </pre>
                </div>
              </li>
              <li>
                <strong>Ожидаемый результат для MS SQL Server:</strong>
                <div className="bg-muted p-4 rounded-md mt-2 overflow-x-auto">
                  <pre className="text-sm">
{`Microsoft SQL Native Client error '80040e14' Unclosed quotation mark after the character string`}
                  </pre>
                </div>
              </li>
              <li>
                <strong>Ожидаемый результат для PostgreSQL:</strong>
                <div className="bg-muted p-4 rounded-md mt-2 overflow-x-auto">
                  <pre className="text-sm">
{`Query failed: ERROR: syntax error at or near "'" at character 56 in /www/site/test.php on line 121`}
                  </pre>
                </div>
              </li>
            </ol>

            <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-md p-4 mt-4">
              <P className="text-sm mb-2">
                <strong>Важно:</strong> если ошибку не выдало — могут быть следующие причины:
              </P>
              <ol className="list-decimal pl-6 text-sm">
                <li>
                  SQL инъекции здесь нет — Фильтруются кавычки, или просто стоит преобразование в (int)
                </li>
                <li>
                  Отключен вывод ошибок. Узнаем у разработчиков отключали ли они вывод ошибок или тестируем через Blind SQL
                </li>
              </ol>
            </div>

            <H3>Способ 2:</H3>
            <P>
              Можем попробовать запросить у базы данных информацию о ее версии. Эти команды встроены в базу данных, 
              поэтому зачастую это самый простой путь для идентификации. Вот пейлоады:
            </P>
            <ul className="list-none pl-0 space-y-1">
              <li><strong>MySQL:</strong> <code className="bg-muted px-1 py-0.5 rounded">SELECT version()</code></li>
              <li><strong>MS SQL:</strong> <code className="bg-muted px-1 py-0.5 rounded">SELECT @@version</code></li>
              <li><strong>PostgreSQL:</strong> <code className="bg-muted px-1 py-0.5 rounded">SELECT version()</code></li>
              <li><strong>Oracle:</strong> <code className="bg-muted px-1 py-0.5 rounded">SELECT version FROM v$instance</code> or <code className="bg-muted px-1 py-0.5 rounded">SELECT FROM PRODUCT_COMPONENT_VERSION</code></li>
            </ul>
            <P><strong>Пример:</strong></P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`http://www.exampleurl.com/product.php?id=4 UNION SELECT version()`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Способы поиска уязвимости</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Первым шагом в процессе выявления SQL-инъекции является определение способов передачи данных в web-приложение:
            </P>
            <ol className="list-decimal pl-6 space-y-2">
              <li>Параметров, передаваемых при помощи <strong>GET/POST</strong> и реже <strong>PUT/PATCH</strong>-методов;</li>
              <li>Значений, содержащихся в <strong>Cookie</strong>;</li>
              <li>Параметров HTTP-заголовка (таких как <strong>Referer</strong> и <strong>UserAgent</strong>).</li>
            </ol>
            <P>
              После определения входных параметров необходимо определить корректность обработки их web-приложением. 
              Модифицируя входные параметры, необходимо добиться возникновения исключения в web-приложении, результатом 
              которого будет сообщение о возникшем исключении либо некорректно отображенная страница или ответ, содержащий 
              неполные (избыточные) данные. То есть, добавляем кавычки {'→'} отправляем запрос {'→'} смотрим ответ.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Способы защиты</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ol className="list-decimal pl-6 space-y-3">
              <li>
                <strong>Используйте безопасный API, исключающий применение интерпретатора или предоставляющий 
                параметризованный интерфейс, либо используйте инструменты объектно-реляционного отображения (ORM)</strong>.
                <P className="text-sm mt-2">
                  <em>Примечание:</em> даже параметризованные хранимые процедуры могут привести к SQL-внедрениям, если PL/SQL или T-SQL 
                  позволяют присоединять запросы и данные или выполнять вредоносный код с помощью EXECUTE IMMEDIATE или exec().
                </P>
              </li>
              <li>
                <strong>Реализуйте на сервере белые списки для проверки входных данных</strong>. Это, конечно, не обеспечит полную защиту, 
                поскольку многие приложения используют спецсимволы, например, в текстовых областях или API для мобильных приложений.
              </li>
              <li>
                Для остальных динамических запросов <strong>реализуйте экранирование спецсимволов</strong>, используя соответствующий 
                интерпретатору синтаксис.
                <P className="text-sm mt-2">
                  <em>Примечание:</em> элементы SQL-структуры, такие как названия таблиц или столбцов, нельзя экранировать, поэтому 
                  предоставляемые пользователями названия представляют опасность. Это обычная проблема программ для составления отчетов.
                </P>
              </li>
              <li>
                <strong>Используйте в запросах LIMIT</strong> или другие элементы управления SQL для предотвращения утечек данных.
              </li>
              <li>
                Наиболее надежным способом предотвращения SQL-инъекций является <strong>использование параметризированных SQL-параметров</strong>. 
                К примеру, в случае с PHP это возможно с помощью пакета PEAR's DB, предлагающего интерфейс для выполнения абсолютно 
                безопасных SQL-выражений. Обращение к БД происходит следующим образом:{' '}
                <code className="bg-muted px-1 py-0.5 rounded">$p = $db-&gt;prepare("SELECT * FROM users WHERE id = ?"); $db-execute($p, array($_GET['id']))</code>. 
                Основная идея заключается в том, что если позиция параметров явно задана, то можно абсолютно безопасно передавать SQL-запросы базе данных, 
                исключая возможность для параметров самим стать SQL-выражениями (в том числе зловредными). Стоит заметить, что другие механизмы, 
                такие как использование принудительного приведения типов (например, с помощью функции <strong>intval()</strong>) в связке с 
                экранированием строк такими функциями, как <strong>mysql_real_escape_string()</strong> или <strong>addslashes()</strong>, 
                не являются абсолютно безопасными. Проблема в том, что существуют некоторые варианты для их обхода, а следовательно, 
                к их использованию необходимо подходить с максимальным вниманием.
              </li>
            </ol>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Полезный инструментарий</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <H3>1. Repeater</H3>
              <P>
                Конечно же <strong>Repeater</strong> – в современных веб-приложениях зачастую нет смысла сканить автоматическими 
                сканерами каждый параметр или предполагаемый хедер. Во-первых, сработает WAF, во-вторых нас может заблокировать 
                на какое-то время и третье самое главное – займет очень много времени, а профита может не оказаться. Ставим кавычки, 
                исследуем приложение, смотрим как отвечает и какие статусы ответа от сервера мы получаем. Также, можем попробовать 
                добавить простой Payload и проверить как ответит тот-же WAF.
              </P>
            </div>

            <div>
              <H3>2. sqlmap</H3>
              <P>
                <strong>sqlmap</strong> – мощнейший инструмент для обнаружения, эксплуатации и извлечения данных. 
                Имеет широкий функционал. <strong>Предустановлен в Kali Linux</strong>.
              </P>
              <P>Некоторые флаги ниже:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`sqlmap -u "URL" [options]

sqlmap -u "https://target/page.php?id=1" --batch
# batch работает как -y в Unix системах. То есть на все говорим Yes.

-p              # указываем необходимый параметр (например email)
--cookie        # передать cookie
--headers       # дополнительные хедеры
-r              # копируем весь запрос из Burp, сохраняем его как например sql_reset_password.txt
                # и после запускаем: sqlmap -r sql_reset_password.txt

--technique=BEUSTQ   # какие техники разрешены (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
--level         # глубина тестирования (1–5). Больше = более агрессивно.
--risk          # риск payload'ов (1–3). Больше = рискованнее.
--threads       # сколько потоков для ускорения (для некоторых тестов).`}
                </pre>
              </div>
              <P>
                И т.д.. Только добавлю, что функционал настолько широк, что даже позволяет получить <strong>shell и командное управление</strong>.
              </P>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Домашнее задание</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Если часть задач не получается из-за функционала <strong>Burp Suite Community Edition</strong>, попробуйте использовать{' '}
              <strong>sqlmap</strong> в качестве тренировки.
            </P>
            <P>
              В начале полезно почитать (и в дальнейшем изучить){' '}
              <a 
                href="https://portswigger.net/web-security/sql-injection/cheat-sheet" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                Cheat sheet <ExternalLink className="ml-1 h-4 w-4" />
              </a>{' '}
              по SQL инъекциям. (Возможно, часть теории будет дублироваться в этих теоретических вставках, но тут есть и 
              некоторое расширение теории, поэтому рекомендуем изучить её перед выполнением практических задач)
            </P>

            <ol className="list-decimal pl-6 space-y-4">
              <li>
                Изучаем еще одну статейку о{' '}
                <a 
                  href="https://portswigger.net/web-security/sql-injection" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  SQL injection <ExternalLink className="ml-1 h-4 w-4" />
                </a>{' '}
                и выполняем лабораторные работы:
                <ul className="list-disc pl-6 mt-2 space-y-1">
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection vulnerability in WHERE clause allowing retrieval of hidden data <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/lab-login-bypass" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection vulnerability allowing login bypass <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                </ul>
              </li>

              <li>
                Углубляемся в поиск SQL injection и изучаем{' '}
                <a 
                  href="https://portswigger.net/web-security/sql-injection/union-attacks" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  UNION attacks <ExternalLink className="ml-1 h-4 w-4" />
                </a>, выполняем лабораторные:
                <ul className="list-disc pl-6 mt-2 space-y-1">
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection UNION attack, determining the number of columns returned by the query <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection UNION attack, finding a column containing text <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection UNION attack, retrieving data from other tables <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                </ul>
              </li>

              <li>
                Не всегда результат инъекции будет отображаться, поэтому нам также важно уметь находить{' '}
                <a 
                  href="https://portswigger.net/web-security/sql-injection/blind" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  blind инъекции <ExternalLink className="ml-1 h-4 w-4" />
                </a>:
                <ul className="list-disc pl-6 mt-2 space-y-1">
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/blind/lab-time-delays" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      Blind SQL injection with time delays <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                </ul>
              </li>

              <li>
                Теперь будем собирать{' '}
                <a 
                  href="https://portswigger.net/web-security/sql-injection/examining-the-database" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  информацию о базе данных с помощью SQL injection <ExternalLink className="ml-1 h-4 w-4" />
                </a>{' '}
                и выполнять лабораторные:
                <ul className="list-disc pl-6 mt-2 space-y-1">
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection attack, querying the database type and version on Oracle <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection attack, querying the database type and version on MySQL and Microsoft <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                </ul>
              </li>

              <li>
                Задачи со <strong>*</strong>, в них нужно получить информацию из базы данных. Для таких задач мы обычно используем{' '}
                <strong>SQLmap</strong>, но также полезно уметь вытаскивать БД вручную:
                <ul className="list-disc pl-6 mt-2 space-y-1">
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection attack, listing the database contents on non-Oracle databases <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection attack, listing the database contents on Oracle <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                  <li>
                    <a 
                      href="https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-primary hover:underline inline-flex items-center"
                    >
                      SQL injection UNION attack, retrieving multiple values in a single column <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </li>
                </ul>
              </li>
            </ol>
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
      </div>
    </ContentPageLayout>
  );
}
