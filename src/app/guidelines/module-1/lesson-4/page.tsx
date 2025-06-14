
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import Link from 'next/link';
import { FlaskConical, ShieldCheck, Lightbulb, CheckCircle2, AlertTriangle, HelpCircle } from 'lucide-react';

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

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><Lightbulb className="mr-2 h-6 w-6 text-primary" />A. Цели урока</CardTitle>
        </CardHeader>
        <CardContent>
          <P>К концу этого урока вы сможете:</P>
          <Ul items={[
            "Понимать основные концепции SQL-инъекций и их потенциальное воздействие.",
            "Распознавать различные типы SQL-инъекций.",
            "Вручную эксплуатировать SQL-инъекции для обхода аутентификации и извлечения данных в DVWA на уровнях Low и Medium.",
            "Эксплуатировать SQL-инъекцию для получения несанкционированного доступа в OWASP Juice Shop.",
            "Использовать SQLMap для автоматического обнаружения и эксплуатации SQL-инъекций.",
            "Знать фундаментальные методы защиты от SQL-инъекций."
          ]} />
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><CheckCircle2 className="mr-2 h-6 w-6 text-primary" />B. Необходимые инструменты и подготовка</CardTitle>
        </CardHeader>
        <CardContent>
          <P>Перед началом убедитесь, что у вас настроены и запущены:</P>
          <Ul items={[
            <><strong>Damn Vulnerable Web Application (DVWA):</strong> Развернуто через Docker, как описано в Уроке 2. Убедитесь, что вы можете войти в систему (admin/password) и менять уровни безопасности<Link href="#source-1" className={LinkStyle}><sup className="align-super text-xs">1</sup></Link>.</>,
            <><strong>OWASP Juice Shop:</strong> Развернуто через Docker, как описано в Уроке 3. Убедитесь, что приложение доступно<Link href="#source-4" className={LinkStyle}><sup className="align-super text-xs">4</sup></Link>.</>,
            "<strong>Burp Suite Community Edition:</strong> Установлен и настроен для перехвата трафика браузера, как описано в Уроке 1.",
            <><strong>SQLMap:</strong> Установлен. SQLMap – это мощный инструмент для автоматизации SQL-инъекций<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>.</>,
            "<strong>Веб-браузер:</strong> С настроенным прокси для Burp Suite."
          ]} />
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><HelpCircle className="mr-2 h-6 w-6 text-primary" />C. Краткий обзор SQL-инъекций (SQLi)</CardTitle>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="sqli-what">
              <AccordionTrigger className="text-lg">Что такое SQLi и почему это опасно?</AccordionTrigger>
              <AccordionContent>
                <P>
                  Язык структурированных запросов (SQL) используется для взаимодействия с базами данных. SQL-инъекция (SQLi) – это уязвимость, при которой злоумышленник может внедрить вредоносный SQL-код в запросы, отправляемые приложением к базе данных<Link href="#source-8" className={LinkStyle}><sup className="align-super text-xs">8</sup></Link>. Это происходит, когда приложение некорректно обрабатывает пользовательский ввод и напрямую вставляет его в SQL-запросы.
                </P>
                <P>Последствия успешной SQLi-атаки могут быть разрушительными<Link href="#source-8" className={LinkStyle}><sup className="align-super text-xs">8</sup></Link>:</P>
                <Ul items={[
                  "Обход аутентификации: Получение доступа к системе без валидных учетных данных.",
                  "Несанкционированный доступ к данным: Чтение конфиденциальной информации (личные данные, финансовая информация, пароли).",
                  "Модификация или удаление данных: Изменение или уничтожение важной информации в базе данных.",
                  "Получение контроля над сервером: В некоторых случаях возможно выполнение команд на сервере базы данных и даже на операционной системе."
                ]} />
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="sqli-types">
              <AccordionTrigger className="text-lg">Основные типы SQLi для практики</AccordionTrigger>
              <AccordionContent>
                <Ul items={[
                  <><strong>In-band SQLi (Внутриканальные):</strong> Злоумышленник использует тот же канал для атаки и получения результатов<Link href="#source-11" className={LinkStyle}><sup className="align-super text-xs">11</sup></Link>.</>,
                  <><strong>Error-based SQLi (На основе ошибок):</strong> Злоумышленник вызывает ошибки базы данных, которые раскрывают информацию о ее структуре или данных<Link href="#source-11" className={LinkStyle}><sup className="align-super text-xs">11</sup></Link>.</>,
                  <><strong>UNION-based SQLi (На основе оператора UNION):</strong> Используется оператор UNION для объединения результатов легитимного запроса с результатами вредоносного запроса, позволяя извлечь данные из других таблиц<Link href="#source-11" className={LinkStyle}><sup className="align-super text-xs">11</sup></Link>.</>,
                  <><strong>Inferential SQLi (Слепые/Умозрительные):</strong> Приложение не возвращает данные напрямую. Злоумышленник делает выводы, наблюдая за поведением приложения (изменения на странице, время ответа)<Link href="#source-11" className={LinkStyle}><sup className="align-super text-xs">11</sup></Link>.
                    <Ul items={[
                      "Boolean-based Blind SQLi: Запросы формируются так, чтобы ответ приложения менялся в зависимости от истинности или ложности внедренного условия.",
                      "Time-based Blind SQLi: Внедряются команды, заставляющие базу данных ожидать определенное время, если условие истинно. Время ответа сервера указывает на результат."
                    ]} />
                  </>
                ]} />
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><FlaskConical className="mr-2 h-6 w-6 text-primary" />D. Практическое задание №1: Ручная эксплуатация SQLi в DVWA (Уровень Low)</CardTitle>
          <CardDescription>Научиться обходить аутентификацию и извлекать данные с помощью базовых SQL-инъекций на низком уровне безопасности DVWA.</CardDescription>
        </CardHeader>
        <CardContent>
          <H3>Подготовка:</H3>
          <Ul items={[
            "Войдите в DVWA (admin/password).",
            "Перейдите в раздел \"DVWA Security\" и установите уровень безопасности на \"Low\". Нажмите \"Submit\".",
            "Перейдите на страницу \"SQL Injection\"."
          ]} />
          <Accordion type="single" collapsible className="w-full mt-4">
            <AccordionItem value="task-1-1">
              <AccordionTrigger>Задача 1.1: Обход аутентификации (теоретический пример на основе DVWA)</AccordionTrigger>
              <AccordionContent>
                <P>Хотя страница SQL Injection в DVWA напрямую не является формой входа, принцип обхода аутентификации важен. Представьте, что запрос для проверки логина и пароля выглядит так:</P>
                <CodeBlock code="SELECT * FROM users WHERE username = 'введенное_имя' AND password = 'введенный_пароль';" />
                <P>Если бы поле "User ID" на странице SQL Injection было полем имени пользователя, вы могли бы попробовать:</P>
                <P><strong>Полезная нагрузка:</strong></P>
                <CodeBlock code="admin'--" />
                <P><strong>Результат:</strong> Запрос превратился бы в</P>
                <CodeBlock code="SELECT * FROM users WHERE username = 'admin'--' AND password = '...'" />
                <P>Часть запроса после -- (комментарий SQL) игнорируется, позволяя войти как 'admin' без пароля<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link>.</P>
                <P><strong>Полезная нагрузка:</strong></P>
                <CodeBlock code="' OR '1'='1" />
                <P><strong>Результат:</strong> Запрос мог бы стать</P>
                <CodeBlock code="SELECT * FROM users WHERE username = '' OR '1'='1--' AND password = '...'" />
                <P>Условие 1=1 всегда истинно, что может позволить обойти проверку<Link href="#source-15" className={LinkStyle}><sup className="align-super text-xs">15</sup></Link>.</P>
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="task-1-2">
              <AccordionTrigger>Задача 1.2: Извлечение данных с помощью UNION-based SQLi</AccordionTrigger>
              <AccordionContent>
                <P>На странице "SQL Injection" в DVWA (Low) есть поле "User ID". Когда вы вводите ID, приложение выполняет примерно такой запрос:</P>
                <CodeBlock code="SELECT first_name, last_name FROM users WHERE user_id = 'ВАШ_ВВОД';" />
                <H3>Шаги:</H3>
                <Ul items={[
                  "Проверка функциональности: Введите 1 в поле \"User ID\" и нажмите \"Submit\". Вы должны увидеть имя и фамилию пользователя с ID 1.",
                  <>Определение количества столбцов: Чтобы использовать UNION SELECT, нам нужно знать, сколько столбцов возвращает исходный запрос. Используйте <CodeBlock code="ORDER BY N--" /> для этого.
                    <Ul items={[
                      <>Введите: <CodeBlock code="1' ORDER BY 1--" /> (должно сработать)</>,
                      <>Введите: <CodeBlock code="1' ORDER BY 2--" /> (должно сработать, так как есть first_name и last_name)</>,
                      <>Введите: <CodeBlock code="1' ORDER BY 3--" /> (должна появиться ошибка, так как третьего столбца нет). Это означает, что исходный запрос возвращает 2 столбца<Link href="#source-16" className={LinkStyle}><sup className="align-super text-xs">16</sup></Link>.</>
                    ]} />
                  </>,
                  <>Извлечение данных из таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>: Теперь мы можем попытаться извлечь данные. Мы знаем, что в DVWA есть таблица <code className="font-mono text-sm bg-muted p-1 rounded">users</code> со столбцами <code className="font-mono text-sm bg-muted p-1 rounded">user</code> (имя пользователя) и <code className="font-mono text-sm bg-muted p-1 rounded">password</code> (хэш пароля).
                    <P><strong>Полезная нагрузка:</strong></P>
                    <CodeBlock code="1' UNION SELECT user, password FROM users--" />
                    <P>Введите эту полезную нагрузку в поле "User ID" и нажмите "Submit".</P>
                    <P><strong>Ожидаемый результат:</strong> Вы должны увидеть список имен пользователей и их хешированных паролей из таблицы users, отображенных на странице<Link href="#source-15" className={LinkStyle}><sup className="align-super text-xs">15</sup></Link>.</P>
                  </>,
                  <>Объяснение:
                    <Ul items={[
                      <><CodeBlock code="1'" /> : Закрывает кавычку для user_id и завершает легитимное условие.</>,
                      <><CodeBlock code="UNION SELECT user, password FROM users" />: Добавляет результаты нашего запроса (имена пользователей и пароли) к результатам исходного запроса.</>,
                      <><CodeBlock code="--" />: Комментирует оставшуюся часть исходного SQL-запроса, чтобы избежать синтаксических ошибок.</>
                    ]} />
                  </>,
                  <>(Опционально) Извлечение другой информации: Попробуйте извлечь версию базы данных: <CodeBlock code="1' UNION SELECT @@version, NULL--" />. <CodeBlock code="@@version" /> – переменная, часто содержащая версию СУБД (для MySQL)<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link>. NULL используется, так как нам нужно два столбца.</>
                ]} />
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
        <CardFooter>
          <div className="p-4 bg-muted/50 rounded-lg w-full">
            <h4 className="font-semibold mb-2 text-foreground/90 flex items-center"><HelpCircle className="mr-2 h-5 w-5 text-accent-foreground" />Вопросы для размышления:</h4>
            <Ul items={[
              "Почему важно определить правильное количество столбцов перед использованием UNION SELECT?",
              "Какие еще данные вы могли бы попытаться извлечь из базы данных DVWA, зная структуру таблиц (можно посмотреть через phpMyAdmin, если доступен, или угадывать стандартные имена)?"
            ]} />
          </div>
        </CardFooter>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><FlaskConical className="mr-2 h-6 w-6 text-primary" />E. Практическое задание №2: Ручная эксплуатация SQLi в DVWA (Уровень Medium)</CardTitle>
          <CardDescription>Понять, как базовые меры защиты на среднем уровне DVWA влияют на SQL-инъекции, и попытаться их обойти.</CardDescription>
        </CardHeader>
        <CardContent>
          <H3>Подготовка:</H3>
          <Ul items={[
            "В DVWA перейдите в раздел \"DVWA Security\" и установите уровень безопасности на \"Medium\". Нажмите \"Submit\".",
            "Перейдите на страницу \"SQL Injection\"."
          ]} />
          <Accordion type="single" collapsible className="w-full mt-4">
            <AccordionItem value="task-2-1">
              <AccordionTrigger>Задача 2.1: Анализ защиты и обход фильтров</AccordionTrigger>
              <AccordionContent>
                <P>На среднем уровне DVWA для SQL-инъекций используется выпадающий список для выбора User ID, и запросы отправляются методом POST<Link href="#source-20" className={LinkStyle}><sup className="align-super text-xs">20</sup></Link>. Также применяется функция</P>
                <CodeBlock code="mysql_real_escape_string()" />
                <P>для экранирования спецсимволов.</P>
                <H3>Шаги:</H3>
                <Ul items={[
                  <>Анализ исходного кода (View Source): На странице SQL Injection (Medium) нажмите кнопку "View Source". Обратите внимание на код обработки <CodeBlock code="$_POST['id']" />. Вы увидите, что используется <CodeBlock code="mysql_real_escape_string()" />. Эта функция экранирует специальные символы, такие как одинарная кавычка ('). Также заметьте, что <CodeBlock code="id" /> используется в запросе без кавычек, так как ожидается числовое значение из выпадающего списка.
                    <CodeBlock code={'`$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;"`'} />
                  </>,
                  "Попытка эксплуатации: Поскольку id используется как числовое значение и не обрамляется кавычками в SQL-запросе, экранирование кавычек функцией mysql_real_escape_string() не помешает нам, если мы не будем использовать кавычки в нашей полезной нагрузке.",
                  <>Использование Burp Suite для модификации запроса:
                    <Ul items={[
                      "В Burp Suite перейдите на вкладку \"Proxy\" -> \"Intercept\". Включите перехват (\"Intercept is on\").",
                      "На странице SQL Injection в DVWA выберите любой User ID из списка и нажмите \"Submit\".",
                      "Запрос будет перехвачен в Burp Suite. Найдите параметр id в теле POST-запроса.",
                      <>Измените значение параметра id на следующую полезную нагрузку: <CodeBlock code="1 UNION SELECT user, password FROM users" /> (Обратите внимание: здесь нет кавычек вокруг 1 и нет комментария -- в конце, так как после числового параметра обычно ничего не следует в простом запросе <CodeBlock code="WHERE user_id = $id;" />).</>,
                      "Нажмите \"Forward\" в Burp Suite, чтобы отправить измененный запрос."
                    ]} />
                  </>,
                  "Ожидаемый результат: Вы должны увидеть список имен пользователей и их хешированных паролей, как и на уровне Low."
                ]} />
                <P><strong>Объяснение:</strong> Так как параметр id обрабатывается как число, и в SQL-запросе он не заключен в кавычки,</P>
                <CodeBlock code="mysql_real_escape_string" />
                <P>не мешает инъекции, если мы не используем символы, которые эта функция экранирует (например, кавычки). Мы напрямую внедряем UNION SELECT после числового ID.</P>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
        <CardFooter>
          <div className="p-4 bg-muted/50 rounded-lg w-full">
            <h4 className="font-semibold mb-2 text-foreground/90 flex items-center"><HelpCircle className="mr-2 h-5 w-5 text-accent-foreground" />Вопросы для размышления:</h4>
            <Ul items={[
              "Почему mysql_real_escape_string() не предотвратила эту инъекцию?",
              "Какие еще полезные нагрузки могли бы сработать в данном числовом контексте?"
            ]} />
          </div>
        </CardFooter>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><FlaskConical className="mr-2 h-6 w-6 text-primary" />F. Практическое задание №3: Эксплуатация SQLi в OWASP Juice Shop</CardTitle>
          <CardDescription>Использовать SQL-инъекцию для обхода аутентификации и входа под учетной записью администратора в OWASP Juice Shop.</CardDescription>
        </CardHeader>
        <CardContent>
          <H3>Подготовка:</H3>
          <Ul items={[
            "Убедитесь, что OWASP Juice Shop запущен и доступен по адресу http://localhost:3000.",
            "Перейдите на страницу входа (/#/login)."
          ]} />
          <Accordion type="single" collapsible className="w-full mt-4">
            <AccordionItem value="task-3-1">
              <AccordionTrigger>Задача 3.1: Вход под учетной записью администратора</AccordionTrigger>
              <AccordionContent>
                <P>Это соответствует челленджу "Login Admin" (сложность ⭐⭐) в Juice Shop<Link href="#source-4" className={LinkStyle}><sup className="align-super text-xs">4</sup></Link>.</P>
                <H3>Шаги:</H3>
                <Ul items={[
                  "Анализ формы входа: На странице входа есть поля \"Email\" и \"Password\".",
                  <>Попытка SQL-инъекции для обхода аутентификации:
                    <Ul items={[
                      <>В поле \"Email\" введите следующую полезную нагрузку: <CodeBlock code="' or 1=1--" /></>,
                      "В поле \"Password\" введите любой текст (например, \"password\").",
                      "Нажмите кнопку \"Log in\"."
                    ]} />
                  </>,
                  <>Ожидаемый результат: Вы должны успешно войти в систему под учетной записью администратора (admin@juice-sh.op). Juice Shop также уведомит вас о решении челленджа \"Login Admin\"<Link href="#source-18" className={LinkStyle}><sup className="align-super text-xs">18</sup></Link>.</>
                ]} />
                <P><strong>Объяснение:</strong></P>
                <Ul items={[
                  <><CodeBlock code="'" /> : Закрывает предполагаемую кавычку вокруг значения email в SQL-запросе.</>,
                  <><CodeBlock code="or 1=1" />: Добавляет условие, которое всегда истинно. Если исходный запрос выглядит примерно как <CodeBlock code="SELECT * FROM Users WHERE email = 'ВАШ_EMAIL' AND password = 'ВАШ_ПАРОЛЬ'" />, то с инъекцией он станет <CodeBlock code="SELECT * FROM Users WHERE email = '' or 1=1--' AND password = '...'" />. Условие <CodeBlock code="email = '' or 1=1" /> будет истинным для всех строк, и СУБД, вероятно, вернет первую подходящую запись, которой часто оказывается администратор.</>,
                  <><CodeBlock code="--" />: Комментирует оставшуюся часть SQL-запроса, включая проверку пароля.</>
                ]} />
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
        <CardFooter>
          <div className="p-4 bg-muted/50 rounded-lg w-full">
            <h4 className="font-semibold mb-2 text-foreground/90 flex items-center"><HelpCircle className="mr-2 h-5 w-5 text-accent-foreground" />Вопросы для размышления:</h4>
            <Ul items={[
              "Почему эта полезная нагрузка сработала? Попробуйте представить, как мог бы выглядеть SQL-запрос на стороне сервера.",
              <>Какие еще вариации этой полезной нагрузки вы могли бы попробовать? (например, используя # вместо -- для MySQL, или ' OR 'a'='a<Link href="#source-8" className={LinkStyle}><sup className="align-super text-xs">8</sup></Link>)</>
            ]} />
          </div>
        </CardFooter>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><FlaskConical className="mr-2 h-6 w-6 text-primary" />G. Практическое задание №4: Автоматизация SQLi с помощью SQLMap</CardTitle>
          <CardDescription>Научиться использовать SQLMap для автоматического обнаружения и эксплуатации SQL-инъекций на примере DVWA.</CardDescription>
        </CardHeader>
        <CardContent>
          <H3>Подготовка:</H3>
          <Ul items={[
            "Убедитесь, что DVWA запущено, уровень безопасности установлен на \"Low\".",
            "Откройте терминал или командную строку, где у вас установлен SQLMap."
          ]} />
          <Accordion type="single" collapsible className="w-full mt-4">
            <AccordionItem value="task-4-1">
              <AccordionTrigger>Задача 4.1: Сканирование DVWA (Low) с помощью SQLMap</AccordionTrigger>
              <AccordionContent>
                <H3>Шаги:</H3>
                <Ul items={[
                  <>Получение URL и Cookie:
                    <Ul items={[
                      "В браузере перейдите на страницу \"SQL Injection\" в DVWA (Low).",
                      <>Скопируйте полный URL из адресной строки. Он должен выглядеть примерно так:</>,
                      <CodeBlock code="http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" />,
                      <P>(замените localhost на ваш IP/домен DVWA, если необходимо).</P>,
                      "Откройте инструменты разработчика в браузере (обычно F12), перейдите на вкладку \"Application\" (или \"Storage\"), найдите Cookies для вашего сайта DVWA. Нам нужен PHPSESSID и значение cookie security (которое должно быть low).",
                      <>Пример cookie:</>,
                      <CodeBlock code="PHPSESSID=ваша_длинная_строка_сессии; security=low" />,
                    ]} />
                  </>,
                  <>Запуск SQLMap для обнаружения уязвимости: В терминале выполните следующую команду, подставив ваш URL и cookie:
                    <CodeBlock language="bash" code={'sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" --batch'} />
                    <Ul items={[
                      <><strong>-u "URL":</strong> Указывает целевой URL<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>.</>,
                      <><strong>--cookie="COOKIE_STRING":</strong> Предоставляет cookie для аутентифицированной сессии<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>.</>,
                      "<strong>--batch:</strong> Запускает SQLMap с настройками по умолчанию, не задавая вопросов."
                    ]} />
                  </>,
                  <>Ожидаемый результат: SQLMap проанализирует параметр id и сообщит, что он уязвим к SQL-инъекциям. Он также может определить тип СУБД (MySQL) и возможные типы инъекций<Link href="#source-22" className={LinkStyle}><sup className="align-super text-xs">22</sup></Link>.</>
                ]} />
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="task-4-2">
              <AccordionTrigger>Задача 4.2: Извлечение данных из DVWA (Low) с помощью SQLMap</AccordionTrigger>
              <AccordionContent>
                <H3>Шаги:</H3>
                <Ul items={[
                  <>Получение списка баз данных: Используйте команду:
                    <CodeBlock language="bash" code={'sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" --dbs --batch'} />
                    <P><strong>--dbs:</strong> Указывает SQLMap извлечь список доступных баз данных<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</P>
                    <P><strong>Ожидаемый результат:</strong> SQLMap выведет список баз данных, среди которых должна быть <code className="font-mono text-sm bg-muted p-1 rounded">dvwa</code>.</P>
                  </>,
                  <>Получение списка таблиц из базы данных <code className="font-mono text-sm bg-muted p-1 rounded">dvwa</code>: Используйте команду:
                    <CodeBlock language="bash" code={'sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" -D dvwa --tables --batch'} />
                    <P><strong>-D dvwa:</strong> Указывает целевую базу данных.</P>
                    <P><strong>--tables:</strong> Указывает SQLMap извлечь список таблиц из указанной БД<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</P>
                    <P><strong>Ожидаемый результат:</strong> SQLMap выведет список таблиц в базе <code className="font-mono text-sm bg-muted p-1 rounded">dvwa</code>, включая <code className="font-mono text-sm bg-muted p-1 rounded">users</code> и <code className="font-mono text-sm bg-muted p-1 rounded">guestbook</code>.</P>
                  </>,
                  <>Получение столбцов из таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>: Используйте команду:
                    <CodeBlock language="bash" code={'sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" -D dvwa -T users --columns --batch'} />
                    <P><strong>-T users:</strong> Указывает целевую таблицу.</P>
                    <P><strong>--columns:</strong> Указывает SQLMap извлечь имена столбцов из указанной таблицы<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</P>
                    <P><strong>Ожидаемый результат:</strong> SQLMap выведет столбцы таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code> (например, user_id, first_name, last_name, user, password).</P>
                  </>,
                  <>Извлечение (дамп) данных из таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>: Используйте команду:
                    <CodeBlock language="bash" code={'sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=ВАШ_PHPSESSID; security=low" -D dvwa -T users --dump --batch'} />
                    <P><strong>--dump:</strong> Указывает SQLMap извлечь все данные из указанной таблицы<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</P>
                    <P><strong>Ожидаемый результат:</strong> SQLMap выведет содержимое таблицы <code className="font-mono text-sm bg-muted p-1 rounded">users</code>, включая имена пользователей и хеши их паролей. SQLMap может предложить сохранить хеши для последующего взлома.</P>
                  </>
                ]} />
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
        <CardFooter>
          <div className="p-4 bg-muted/50 rounded-lg w-full">
            <h4 className="font-semibold mb-2 text-foreground/90 flex items-center"><HelpCircle className="mr-2 h-5 w-5 text-accent-foreground" />Вопросы для размышления:</h4>
            <Ul items={[
              "Насколько быстрее SQLMap справился с извлечением данных по сравнению с ручным методом?",
              "Какие еще опции SQLMap вы могли бы исследовать (например, --current-db, --current-user, --os-shell – с осторожностью!)?"
            ]} />
          </div>
        </CardFooter>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><ShieldCheck className="mr-2 h-6 w-6 text-primary" />H. Основы защиты от SQLi</CardTitle>
        </CardHeader>
        <CardContent>
          <P>Хотя этот урок посвящен эксплуатации, важно понимать, как защищаться от SQL-инъекций.</P>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="protection-prepared">
              <AccordionTrigger>Параметризованные запросы (Prepared Statements)</AccordionTrigger>
              <AccordionContent>
                <P>Это наиболее надежный метод. Запрос сначала определяется с плейсхолдерами, а пользовательские данные передаются отдельно. СУБД обрабатывает данные именно как данные, а не как исполняемый код<Link href="#source-10" className={LinkStyle}><sup className="align-super text-xs">10</sup></Link>.</P>
                <P>Пример на PHP (MySQLi)<Link href="#source-24" className={LinkStyle}><sup className="align-super text-xs">24</sup></Link>:</P>
                <CodeBlock language="php" code={'`$stmt = $mysqli->prepare("SELECT * FROM users WHERE user = ?");\n$stmt->bind_param("s", $username); // "s" - строка\n$stmt->execute();`'} />
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="protection-validation">
              <AccordionTrigger>Валидация входных данных</AccordionTrigger>
              <AccordionContent>
                <P>Проверяйте все данные от пользователя на соответствие ожидаемому формату, типу, длине (используйте \"белые списки\")<Link href="#source-8" className={LinkStyle}><sup className="align-super text-xs">8</sup></Link>.</P>
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="protection-privileges">
              <AccordionTrigger>Принцип наименьших привилегий</AccordionTrigger>
              <AccordionContent>
                <P>Учетная запись, используемая приложением для доступа к БД, должна иметь только минимально необходимые права<Link href="#source-10" className={LinkStyle}><sup className="align-super text-xs">10</sup></Link>.</P>
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="protection-escaping">
              <AccordionTrigger>Экранирование спецсимволов</AccordionTrigger>
              <AccordionContent>
                <P>Менее надежный метод, используется, если параметризованные запросы недоступны. Применяйте специфичные для СУБД функции экранирования<Link href="#source-10" className={LinkStyle}><sup className="align-super text-xs">10</sup></Link>.</P>
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="protection-waf">
              <AccordionTrigger>Web Application Firewalls (WAF)</AccordionTrigger>
              <AccordionContent>
                <P>Могут обнаруживать и блокировать известные SQLi-атаки, но не являются панацеей и могут быть обойдены<Link href="#source-10" className={LinkStyle}><sup className="align-super text-xs">10</sup></Link>.</P>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center"><Lightbulb className="mr-2 h-6 w-6 text-primary" />I. Заключение и дальнейшие шаги</CardTitle>
        </CardHeader>
        <CardContent>
          <P>Поздравляем с завершением практического урока по SQL-инъекциям! Вы получили ценный опыт ручной и автоматизированной эксплуатации этой распространенной уязвимости.</P>
          <H3>Ключевые выводы:</H3>
          <Ul items={[
            "SQL-инъекции остаются серьезной угрозой.",
            "Понимание различных техник эксплуатации критически важно для тестировщиков безопасности.",
            "Инструменты вроде SQLMap значительно ускоряют процесс, но ручное понимание остается фундаментальным.",
            "Применение надежных методов защиты, таких как параметризованные запросы, является обязательным для разработчиков."
          ]} />
          <H3>Дальнейшие шаги:</H3>
          <Ul items={[
            <>Продолжайте практиковаться на DVWA (уровни High, Impossible для изучения кода защиты) и OWASP Juice Shop (там много других SQLi-челленджей разной сложности)<Link href="#source-4" className={LinkStyle}><sup className="align-super text-xs">4</sup></Link>.</>,
            "Изучите более продвинутые техники SQLi: слепые инъекции (Boolean-based, Time-based), Out-of-band SQLi.",
            "Глубже изучите возможности SQLMap и других инструментов.",
            <>Исследуйте специфичные для различных СУБД (MySQL, PostgreSQL, SQL Server, Oracle) функции и синтаксис, которые могут быть использованы в SQLi<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link>.</>
          ]} />
          <P>Помните, что все полученные знания должны использоваться этично и только в разрешенных средах для тестирования и обучения.</P>
        </CardContent>
      </Card>

      <H2 id="sources">Источники</H2>
      <ol className="list-decimal list-inside space-y-2 text-sm">
        <li id="source-1">Laboratory Exercise – Cyber Basics – Web Application Security: SQL Injection Lab, <Link href="https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-2">kaakaww/dvwa-docker, <Link href="https://github.com/kaakaww/dvwa-docker" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-3">DVWA command injection (C) - DCC/FCUP, <Link href="https://www.dcc.fc.up.pt/~edrdo/aulas/qses/lectures/lab1/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-4">OWASP Juice Shop, <Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-5">SQLmap: Uncovering and Exploiting SQL Injection Vulnerabilities - Evolve Security, <Link href="https://www.evolvesecurity.com/blog-posts/tools-of-the-trade-your-ally-in-uncovering-sql-injection-vulnerabilities" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-6">Tutorial- SQLmap First we start the web application (Damn Vulnerable Web App), <Link href="http://www.cs.toronto.edu/~arnold/427/16s/csc427_16s/tutorials/sqlmap/SQLMap%20Tutorial.pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-7">Important SQLMap commands - Infosec, <Link href="https://www.infosecinstitute.com/resources/penetration-testing/important-sqlmap-commands/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-8">SQL Injection - OWASP Foundation, <Link href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-9">SQL injection - PortSwigger, <Link href="https://portswigger.net/kb/issues/00100200_sql-injection" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-10">What is a SQL Injection Attack? - CrowdStrike.com, <Link href="https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/sql-injection-attack/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-11">Threats Types of SQL Injection - Packetlabs, <Link href="https://www.packetlabs.net/posts/types-of-sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-12">Error-Based SQL Injection: Risks, Exploitation & Mitigation - Indusface, <Link href="https://www.indusface.com/learning/error-based-sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-13">SQL Injection: Examples, Real Life Attacks & 9 Defensive Measures | Radware, <Link href="https://www.radware.com/cyberpedia/application-security/sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-14">What is SQL Injection (SQLi) and How to Prevent Attacks - Acunetix, <Link href="https://www.acunetix.com/websitesecurity/sql-injection/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-15">SQL injection UNION attacks | Web Security Academy - PortSwigger, <Link href="https://portswigger.net/web-security/sql-injection/union-attacks" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-16">SQL Injection Cheat Sheet - Invicti, <Link href="https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-17">OWASP Juice Shop - TryHackMe, <Link href="https://tryhackme.com/room/owaspjuiceshop" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-18">R-230616904_OWASP_JuiceShop_WebApp - Secure Ideas, <Link href="https://secureideas.com/hubfs/R-230616904_OWASP_JuiceShop_WebApp%20.pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-19">DVWA/vulnerabilities/sqli/index.php at master - GitHub, <Link href="https://github.com/ethicalhack3r/DVWA/blob/master/vulnerabilities/sqli/index.php" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-20">Injection :: Pwning OWASP Juice Shop, <Link href="https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-21">Blind SQL Injections with SQLMap against the DVWA - YouTube, <Link href="https://www.youtube.com/watch?v=joZKlgR1J5A" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-22">SQL Injection - Manual - PHP, <Link href="https://www.php.net/manual/en/security.database.sql-injection.php" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-23">How to prevent SQL Injection Vulnerabilities: How Prepared Statements Work, <Link href="https://www.securityjourney.com/post/how-to-prevent-sql-injection-vulnerabilities-how-prepared-statements-work" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-24">Pwning OWASP Juice Shop - Leanpub, <Link href="https://leanpub.com/juice-shop" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
        <li id="source-25">Introduction - Pwning OWASP Juice Shop, <Link href="https://pwning.owasp-juice.shop/companion-guide/latest/introduction/README.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ссылка</Link></li>
      </ol>
    </ContentPageLayout>
  );
}
