'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import Link from 'next/link';
import { cn } from '@/lib/utils';
import { FlaskConical, CheckCircle2, XCircle, ScrollText, BookOpen, Database, Shield, Search, Target } from 'lucide-react';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sourcesData = [
    { id: 1, text: "SQL injection - PortSwigger Web Security Academy", url: "https://portswigger.net/web-security/sql-injection" },
    { id: 2, text: "Lab: SQL injection vulnerability allowing login bypass", url: "https://portswigger.net/web-security/sql-injection/lab-login-bypass" },
    { id: 3, text: "Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data", url: "https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data" },
    { id: 4, text: "Lab: Blind SQL injection with conditional responses", url: "https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses" },
    { id: 5, text: "WAHH - Глава 9: Атака на хранилища данных" },
    { id: 6, text: "DVWA: SQL Injection", url: "https://github.com/digininja/DVWA" },
    { id: 7, text: "OWASP Juice Shop", url: "https://owasp.org/www-project-juice-shop/" },
    { id: 8, text: "Lab: SQL injection UNION attack", url: "https://portswigger.net/web-security/sql-injection/union-attacks" },
    { id: 9, text: "Lab: SQL injection attack, querying the database type and version", url: "https://portswigger.net/web-security/sql-injection/examining-the-database" },
    { id: 10, text: "NoSQL injection - PortSwigger", url: "https://portswigger.net/web-security/nosql-injection" }
];

const quizQuestions = [
    { question: "Почему атака на хранилища данных позволяет обойти контроль доступа приложения?", answers: ["База данных хранит все данные открыто", "Злоумышленник может изменить логику запросов и получить доступ к любым данным", "Хранилища данных не имеют системы безопасности", "Приложения не проверяют права доступа"], correctAnswerIndex: 1 },
    { question: "Чем интерпретируемые языки отличаются от компилируемых в контексте инъекций?", answers: ["Они работают быстрее", "Код анализируется и выполняется во время выполнения, что позволяет внедрять дополнительные инструкции", "Они более безопасны", "Они не поддерживают переменные"], correctAnswerIndex: 1 },
    { question: "Как работает обход входа с помощью admin'--?", answers: ["Создается новый пользователь admin", "Комментарий -- завершает запрос и игнорирует проверку пароля", "Удаляется таблица пользователей", "Пароль заменяется на admin"], correctAnswerIndex: 1 },
    { question: "Что произойдет при использовании OR 'a'='a' вместо OR 1=1?", answers: ["Ничего не изменится, оба условия всегда истинны", "Возникнет ошибка", "Запрос будет выполняться медленнее", "Условие будет ложным"], correctAnswerIndex: 0 },
    { question: "Какой способ поможет подтвердить SQL-инъекцию, когда приложение не выводит ошибки?", answers: ["Использование математических выражений (1+1=2)", "Временные задержки (SLEEP функции)", "Логические условия с разными ответами", "Все перечисленные"], correctAnswerIndex: 3 },
    { question: "Какие различия в синтаксисе помогают определить тип СУБД?", answers: ["Разные способы конкатенации строк", "Специфические функции баз данных", "Различный синтаксис комментариев", "Все перечисленные"], correctAnswerIndex: 3 },
    { question: "Что такое SQL-инъекция второго порядка?", answers: ["Повторная отправка того же запроса", "Вредоносные данные сохраняются в базе и используются позже в другом месте", "Использование двух разных таблиц", "Атака через два разных параметра"], correctAnswerIndex: 1 },
    { question: "Какой JSON-объект в MongoDB может обойти проверку пароля?", answers: ["{ password: 'admin' }", "{ '$ne': null }", "{ '$eq': true }", "{ 'password': '*' }"], correctAnswerIndex: 1 },
    { question: "Что такое UNION-атака в SQL?", answers: ["Объединение двух таблиц", "Объединение результатов нескольких запросов для извлечения данных из других таблиц", "Создание союза хакеров", "Удаление всех таблиц"], correctAnswerIndex: 1 },
    { question: "Почему использование подготовленных выражений защищает от инъекций?", answers: ["Они работают быстрее", "Они отделяют данные от программных инструкций", "Они шифруют запросы", "Они блокируют все запросы"], correctAnswerIndex: 1 },
    { question: "Какой оператор в XPath может быть использован для инъекции?", answers: ["SELECT", "or '1'='1'", "UPDATE", "DELETE"], correctAnswerIndex: 1 },
    { question: "Что означает фильтр *)(|(uid=*)) в LDAP?", answers: ["Поиск всех пользователей", "Удаление пользователей", "Создание нового пользователя", "Изменение пароля"], correctAnswerIndex: 0 },
    { question: "Какой HTTP-статус обычно указывает на ошибку SQL-инъекции?", answers: ["200 OK", "404 Not Found", "500 Internal Server Error", "403 Forbidden"], correctAnswerIndex: 2 },
    { question: "Как можно обойти фильтр одинарных кавычек в SQL?", answers: ["Использовать двойные кавычки", "Использовать функции ASCII() и CHAR()", "URL-кодирование", "Все перечисленные"], correctAnswerIndex: 3 },
    { question: "Что делает запрос 1+1 в контексте поиска SQL-инъекции?", answers: ["Проверяет математические операции базы данных", "Ничего особенного", "Удаляет данные", "Создает новую таблицу"], correctAnswerIndex: 0 }
];

interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
  onAnswer: (questionIndex: number, answerIndex: number) => void;
  selectedAnswer: number | null;
  showResult: boolean;
  questionIndex: number;
}

function QuizItem({ question, answers, correctAnswerIndex, onAnswer, selectedAnswer, showResult, questionIndex }: QuizItemProps) {
  return (
    <Card className="mb-4">
      <CardHeader>
        <CardTitle className="text-lg">{question}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {answers.map((answer, index) => {
            const isSelected = selectedAnswer === index;
            const isCorrect = index === correctAnswerIndex;
            const showCorrect = showResult && isCorrect;
            const showIncorrect = showResult && isSelected && !isCorrect;

            return (
              <button
                key={index}
                onClick={() => onAnswer(questionIndex, index)}
                disabled={showResult}
                className={cn(
                  "w-full text-left p-3 rounded-lg border transition-colors",
                  isSelected && !showResult && "bg-primary/10 border-primary",
                  showCorrect && "bg-green-100 border-green-500 dark:bg-green-900/20",
                  showIncorrect && "bg-red-100 border-red-500 dark:bg-red-900/20",
                  !showResult && "hover:bg-muted"
                )}
              >
                <div className="flex items-center justify-between">
                  <span>{answer}</span>
                  {showResult && (
                    <span>
                      {isCorrect ? (
                        <CheckCircle2 className="h-5 w-5 text-green-600" />
                      ) : isSelected ? (
                        <XCircle className="h-5 w-5 text-red-600" />
                      ) : null}
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

export default function ModuleThreeLessonFourPage() {
  const [quizAnswers, setQuizAnswers] = React.useState<(number | null)[]>(new Array(quizQuestions.length).fill(null));
  const [showResults, setShowResults] = React.useState<boolean[]>(new Array(quizQuestions.length).fill(false));

  const handleAnswer = (questionIndex: number, answerIndex: number) => {
    const newAnswers = [...quizAnswers];
    newAnswers[questionIndex] = answerIndex;
    setQuizAnswers(newAnswers);

    const newShowResults = [...showResults];
    newShowResults[questionIndex] = true;
    setShowResults(newShowResults);
  };

  const correctAnswersCount = quizAnswers.filter((answer, index) => answer === quizQuestions[index].correctAnswerIndex).length;
  const totalQuestions = quizQuestions.length;

  return (
    <ContentPageLayout 
      title="Урок 4: Атака на хранилища данных"
      description="Изучение SQL-инъекций, NoSQL-атак и других векторов атак на базы данных"
    >
      <div className="space-y-8">
        <section>
          <P>
            Этот урок завершает третий модуль и выходит за рамки аутентификации и управления сессиями. На практике уязвимости часто спрятаны в глубине приложения – в том месте, где код взаимодействует с хранилищем данных. Глава 9 «Атака на хранилища данных» из книги The Web Application Hacker's Handbook описывает типичные векторы атак на SQL‑, NoSQL‑, XPath‑ и LDAP‑базы.
          </P>
        </section>

        <section>
          <H2>1. Почему хранилище данных – ключевая цель</H2>
          <P>
            Почти все веб‑приложения используют хранилища данных для управления информацией: они хранят учетные записи пользователей, права доступа, настройки конфигурации и другие элементы логики приложения. Современные СУБД – это не просто пассивные контейнеры, они содержат сложную бизнес‑логику и доверяют запросам, поступающим от приложения.
          </P>
          <P>
            Если злоумышленник сможет вмешаться во взаимодействие приложения с хранилищем, он сможет извлечь или изменить конфиденциальные данные и обойти контроль доступа. Поэтому цель атакующего – найти способ превратить пользовательский ввод в часть исполняемого кода на языке запросов.
          </P>
        </section>

        <section>
          <H2>2. Интерпретируемые языки и внедрение кода</H2>
          <P>
            Многие языки, используемые для работы с базами (SQL, LDAP, XPath, запросы MongoDB), являются интерпретируемыми: существует компонент времени выполнения, который анализирует строку запроса и выполняет содержащиеся в ней инструкции.
          </P>
          <P>
            Приложение часто формирует такие запросы, используя шаблон и значения, полученные от клиента. Если ввод пользователя смешивается с инструкциями, специально сформированный запрос может выйти за пределы контекста данных и заставить интерпретатор выполнить дополнительный код.
          </P>

          <H3>2.1 Обход входа в систему</H3>
          <P>Простейший пример – форма входа, которая проверяет имя пользователя и пароль, выполняя запрос:</P>
          <CodeBlock code="SELECT id FROM users WHERE username='$username' AND password='$password';" />
          <P>
            Если приложение некорректно обрабатывает ввод, злоумышленник может подставить значение <code>admin'--</code> в поле имени пользователя и произвольный пароль в поле пароля. Подстановка <code>--</code> завершает условие и комментирует остаток запроса, благодаря чему проверка пароля не выполняется.
          </P>
          <P>
            Более универсальная техника – использование условия <code>OR 1=1</code> вместе с пустым именем пользователя: это заставляет запрос вернуть все записи, что также позволяет войти в систему.
          </P>
        </section>

        <section>
          <H2>3. SQL‑инъекция</H2>
          <P>
            SQL‑инъекция – это уязвимость, позволяющая злоумышленнику вмешиваться в запросы к базе данных. При успешной атаке он может просмотреть, изменять или удалять данные, а также выполнять административные операции.
          </P>
          <P>
            Чтобы обнаружить SQL‑инъекцию, атакующий отправляет специальные символы или выражения и наблюдает, как меняется ответ сервера. Простейший тест – добавить одинарную кавычку, двойную кавычку или обратную косую, чтобы выявить синтаксические ошибки.
          </P>

          <H3>3.1 Базовая эксплуатация</H3>
          <P><strong>Извлечение данных:</strong> если результаты запроса возвращаются пользователю (например, список товаров), можно попытаться изменить запрос так, чтобы получить дополнительные строки. Злоумышленник использует комментарий (<code>'--</code>) или условие <code>OR 1=1</code>, чтобы обойти фильтр и отобразить все записи.</P>
          <P><strong>Изменение логики:</strong> для обхода аутентификации используется вариант с <code>admin'--</code> или <code>' OR 1=1--</code>. Важно помнить, что конструкция <code>OR 1=1</code> может изменить и операции обновления/удаления, поэтому следует действовать осторожно.</P>

          <H3>3.2 Внедрение в различные выражения</H3>
          <P>Помимо данных в запросах SELECT, пользовательский ввод часто попадает в другие части SQL‑выражения:</P>
          <Ul items={[
            "**ORDER BY** – если параметр управляет сортировкой, злоумышленник может подставить имя столбца или вложенный подзапрос. Подстановка числа 1, 2, 3 меняет порядок сортировки.",
            "**INSERT, UPDATE и DELETE** – изменение структуры запросов позволяет добавлять, менять или удалять записи. Например, инъекция '; DROP TABLE users;--' может удалить таблицу.",
            "**Union‑атаки** – оператор UNION позволяет объединять результаты нескольких запросов. Если число и тип столбцов совпадают, злоумышленник может внедрить второй запрос и вывести его результаты."
          ]} />

          <CodeBlock code="SELECT author,title,year FROM books WHERE publisher='Wiley' UNION SELECT username,password,uid FROM users--" />

          <H3>3.3 Поиск и подтверждение уязвимости</H3>
          <P>Чтобы определить, насколько глубоко ввод проникает в SQL, тестировщики используют ряд подходов:</P>
          <Ul items={[
            "**Отправка математических выражений:** Вместо числа 2 подставляют 1+1 или 3-1. Если результат не меняется, возможно, база вычисляет выражение.",
            "**Использование функций:** База воспринимает функции ASCII() или CHAR() как числа. Замена 2 на 67-ASCII('A') позволяет обойти фильтры одинарных кавычек.",
            "**URL‑кодирование:** При отправке атакующих строк важно кодировать проблемные символы: & → %26, = → %3d, пробел → %20.",
            "**Логические выводы:** Если приложение не показывает ошибки, можно использовать условия, изменяющие время отклика."
          ]} />

          <H3>3.4 Снятие отпечатков базы данных</H3>
          <P>Разные СУБД по‑разному конкатенируют строки и выполняют функции:</P>
          <Ul items={[
            "**Oracle:** 'serv'||'ices', BITAND(1,1)-BITAND(1,1)",
            "**MS‑SQL:** 'serv'+'ices', @@PACK_RECEIVED-@@PACK_RECEIVED", 
            "**MySQL:** 'serv' 'ices', CONNECTION_ID()-CONNECTION_ID()"
          ]} />

          <H3>3.5 Избежание фильтров и SQL‑инъекция второго порядка</H3>
          <P>
            Некоторые приложения фильтруют одиночные кавычки или опасные ключевые слова, но этого недостаточно. SQL‑инъекция второго порядка означает, что вредоносные данные сохраняются в базе, а потом используются в другом месте приложения.
          </P>
          <P>
            Например, атакующий регистрируется с именем <code>bad'||(select password from users where username='admin')||'</code>, которое безвредно при сохранении, но позже вставляется в отчёт и раскрывает пароль.
          </P>

          <H3>3.6 Продвинутые техники</H3>
          <P>
            Более сложные атаки включают: чтение файлов с сервера, выполнение системных команд через расширенные функции СУБД, туннелирование через базу, использование вызовов xp_cmdshell в MS‑SQL и т. д.
          </P>
        </section>

        <section>
          <H2>4. Внедрение в NoSQL, XPath и LDAP</H2>
          <P>
            Инъекционные атаки не ограничиваются SQL. Многие современные приложения используют NoSQL‑хранилища (MongoDB, CouchDB), XML‑базы и каталоги LDAP.
          </P>

          <Ul items={[
            "**NoSQL (MongoDB):** Типичный запрос имеет вид db.users.find({ username: user, password: pass }). Если параметры передаются как JSON‑строка, можно передать объект { \"$ne\": null }, чтобы условие всегда было истинным.",
            "**XPath:** При запросе //user[username/text()='$user' and password/text()='$pass'] можно ввести admin' or '1'='1 и получить первый узел пользователя.",
            "**LDAP:** Каталоги LDAP используют фильтры вида (uid=$user)(userPassword=$pass). Инъекция *)(|(uid=*)) вернёт всех пользователей."
          ]} />
        </section>

        <section>
          <H2>5. Практика: PortSwigger и DVWA</H2>
          <P>
            Для закрепления материала рекомендуем пройти бесплатные лаборатории PortSwigger Web Security Academy. В каждом упражнении вы получаете тестовое приложение и задание; после решения система проверит ваш ответ.
          </P>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FlaskConical className="h-5 w-5 text-primary" />
                  Лабораторная 4.1
                </CardTitle>
                <CardDescription>SQL‑инъекция: обход входа</CardDescription>
              </CardHeader>
              <CardContent>
                <Ul items={[
                  "Перейдите к упражнению «SQL injection vulnerability allowing login bypass»",
                  "Введите administrator'-- в поле имени пользователя",
                  "Используйте произвольный пароль",
                  "Проанализируйте, как работает SQL-запрос"
                ]} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5 text-primary" />
                  Лабораторная 4.2
                </CardTitle>
                <CardDescription>Получение скрытых данных</CardDescription>
              </CardHeader>
              <CardContent>
                <Ul items={[
                  "Откройте «SQL injection vulnerability in WHERE clause»",
                  "Измените параметр category на ' OR 1=1--",
                  "Попробуйте UNION для вывода других таблиц",
                  "Проанализируйте полученные результаты"
                ]} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5 text-primary" />
                  Лабораторная 4.3
                </CardTitle>
                <CardDescription>Слепая SQL‑инъекция</CardDescription>
              </CardHeader>
              <CardContent>
                <Ul items={[
                  "Найдите «Blind SQL injection with conditional responses»",
                  "Используйте куку отслеживания для инъекции",
                  "Применяйте логические выражения для извлечения данных",
                  "Определите пароль администратора по времени ответа"
                ]} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5 text-primary" />
                  Дополнительная практика
                </CardTitle>
                <CardDescription>DVWA, bWAPP, OWASP Juice Shop</CardDescription>
              </CardHeader>
              <CardContent>
                <Ul items={[
                  "DVWA: SQL Injection - используйте 1' UNION SELECT user,password FROM users--",
                  "DVWA: Blind SQL Injection - определите пароль через SUBSTRING",
                  "OWASP Juice Shop: найдите задачу с SQL‑инъекцией",
                  "Попробуйте полезную нагрузку ' OR TRUE--"
                ]} />
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>6. Тестовые вопросы</H2>
          <P>Проверьте, насколько хорошо вы усвоили материал:</P>
          
          <div className="mb-6">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-medium">
                Прогресс: {quizAnswers.filter(a => a !== null).length} из {totalQuestions}
              </span>
              {quizAnswers.filter(a => a !== null).length === totalQuestions && (
                <span className="text-sm font-medium">
                  Правильных ответов: {correctAnswersCount} из {totalQuestions} 
                  ({Math.round((correctAnswersCount / totalQuestions) * 100)}%)
                </span>
              )}
            </div>
          </div>

          {quizQuestions.map((quiz, index) => (
            <QuizItem
              key={index}
              questionIndex={index}
              question={`${index + 1}. ${quiz.question}`}
              answers={quiz.answers}
              correctAnswerIndex={quiz.correctAnswerIndex}
              onAnswer={handleAnswer}
              selectedAnswer={quizAnswers[index]}
              showResult={showResults[index]}
            />
          ))}
        </section>

        <section>
          <H2>7. Заключение</H2>
          <P>
            Атаки на хранилища данных остаются одним из самых опасных классов уязвимостей. Они являются прямым следствием смешения программных инструкций и пользовательских данных.
          </P>
          <P>
            Вы узнали, как простая ошибка в обработке строк приводит к полному обходу аутентификации, как извлекать скрытые данные с помощью UNION и логических условий, как выявлять уязвимости в ORDER BY, INSERT и UPDATE, а также как определить тип базы данных по косвенным признакам.
          </P>
          <P>
            Не ограничивайтесь SQL – те же принципы применимы к NoSQL, XPath и LDAP. Всегда проверяйте ввод, используйте параметризованные запросы и функции API, отделяющие данные от кода.
          </P>
        </section>

        <section>
          <H2>Источники</H2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">№</TableHead>
                <TableHead>Источник</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sourcesData.map((source) => (
                <TableRow key={source.id}>
                  <TableCell>{source.id}</TableCell>
                  <TableCell>
                    {source.url ? (
                      <Link href={source.url} className={LinkStyle} target="_blank" rel="noopener noreferrer">
                        {source.text}
                      </Link>
                    ) : (
                      source.text
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      </div>
    </ContentPageLayout>
  );
}