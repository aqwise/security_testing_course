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
    { question: "Какое определение лучше всего описывает SQL инъекцию?", answers: ["Руководство по использованию параметризованных запросов", "Уязвимость, позволяющая нарушителю вмешиваться в запросы к базе данных", "Процесс шифрования данных перед отправкой", "Метод аутентификации пользователей"], correctAnswerIndex: 1 },
    { question: "Какова основная причина возникновения инъекционных уязвимостей в веб приложениях?", answers: ["Использование статических запросов к базе данных", "Смешивание кода запроса и пользовательского ввода без должной обработки", "Сервер работает под управлением Linux", "Использование шаблонов ORM"], correctAnswerIndex: 1 },
    { question: "Какой потенциал ущерба существует при успешной SQL инъекции?", answers: ["Только просмотр некритичных данных", "Только изменение внешнего вида сайта", "Просмотр, изменение или удаление данных, выполнение административных команд", "SQL инъекции не приводят к реальному ущербу"], correctAnswerIndex: 2 },
    { question: "В каких местах веб приложения обычно встречается SQL инъекция?", answers: ["Только в формах логина", "Формы ввода, URL параметры, cookie, HTTP заголовки", "Только в файлах конфигурации", "Только в CSS стилях"], correctAnswerIndex: 1 },
    { question: "Какой из нижеперечисленных payload ов может обойти проверку логина?", answers: ["admin'--", "SELECT * FROM users", "<script>alert(1)</script>", "password=guest"], correctAnswerIndex: 0 },
    { question: "Почему использование конструкции 'OR 1=1' в инъекции может быть опасным?", answers: ["Она никогда не возвращает результат", "Она может изменить действие запроса, например, удалить все записи", "Она приводит к синтаксической ошибке", "Она корректно работает только в обновлениях (UPDATE)"], correctAnswerIndex: 1 },
    { question: "Для чего злоумышленник может использовать оператор UNION в SQL инъекции?", answers: ["Для создания новых таблиц", "Для объединения результатов легального и злонамеренного запроса с целью вывести скрытые данные", "Для стирания логов", "Для управления транзакциями"], correctAnswerIndex: 1 },
    { question: "Чем отличается blind SQL инъекция от обычной?", answers: ["Blind означает, что атака выполняется с закрытыми глазами", "При blind нет явного сообщения об ошибке, приходится полагаться на косвенные признаки (истина/ложь, временные задержки)", "Blind использует только UPDATE запросы", "Blind может выполняться только из админ панели"], correctAnswerIndex: 1 },
    { question: "Что такое SQL инъекция второго порядка?", answers: ["Инъекция, которая выполняет запросы только во второй половине дня", "Атака, при которой вредоносная строка сохраняется в базе и выполняется позже в другом контексте", "Атака, которая требует участия двух злоумышленников", "Такого понятия не существует"], correctAnswerIndex: 1 },
    { question: "Что из перечисленного может быть примером инъекции в NoSQL?", answers: ["Использование параметризованного запроса в MongoDB", "Вставка объекта {$ne:null} в поле фильтра", "Использование UNION SELECT в SQLite", "Работа с XSLT шаблонами"], correctAnswerIndex: 1 },
    { question: "Какой тип данных чаще всего подвергается XPath инъекции?", answers: ["Двоичные файлы", "XML документы", "CSV файлы", "Изображения"], correctAnswerIndex: 1 },
    { question: "Какой риск несёт LDAP инъекция?", answers: ["Обход аутентификации и изменение LDAP каталога", "Повышение привилегий на уровне ОС", "Внедрение CSRF", "Ошибка компиляции кода"], correctAnswerIndex: 0 },
    { question: "Какое действие часто используют для выявления SQL инъекций?", answers: ["Вставить символ апострофа (')", "Изменить User Agent на Mozilla", "Удалить cookie", "Изменить порт сервера"], correctAnswerIndex: 0 },
    { question: "Как распознать уязвимость к blind инъекции?", answers: ["Изменяя регистр букв в запросе", "Добавляя условие 'AND 1=1' и 'AND 1=2' и сравнивая ответы", "Изменяя язык браузера", "Подставляя правильный пароль"], correctAnswerIndex: 1 },
    { question: "Как работает time based blind SQL инъекция?", answers: ["Она выводит данные мгновенно", "Она использует временную задержку в запросе для определения истинности выражения", "Она отправляет запросы только в течение часа", "Она требует отключения брандмауэра"], correctAnswerIndex: 1 },
    { question: "Что характеризует Out of band SQL инъекцию?", answers: ["Результат приходит через другой канал, например, DNS или HTTP запрос", "Используется только в локальных сетях", "Она не требует веб приложения", "Это просто другое название time based инъекции"], correctAnswerIndex: 0 },
    { question: "Как атакующий может определить количество столбцов при UNION инъекции?", answers: ["С помощью команды DROP TABLE", "Постепенно увеличивая количество NULL в UNION SELECT до тех пор, пока запрос не перестанет выдавать ошибку", "Изменяя размер пакета TCP", "Изменяя куку сессии"], correctAnswerIndex: 1 },
    { question: "Какой SQL оператор используется для изменения существующих записей?", answers: ["INSERT", "SELECT", "UPDATE", "DELETE"], correctAnswerIndex: 2 },
    { question: "Какой оператор позволяет злоумышленнику удалить записи через SQL инъекцию?", answers: ["MERGE", "SELECT", "INSERT", "DELETE"], correctAnswerIndex: 3 },
    { question: "Как злоумышленник может вывести скрытое поле, используя SQL инъекцию?", answers: ["Закомментировать конец запроса и добавить собственный SELECT", "Изменить цвет текста на странице", "Сменить пароль на сервере", "Удалить скрытое поле в HTML"], correctAnswerIndex: 0 },
    { question: "Какой метод защиты является наиболее эффективным против SQL инъекций?", answers: ["Проверка IP адреса пользователя", "Параметризованные запросы (prepared statements)", "Установка большого таймаута подключения", "Сжатие ответа сервера"], correctAnswerIndex: 1 },
    { question: "Что включает в себя корректная валидация входных данных?", answers: ["Принимать все символы без ограничений", "Использовать whitelist проверку и ограничения по длине", "Заменять все буквы на заглавные", "Удалять все пробелы"], correctAnswerIndex: 1 },
    { question: "Почему важно запускать базу данных с минимальными привилегиями?", answers: ["Чтобы ускорить выполнение запросов", "Чтобы в случае компрометации атакующий имел минимальный доступ", "Чтобы можно было использовать больше потоков", "Потому что так требует закон"], correctAnswerIndex: 1 },
    { question: "Как хранимые процедуры могут помочь в защите?", answers: ["Они делают запросы неизменяемыми и уменьшают необходимость конкатенации строк", "Они автоматически шифруют данные", "Они заменяют базу данных", "Они удаляют старые записи"], correctAnswerIndex: 0 },
    { question: "Почему простое экранирование входных данных недостаточно?", answers: ["Невозможно экранировать символы", "Это может быть обходено с помощью разнообразных кодировок", "Экранирование всегда вызывает ошибку", "SQL сервера не поддерживают экранирование"], correctAnswerIndex: 1 },
    { question: "Как WAF может помочь в контексте SQL инъекций?", answers: ["Он полностью исключает необходимость в других мерах защиты", "Он фильтрует известные вредоносные шаблоны, но должен использоваться вместе с другими мерами", "Он отправляет атакующих на другой сервер", "Он шифрует базу данных"], correctAnswerIndex: 1 },
    { question: "Какая разница между динамическими и статическими SQL запросами?", answers: ["Динамические не используют параметры; статические формируются на этапе компиляции", "Динамические всегда безопасны; статические всегда уязвимы", "Нет разницы", "Статические могут выполняться только один раз"], correctAnswerIndex: 0 },
    { question: "Какие типы входов следует проверять на SQL инъекции?", answers: ["Только текстовые поля", "Все места, где данные взаимодействуют с запросами: параметры URL, формы, cookie, HTTP заголовки", "Только файлы загрузки", "Только поля email"], correctAnswerIndex: 1 },
    { question: "Почему следует комбинировать SQL инъекцию с другими уязвимостями (например, XSS)?", answers: ["Чтобы повысить привилегию текста в базе", "Потому что это упрощает эксплуатацию, доступна возможность атаковать разные уровни", "Это не рекомендуется", "Чтобы атакующий устал"], correctAnswerIndex: 1 },
    { question: "Помогают ли ORM фреймворки полностью устранить SQL инъекции?", answers: ["Да, они делают приложения полностью безопасными", "Нет, потому что можно выполнять сырой SQL и допускать ошибки", "Да, но только в Python", "ORM фреймворки не связаны с базами данных"], correctAnswerIndex: 1 },
    { question: "Если при добавлении UNION SELECT возникает ошибка «Неверное количество столбцов», что нужно сделать?", answers: ["Использовать оператор UPDATE", "Подобрать количество столбцов, добавляя NULL значения, пока запрос не будет успешен", "Изменить схему БД", "Сменить браузер"], correctAnswerIndex: 1 },
    { question: "Почему при UNION инъекции важно учитывать типы данных?", answers: ["Потому что база данных сортирует таблицы по алфавиту", "Потому что каждый столбец должен соответствовать типу данных исходного запроса", "Это не имеет значения", "Чтобы изменить кодировку страницы"], correctAnswerIndex: 1 },
    { question: "Какой пример payload а может обойти форму логина?", answers: ["' OR 1=1--", "SELECT username FROM users", "<script>alert(1)</script>", "DROP DATABASE"], correctAnswerIndex: 0 },
    { question: "Какой метод эксплуатации использует вывод ошибок для получения структурной информации о базе?", answers: ["Blind injection", "Error based injection", "Time based injection", "Command injection"], correctAnswerIndex: 1 },
    { question: "Что такое stacked queries (многозапросная инъекция)?", answers: ["Отправка нескольких запросов в одном пакете, разделённых точкой с запятой", "Использование стека памяти", "Сжатие SQL запроса", "Запрос, состоящий только из UNION"], correctAnswerIndex: 0 },
    { question: "Как можно обнаружить инъекцию второго порядка?", answers: ["Проследить, где вводимые данные используются повторно в запросах", "Использовать csrf токен", "Изменить шрифт на странице", "Удалить таблицу sessions"], correctAnswerIndex: 0 },
    { question: "Какая защита подходит против NoSQL инъекций?", answers: ["Принцип подобен SQL: использование параметризованных запросов и жёсткая валидация", "Отказ от использования базы данных", "Сжатие данных", "Переход на XML"], correctAnswerIndex: 0 },
    { question: "Что может сделать атакующий при успешной XPath инъекции?", answers: ["Получить несанкционированный доступ к XML данным", "Запустить вирус", "Изменить сетевые настройки", "Удалить лог файлы на сервере"], correctAnswerIndex: 0 },
    { question: "Как предотвратить LDAP инъекцию?", answers: ["Использовать фильтрацию специальных символов и безопасные API", "Изменить порт LDAP", "Сохранять пароли в открытом виде", "Не использовать каталог"], correctAnswerIndex: 0 },
    { question: "Где находится SQL инъекция в списке OWASP Top 10 (2021)?", answers: ["Не входит в Top 10", "A01 – Broken Access Control", "A03 – Injection", "A10 – Server-Side Request Forgery"], correctAnswerIndex: 2 },
    { question: "Чем отличается SQL инъекция от командной (OS) инъекции?", answers: ["SQL инъекция выполняет системные команды", "Командная инъекция направлена на выполнение команд ОС, а SQL – на манипуляции базой данных", "Нет различий", "SQL инъекция всегда сложнее"], correctAnswerIndex: 1 },
    { question: "Почему стоит использовать DVWA или PortSwigger Labs для практики SQL инъекций?", answers: ["Потому что они представляют реальные сайты клиентов", "Они безопасны, легальны и предоставляют контролируемую среду с задачами", "Их нельзя настроить без платного доступа", "Они удаляют все данные с вашего компьютера"], correctAnswerIndex: 1 },
    { question: "Можно ли с помощью UNION инъекции получить данные из нескольких таблиц?", answers: ["Да, объединив запросы, если количество и типы столбцов совпадают", "Нет, UNION работает только в одной таблице", "Только в MySQL", "Только если база данных пуста"], correctAnswerIndex: 0 },
    { question: "Какую роль играет последовательность -- или # в SQL инъекции?", answers: ["Она завершает выполнение вредоносного кода", "Она комментирует остаток исходного запроса, предотвращая его выполнение", "Она создаёт новую строку", "Не имеет значения"], correctAnswerIndex: 1 },
    { question: "Что означает, если реакция приложения различается на 'AND 1=1' и 'AND 1=2'?", answers: ["Это свидетельство обфускации", "Приложение, вероятно, уязвимо к blind SQL инъекции", "Это свидетельствует об ошибке JavaScript", "Это доказывает отсутствие уязвимости"], correctAnswerIndex: 1 },
    { question: "Какой из шагов является первым при тестировании на SQL инъекцию?", answers: ["Изменение DNS", "Определение потенциальных точек ввода и понимание контекста запроса", "Удаление всех таблиц", "Запуск брандмауэра"], correctAnswerIndex: 1 },
    { question: "Почему параметризованные запросы предпочтительнее экранирования?", answers: ["Потому что экранирование устарело и больше не поддерживается", "Потому что параметры полностью разделяют данные и код, а экранирование может быть обойдёно", "Потому что параметризованные запросы быстрее", "Потому что так проще писать код"], correctAnswerIndex: 1 },
    { question: "Как злоумышленник может изменить несколько полей с помощью инъекции в оператор UPDATE?", answers: ["Добавив SET password='hacked', is_admin=1 после WHERE", "Это невозможно", "Отправив DELETE вместо UPDATE", "Изменив заголовок HTTP Referer"], correctAnswerIndex: 0 },
    { question: "Почему следует скрывать подробные сообщения об ошибках от пользователей?", answers: ["Чтобы сократить время отклика", "Подробные ошибки могут помочь злоумышленнику понять структуру запроса и базы данных", "Ошибки всегда бесполезны", "Это не имеет значения"], correctAnswerIndex: 1 },
    { question: "Как SQL инъекция может повлиять на контроль доступа?", answers: ["Она никак не связана", "Используя инъекцию, можно обойти проверки прав и получить доступ к закрытым данным", "Контроль доступа зависит только от брандмауэра", "Она может только изменить цвет интерфейса"], correctAnswerIndex: 1 }
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