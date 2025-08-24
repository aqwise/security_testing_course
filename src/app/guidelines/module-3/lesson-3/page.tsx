'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import Link from 'next/link';
import { cn } from '@/lib/utils';
import { FlaskConical, CheckCircle2, XCircle, ScrollText, BookOpen, KeyRound, ShieldAlert, Fingerprint, Target } from 'lucide-react';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sourcesData = [
    { id: 1, text: "Lab: Unprotected admin functionality - PortSwigger", url: "https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality" },
    { id: 2, text: "Access control vulnerabilities and privilege escalation - PortSwigger", url: "https://portswigger.net/web-security/access-control" },
    { id: 3, text: "WAHH - Глава 8" },
    { id: 4, text: "Lab: Unprotected admin functionality with unpredictable URL", url: "https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url" },
    { id: 5, text: "Lab: User role controlled by request parameter", url: "https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter" },
    { id: 6, text: "Lab: User role can be modified in user profile", url: "https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile" },
    { id: 7, text: "Lab: User ID controlled by request parameter", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter" },
    { id: 8, text: "Lab: User ID controlled by request parameter, with unpredictable user IDs", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids" },
    { id: 9, text: "Lab: User ID controlled by request parameter, with data leakage in redirect", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect" },
    { id: 10, text: "Lab: User ID controlled by request parameter, with password disclosure", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure" },
    { id: 11, text: "Lab: Insecure direct object references", url: "https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references" },
    { id: 12, text: "Lab: Multi-step process with no access control on one step", url: "https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step" },
    { id: 13, text: "Lab: Referer-based access control", url: "https://portswigger.net/web-security/access-control/lab-referer-based-access-control" },
];

const quizQuestions = [
    { question: "Какой из сценариев является примером вертикального повышения привилегий?", answers: ["Пользователь А видит заказы пользователя Б.", "Обычный пользователь получает доступ к панели администратора.", "Пользователь обходит этап оплаты в интернет-магазине.", "Пользователь крадет cookie сессии другого пользователя."], correctAnswerIndex: 1 },
    { question: "Что такое IDOR (Insecure Direct Object Reference)?", answers: ["Уязвимость, позволяющая выполнять произвольный код на сервере.", "Уязвимость, при которой приложение использует идентификатор объекта от клиента без проверки прав доступа.", "Метод шифрования данных.", "Атака, направленная на отказ в обслуживании."], correctAnswerIndex: 1 },
    { question: "Почему 'безопасность через неясность' (security through obscurity) является плохой практикой для защиты админ-панели?", answers: ["Потому что это замедляет работу сайта.", "Потому что злоумышленник может угадать или найти скрытый URL.", "Потому что это требует сложных настроек сервера.", "Потому что это несовместимо с HTTPS."], correctAnswerIndex: 1 },
    { question: "В приложении есть двухэтапный процесс смены email. На первом шаге проверяется пароль, на втором — меняется email. В чем может быть уязвимость?", answers: ["Пароль может быть слишком простым.", "Злоумышленник может пропустить первый шаг и напрямую вызвать второй.", "Сервер может не поддерживать двухэтапные процессы.", "Email может быть недействительным."], correctAnswerIndex: 1 },
    { question: "Какой HTTP-метод обычно используется для запроса данных, но может быть ошибочно разрешен для выполнения действий, если контроль доступа настроен неправильно?", answers: ["POST", "DELETE", "GET", "OPTIONS"], correctAnswerIndex: 2 },
    { question: "Пользователь видит в URL /view?file=report_2023.pdf. Какую первую вещь он должен попробовать для проверки горизонтального контроля доступа?", answers: ["Изменить 'view' на 'edit'.", "Изменить 'report_2023.pdf' на 'report_2022.pdf'.", "Удалить параметр 'file'.", "Закодировать URL в Base64."], correctAnswerIndex: 1 },
    { question: "Что такое 'матрица контроля доступа'?", answers: ["Способ шифрования.", "Таблица, сопоставляющая роли пользователей с их правами на объекты.", "Файл конфигурации веб-сервера.", "Алгоритм для генерации токенов."], correctAnswerIndex: 1 },
    { question: "Какой заголовок HTTP может быть использован для обхода слабого контроля доступа, основанного на проверке источника запроса?", answers: ["User-Agent", "Accept-Language", "Referer", "Cookie"], correctAnswerIndex: 2 },
    { question: "Принцип 'наименьших привилегий' означает, что...", answers: ["Пользователи должны иметь как можно меньше прав.", "Пользователь должен иметь минимально необходимый набор прав для выполнения своих задач.", "Все пользователи по умолчанию являются гостями.", "Привилегии должны выдаваться только администраторам."], correctAnswerIndex: 1 },
    { question: "Какой инструмент в Burp Suite наиболее полезен для сравнения содержимого сайта, доступного двум разным пользователям?", answers: ["Intruder", "Repeater", "Comparer", "Decoder"], correctAnswerIndex: 2 },
    { question: "Обнаружение файла robots.txt со строкой 'Disallow: /admin-panel' является...", answers: ["Признаком хорошей безопасности.", "Утечкой информации, раскрывающей потенциальный путь к админ-панели.", "Стандартной практикой, не влияющей на безопасность.", "Ошибкой конфигурации сервера."], correctAnswerIndex: 1 },
    { question: "Если приложение хранит роль пользователя в cookie (например, role=user), какой вектор атаки наиболее вероятен?", answers: ["SQL-инъекция", "XSS", "Изменение значения cookie на role=admin.", "Перебор пароля."], correctAnswerIndex: 2 },
    { question: "Что является лучшим способом защиты статических файлов (например, PDF-отчетов) от несанкционированного доступа?", answers: ["Хранить их в директории с трудно угадываемым названием.", "Хранить их вне веб-корня и выдавать через скрипт, который проверяет права доступа.", "Защищать файлы паролем на уровне ZIP-архива.", "Разрешать доступ только с определенных IP-адресов."], correctAnswerIndex: 1 },
    { question: "Какая из уязвимостей НЕ является уязвимостью контроля доступа?", answers: ["Вертикальное повышение привилегий.", "Горизонтальное повышение привилегий.", "Межсайтовый скриптинг (XSS).", "Обход бизнес-логики."], correctAnswerIndex: 2 },
    { question: "Принцип 'отказ по умолчанию' (deny by default) означает...", answers: ["Приложение должно отказывать в доступе, если пользователь не из белого списка IP.", "Любой доступ, который явно не разрешен, должен быть запрещен.", "Приложение должно всегда возвращать ошибку 403.", "Пользователи по умолчанию не имеют никаких прав."], correctAnswerIndex: 1 }
];

interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
}

const QuizItem: React.FC<QuizItemProps> = ({ question, answers, correctAnswerIndex }) => {
  const [selectedAnswer, setSelectedAnswer] = React.useState<number | null>(null);

  const handleAnswerClick = (index: number) => {
    setSelectedAnswer(index);
  };

  const isAnswered = selectedAnswer !== null;

  return (
    <div className="mb-6 p-4 border rounded-lg bg-card shadow-sm">
      <p className="font-semibold text-foreground mb-3">{question}</p>
      <ul className="space-y-2">
        {answers.map((answer, index) => {
          const isCorrect = index === correctAnswerIndex;
          const isSelected = selectedAnswer === index;
          
          let itemClass = "cursor-pointer p-2 rounded-md transition-colors duration-200 border border-transparent";
          if (isAnswered) {
            if (isCorrect) {
              itemClass = cn(itemClass, "bg-green-100 dark:bg-green-900/30 border-green-500 text-green-800 dark:text-green-300 font-medium");
            } else if (isSelected) {
              itemClass = cn(itemClass, "bg-red-100 dark:bg-red-900/30 border-red-500 text-red-800 dark:text-red-300");
            } else {
               itemClass = cn(itemClass, "text-muted-foreground");
            }
          } else {
            itemClass = cn(itemClass, "hover:bg-accent hover:text-accent-foreground");
          }

          return (
            <li
              key={index}
              onClick={() => !isAnswered && handleAnswerClick(index)}
              className={itemClass}
            >
              <span className="mr-2">{String.fromCharCode(97 + index)})</span>{answer}
              {isAnswered && isSelected && !isCorrect && (
                  <span className="text-xs ml-2 text-red-600 dark:text-red-400">(Неверно)</span>
              )}
               {isAnswered && isCorrect && (
                  <span className="text-xs ml-2 text-green-700 dark:text-green-400 font-bold">(Правильный ответ)</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
};


export default function Module3Lesson3Page() {
  return (
    <ContentPageLayout
      title="Урок 3: Атаки на контроль доступа"
      subtitle="Модуль III: Атаки на Ключевые Механизмы Приложения"
    >
        <H2 id="theory">Теория</H2>
        <P>Контроль доступа – это механизм, определяющий, какие действия и ресурсы разрешены для конкретных пользователей. Он работает на основе аутентификации (определения личности пользователя) и управления сессиями (отслеживания пользователя между запросами). После того как приложение знает, кто вы, и поддерживает вашу сессию, задача контроля доступа – решить, что вам позволено делать и к чему вы можете обращаться.</P>
        
        <H3>Типы уязвимостей контроля доступа</H3>
        <P>Контроль доступа делится на три категории: вертикальный, горизонтальный и контекстно-зависимый (бизнес-логический):</P>
        <div className="grid md:grid-cols-3 gap-6 my-6">
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Вертикальный</CardTitle>
                    <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className="text-lg font-bold">Повышение привилегий</div>
                    <p className="text-xs text-muted-foreground">
                        Обычный пользователь получает доступ к функциям администратора.
                    </p>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Горизонтальный</CardTitle>
                    <Fingerprint className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className="text-lg font-bold">Доступ к чужим данным</div>
                    <p className="text-xs text-muted-foreground">
                        Пользователь получает доступ к ресурсам другого пользователя на том же уровне.
                    </p>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Контекстно-зависимый</CardTitle>
                    <Target className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <div className="text-lg font-bold">Обход бизнес-логики</div>
                    <p className="text-xs text-muted-foreground">
                        Пользователь нарушает задуманный порядок действий (например, пропускает оплату).
                    </p>
                </CardContent>
            </Card>
        </div>
        <P>Замечание: Все три типа уязвимостей сводятся к одному: пользователь делает то, что не должен иметь возможности сделать. Различаются только сценарии и методы эксплуатации.</P>
        <P>Нарушение контроля доступа может иметь каскадный эффект. Например, удачная горизонтальная атака часто ведет к вертикальной: получив доступ к чужой учетной записи, злоумышленник может взять на прицел аккаунт с повышенными правами. Классический случай – сначала через уязвимость доступа сменить пароль другого пользователя, а затем захватить учетную запись администратора.</P>
        
        <H3>Распространённые уязвимости и ошибки реализации</H3>
        <P>Большинство проблем с контролем доступа возникают из-за ошибок разработчиков при внедрении проверок. Ниже перечислены распространённые уязвимости контроля доступа:</P>
        <Ul items={[
            `Полностью незащищённая функциональность. В приложении есть скрытые разделы (например, админ-панель), которые не отображаются обычным пользователям, но никак не защищены на сервере. Если злоумышленник узнает или угадает адрес (/admin, /administrator-panel), он получит к ним доступ. Пример: Файл robots.txt может содержать строку Disallow: /admin – этот запрет для поисковых ботов невольно раскрывает путь к админ-разделу.<Link href="#source-1" className={LinkStyle}><sup className="align-super text-xs">1</sup></Link>`,
            `Функции, основанные на идентификаторах (IDOR). Приложение использует переданный от клиента идентификатор ресурса (ID объекта) без надлежащей проверки прав. Злоумышленник может подставить чужой ID и получить доступ к чужим данным. Пример: /profile?user_id=123.`,
            `Многоэтапные процессы без полноценных проверок. Разработчики проверяют права только на первых шагах, предполагая, что до завершающего шага пользователь дойдет легитимно. Злоумышленник может пропустить начальные шаги и отправить запрос непосредственно на финальный URL.`,
            `Контроль доступа на стороне клиента. Приложение полагается на JavaScript для контроля доступа, скрывая или показывая элементы интерфейса. Злоумышленник может легко обойти это, изменив код в браузере или отправив запрос напрямую на сервер.`,
            `Небезопасная конфигурация веб-сервера. Ограничения доступа могут быть неверно настроены на уровне веб-сервера (например, ограничение только для метода POST, но не для GET).`,
            `Хранение роли в изменяемом параметре. Роль пользователя хранится в cookie или скрытом поле формы, и злоумышленник может изменить значение с 'user' на 'admin'.`
        ]} />

        <H2 id="demo">Демонстрация</H2>
        <Card className="my-6 border-accent/50">
            <CardHeader>
                <CardTitle className="flex items-center text-accent-foreground">
                    <BookOpen className="mr-2 h-5 w-5" />
                    Кейс 1: Вертикальное повышение привилегий
                </CardTitle>
                <CardDescription>Доступ к скрытой админ-панели</CardDescription>
            </CardHeader>
            <CardContent>
                <P><strong>Сценарий:</strong> В приложении имеется административный раздел по адресу /admin. Ссылку на него видят только администраторы. Однако разработчики не внедрили проверку прав при открытии этой страницы, полагаясь на то, что «если нет ссылки, никто не найдет».</P>
                <P><strong>Атака:</strong> Злоумышленник, обладая обычным аккаунтом, вручную переходит по URL /admin и обнаруживает, что страница загружается. Он получает полный доступ к админ-интерфейсу.</P>
                <P><strong>Уязвимость:</strong> Админ-панель была полностью незащищена на уровне сервера. UI скрывал ее, что не является защитой.</P>
                <P><strong>Защита:</strong> Всегда проверять роль пользователя на сервере при обращении к чувствительным URL, независимо от того, есть ссылка в интерфейсе или нет.</P>
            </CardContent>
        </Card>
        <Card className="my-6 border-accent/50">
            <CardHeader>
                <CardTitle className="flex items-center text-accent-foreground">
                    <BookOpen className="mr-2 h-5 w-5" />
                    Кейс 2: Горизонтальное повышение привилегий (IDOR)
                </CardTitle>
                <CardDescription>Чтение чужих данных</CardDescription>
            </CardHeader>
            <CardContent>
                <P><strong>Сценарий:</strong> В почтовом приложении у каждого пользователя есть страница вида /mailbox?user_id=XXX. Приложение доверяет этому параметру из URL.</P>
                <P><strong>Атака:</strong> Пользователь с ID 1001 замечает в адресной строке user_id=1001 и меняет значение на 1002. Сервер возвращает содержимое почтового ящика пользователя 1002.</P>
                <P><strong>Уязвимость:</strong> Приложение доверяет параметру user_id и не удостоверяется, что запрошенный ящик принадлежит текущему вошедшему пользователю.</P>
                <P><strong>Защита:</strong> Никогда не полагаться на идентификатор ресурса от клиента. Сервер должен извлечь ID пользователя из сессии и использовать только его для выборки данных, либо сверять, что запрашиваемый ID совпадает с ID в сессии.</P>
            </CardContent>
        </Card>

        <H2 id="practice">Практика с PortSwigger</H2>
        <P>
            Для отработки навыков поиска уязвимостей контроля доступа отлично подходят интерактивные лабораторные работы из PortSwigger Web Security Academy.
            Для закрепления материала используйте раздел{' '}
            <Link href="https://portswigger.net/web-security/access-control" target="_blank" rel="noopener noreferrer" className={LinkStyle}>
            Access control vulnerabilities — PortSwigger Academy
            </Link> (теория и все практики).
        </P>
        <Card className="my-6 border-primary/50">
            <CardHeader>
                <CardTitle className="flex items-center text-primary">
                    <FlaskConical className="mr-2 h-5 w-5" />
                    Ключевые лаборатории
                </CardTitle>
            </CardHeader>
            <CardContent>
                <Ul items={[
                    <> <Link href="https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Unprotected admin functionality</Link> {' — '} Не защищённая админская функциональность. <Link href="#source-1" className={LinkStyle}><sup className="align-super text-xs">1</sup></Link></>,
                    <> <Link href="https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User role controlled by request parameter</Link> {' — '} Роль пользователя задаётся параметром запроса. <Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link></>,
                    <> <Link href="https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User ID controlled by request parameter (IDOR)</Link> {' — '} ID пользователя задаётся параметром. <Link href="#source-7" className={LinkStyle}><sup className="align-super text-xs">7</sup></Link></>,
                    <> <Link href="https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Multi-step process with no access control on one step</Link> {' — '} Отсутствие контроля на одном из шагов. <Link href="#source-12" className={LinkStyle}><sup className="align-super text-xs">12</sup></Link></>,
                    <> <Link href="https://portswigger.net/web-security/access-control/lab-referer-based-access-control" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Referer-based access control</Link> {' — '} Контроль доступа на основе Referer. <Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link></>,
                ]} />
            </CardContent>
        </Card>

        <H3>Методики тестирования</H3>
        <div className="overflow-x-auto my-6">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Метод</TableHead>
                        <TableHead>Описание</TableHead>
                        <TableHead>Пример Инструмента</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    <TableRow>
                        <TableCell>Тестирование с разными ролями</TableCell>
                        <TableCell>Сравнить доступные функции для разных ролей (админ vs. юзер) и попытаться получить доступ к админским функциям под юзером.</TableCell>
                        <TableCell>Burp Suite (Site map comparison)</TableCell>
                    </TableRow>
                    <TableRow>
                        <TableCell>Перебор идентификаторов (IDOR)</TableCell>
                        <TableCell>Найти функции, использующие ID (user_id, order_id), и подставить ID других пользователей/объектов.</TableCell>
                        <TableCell>Burp Intruder</TableCell>
                    </TableRow>
                    <TableRow>
                        <TableCell>Атака на многоэтапные процессы</TableCell>
                        <TableCell>Пропустить шаги, отправив запрос напрямую на конечную точку процесса.</TableCell>
                        <TableCell>Burp Repeater</TableCell>
                    </TableRow>
                    <TableRow>
                        <TableCell>Изменение HTTP-метода</TableCell>
                        <TableCell>Попробовать выполнить действие, изменив метод с POST на GET, HEAD и т.д.</TableCell>
                        <TableCell>Burp Repeater</TableCell>
                    </TableRow>
                </TableBody>
            </Table>
        </div>

        <H3>Рекомендации по обеспечению безопасности</H3>
        <P>Чтобы защитить приложение от уязвимостей контроля доступа, придерживайтесь следующих принципов:</P>
        <Ul items={[
            `Не полагайтесь на скрытность. Всегда реализуйте проверку прав на сервере для каждого эндпоинта.`,
            `Не доверяйте данным от клиента. Решения об авторизации должны основываться на достоверной серверной информации (роль из сессии), а не на параметрах от клиента (isAdmin=true).`,
            `Проверяйте права на каждом шаге. Каждая страница/эндпоинт должна сама решать, можно ли этому пользователю её использовать, независимо от того, откуда он пришёл.`,
            `Используйте принцип "Запрещать по умолчанию" (Deny by default).`,
            `Централизуйте контроль доступа. Реализуйте единый компонент или библиотеку для проверок, чтобы избежать разрозненного и противоречивого кода.`
        ]}/>

        <H2 id="quiz">Тест</H2>
        <Card>
            <CardHeader>
                <CardTitle>Тест по теме "Атаки на контроль доступа"</CardTitle>
                <CardDescription>Проверьте свои знания, выбрав правильный вариант ответа.</CardDescription>
            </CardHeader>
            <CardContent>
                {quizQuestions.map((q, index) => (
                    <QuizItem key={index} {...q} />
                ))}
            </CardContent>
        </Card>

        <H2 id="sources">Источники</H2>
        <ol className="list-decimal list-inside space-y-2 text-sm">
            {sourcesData.map(source => (
                <li key={source.id} id={`source-${source.id}`}>
                    {source.url ? (
                        <Link href={source.url} target="_blank" rel="noopener noreferrer" className={LinkStyle}>{source.text}</Link>
                    ) : (
                        source.text
                    )}
                </li>
            ))}
        </ol>

    </ContentPageLayout>
  );
}
