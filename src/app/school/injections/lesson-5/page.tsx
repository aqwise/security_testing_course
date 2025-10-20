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
      subtitle="Источник: QA Wiki — Command Injection"
    >
      <div className="space-y-6">
        <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
          <CardContent className="pt-4">
            <P className="text-sm text-muted-foreground">
              Источник:{' '}
              <a 
                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4040982567/Command+Injection"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                Confluence — Command Injection <ExternalLink className="ml-1 h-3 w-3" />
              </a>
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Теория</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>Command Injection</strong> - это атака, где целью является выполнение произвольных команд 
              в операционной системе сервера через уязвимое приложение. Уязвимости внедрения команд обычно 
              подразделяются на следующие виды:
            </P>
            <ol className="list-decimal pl-6 space-y-3">
              <li>
                <strong>Одноканальное(Inbound)</strong> – уязвимое приложение выводит результаты внедрённой команды, 
                как например XSS или HTML, SQL.
              </li>
              <li>
                <strong>Слепое внедрение команд(Blind)</strong> – yязвимое приложение не выводит результаты 
                внедрённой команды. Сама команда выполняется, но атакующий не имеет возможности увидеть, что 
                конкретно происходит в системе. Но, может понять это по косвенным признакам. Например, отправляя 
                команду на перезагрузку сервака он не увидит, что сервер принял его команду, но по факту он увидит 
                что сервак перегрузился(отключился и потом появился онлайн). Чем-то похоже на внедрение <code>Sleep</code> оператора 
                в <strong>SQL</strong>.
              </li>
            </ol>
            <P>
              Атаки с помощью командной инъекции возможны, когда веб-приложение принимает небезопасные пользовательские 
              данные (формы, куки, заголовки HTTP и т. д.) в системную оболочку. В этой атаке, команды операционной 
              системы предоставляемые атакующим, обычно выполняются с привилегиями уязвимого приложения. Атаки 
              командного внедрения возможны во многом из-за недостаточной проверки входных данных.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Примеры эксплуатации</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Например, при просмотре файла в веб-приложении имя файла часто отображается в URL-адресе. 
              <strong>Perl</strong> позволяет передавать данные из процесса в открытый оператор. Пользователь 
              может просто добавить символ <code>|</code> в конец имени файла.
            </P>
            <P>Пример URL до внесения изменений:</P>
            <div className="bg-muted p-3 rounded-md mb-3">
              <code className="text-sm">http://sensitive/cgi-bin/userData.pl?doc=user1.txt</code>
            </div>
            <P>Пример URL после внесения изменений:</P>
            <div className="bg-muted p-3 rounded-md mb-3">
              <code className="text-sm">http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|</code>
            </div>
            <P>Это изменение выполнит команду <code>/bin/ls</code>.</P>
            <P>
              Для <strong>.PHP</strong> страницы, при добавлении точки с запятой в конец URL-адреса страницы, 
              за которой следует команда операционной системы, будет выполнена команда. При этом, точка с запятой 
              декодируется в <code>%3B</code>. Например:
            </P>
            <div className="bg-muted p-3 rounded-md mb-3">
              <code className="text-sm">http://sensitive/something.php?dir=%3Bcat /etc/passwd</code>
            </div>
            <P>
              Влияние зависит от контекста. Если это контейнер докера, то урон будет меньшим(хотя как всегда есть 
              исключения). Но если на главный сервер, на котором <em>"стоит"</em> веб-приложение, то полный захват 
              сервера. Случай из реальной жизни – сайт WordPress имел библиоткеку, которая имела уязвимость к 
              выполнению команд. Как результат – зашифрованный сервер и майнер на нем.
            </P>
            <P>
              Техники, которые применяются предлагаю прочитать тут{' '}
              <a 
                href="https://hackware.ru/?p=1133"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                Внедрение команд ОС: понятие, эксплуатация, автоматизированный поиск уязвимости - HackWare.ru <ExternalLink className="ml-1 h-3 w-3" />
              </a>
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Способы защиты от Common Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ol className="list-decimal pl-6 space-y-3">
              <li>Избегать прямого вызова команд ОС</li>
              <li>
                <strong>Экранирование спецсимволов:</strong>
                <div className="mt-2 space-y-2">
                  <P>
                    Общий черный список, который будет включен для ввода команд, может быть{' '}
                    <code>| ; & $ {'>'} {'<'} ' \\ ! {'>>'} #</code>
                  </P>
                  <P>
                    Избегайте или фильтруйте специальные символы для windows{' '}
                    <code>( ) {'<'} {'>'} & * ' | =</code>
                  </P>
                  <P>
                    <code>? ; [ ] ^ ~ ! . " % @ / \\ : + ,</code>
                  </P>
                  <P>
                    Избегайте или фильтруйте специальные символы для linux{' '}
                    <code>{'{'} {'}'} ( ) {'<'} {'>'} & * ' | = ? ; [ ] $ – # ~ ! . " % / \\ : + ,</code>
                  </P>
                </div>
              </li>
              <li>Параметризация в сочетании с проверкой входных данных.</li>
              <li>
                Средствами дополнительной защиты принято считать переназначение прав, непосредственно для 
                выполнения конкретных задач (создать изолированные учетные записи с ограниченными правами, 
                которые используюстя только для одной задачи). То есть админу можно, пользователю нет.
              </li>
            </ol>
            <P className="mt-4">
              В современных приложениях и фрейворках, языках программирования и конфигруаций серверов – многое 
              из этого уже запрещенно по дефолту. Но всегда есть человеческий фактор и он решает.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Домашнее задание</CardTitle>
          </CardHeader>
          <CardContent>
            <P>
              Прочитайте{' '}
              <a 
                href="https://portswigger.net/web-security/os-command-injection"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                теорию <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              {' '}и выполните следующие лабораторные работы:
            </P>
            <ol className="list-decimal pl-6 mt-4 space-y-2">
              <li>
                <a 
                  href="https://portswigger.net/web-security/os-command-injection/lab-simple"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  OS command injection, simple case <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
              <li>
                <a 
                  href="https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Blind OS command injection with time delays <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
              <li>
                <a 
                  href="https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Blind OS command injection with output redirection <ExternalLink className="ml-1 h-3 w-3" />
                </a>
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
