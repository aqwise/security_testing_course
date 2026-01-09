'use client';

import React from 'react';
import { ContentPageLayout } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink } from 'lucide-react';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';
import { getImagePath } from '@/utils/paths';

const P: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({ children, ...props }) => (
  <p className="mb-3 leading-relaxed" {...props}>{children}</p>
);

const H2: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h2 className="text-2xl font-bold mb-4 mt-6" {...props}>{children}</h2>
);

const H3: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h3 className="text-xl font-semibold mb-3 mt-4" {...props}>{children}</h3>
);

export default function Lesson3Page() {

  return (
    <ContentPageLayout
      title="Урок 3: HTML Injection"
      subtitle="Изучение атак HTML Injection: типы, методы тестирования и защита"
    >
      <div className="space-y-6">
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="pt-6">
            <P className="text-sm">
              <strong>Источник материала:</strong> Данный урок основан на материалах из{' '}
              <a
                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4037412233/HTML+Injection"
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
            <P>
              Данный тип уязвимости, как и в случае <strong>XSS</strong>, один из наиболее часто встречающихся,
              и её механика и логика очень схожа. Также, как и в случае ранее — это уязвимость с <strong>клиентской стороны</strong>,
              то есть она может выполниться <strong>только в браузере</strong>.
            </P>
            <P>
              <strong>HTML injection</strong> — это атака, при которой злоумышленник внедряет определенные <strong>HTML-теги</strong>
              и таким образом модифицирует контент страницы. Целью данной атаки является обман пользователей при помощи
              социальной инженерии (например, каким-либо образом заставить пользователя ввести свои данные в форму логина
              и пароля / перейти по ссылке, которой там не должно быть и т.д.)
            </P>
            <P>
              В отличие от <strong>JavaScript Execution</strong>, в данном виде атаки <strong>не используется JavaScript</strong> код.
            </P>
            <P>
              Проще говоря, <strong>HTML injection влияет только на контент страницы</strong>.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Классификация</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <P>Как и в случае с XSS, есть 4 вида:</P>

            <div>
              <H3>1. Отраженный (Reflected)</H3>
              <P>
                Полезная нагрузка отправляется в запросе (GET/POST) и возвращается в ответ сразу же.
                Типично для поисковых строк, параметры URL, сообщения об ошибке и т.д.
              </P>
            </div>

            <div>
              <H3>2. Сохраненный (Stored)</H3>
              <P>
                Полезная нагрузка сохраняется сервером (DB, лог, профиль, комментарий) и затем отображается другим пользователям.
                Более опасен — долговременное воздействие. Например, сайт для скачивания ПО, вставили ссылку и сделали сайт
                похожий на настоящий, пользователь скачал – получил <strong>malware</strong>.
              </P>
            </div>

            <div>
              <H3>3. На стороне клиента (DOM-based)</H3>
              <P>
                Вставка происходит полностью в браузере — JS берёт данные из <em>location/hash/localStorage</em> и вставляет
                в <strong>DOM</strong> без экранирования. Может быть отражённым или сохраняемым по происхождению,
                но уязвимость — в клиентском коде.
              </P>
            </div>

            <div>
              <H3>4. Слепая (Blind)</H3>
              <P>
                Как и в случае с XSS, так же само и работает для HTML. Ниже несколько скринов, чтобы понять логику.
              </P>

              <div className="bg-muted p-4 rounded-md mb-3 mt-3">
                <P className="text-sm mb-2">Отправляем запрос с линкой:</P>
                <div className="border-2 border-dashed border-primary/30 rounded p-4 text-center bg-background">
                  <img
                    src={getImagePath('/pics/html-injection-lesson/blind-html-injection-request.png')}
                    alt="Запрос с HTML инъекцией в параметрах"
                    className="max-w-full h-auto mx-auto rounded shadow-md"
                  />
                </div>
              </div>

              <div className="bg-muted p-4 rounded-md mb-3">
                <P className="text-sm mb-2">Далее приходит письмо на почту и мы видим:</P>
                <div className="border-2 border-dashed border-primary/30 rounded p-4 text-center bg-background">
                  <img
                    src={getImagePath('/pics/html-injection-lesson/blind-html-injection-email-result.png')}
                    alt="Email с отображением внедренного HTML"
                    className="max-w-full h-auto mx-auto rounded shadow-md"
                  />
                </div>
              </div>

              <P className="mt-3">
                В данном случае HTML инъекция была в двух параметрах сразу.
              </P>
              <P>
                А что если вместо <strong>Test</strong> и <strong>User_Name</strong> написать:
                <em> "Dear user! We have been detected suspicious activity! Please change your password … Link Here."</em>
              </P>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Выявление HTML инъекций</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ol className="list-decimal pl-6 mb-4 space-y-3">
              <li>
                Собираем и мапим наше целевое приложение, определяем все точки входа (GET/POST).
              </li>
              <li>
                <P className="mb-2">
                  Самый простой способ – добавлять теги <code className="bg-muted px-1 py-0.5 rounded">&lt;h1&gt;Some_test&lt;/h1&gt;</code>,
                  {' '}<code className="bg-muted px-1 py-0.5 rounded">&lt;b&gt;Bold_Text&lt;/b&gt;</code> и др.
                </P>
                <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-md p-3 mt-2">
                  <P className="text-sm mb-0">
                    <strong>⚠️ Важно:</strong> Если в этом есть необходимость логики, как например на <strong>Confluence</strong>,
                    то это бизнес-идея приложения. Главное, чтобы она не позволяла нам, например, с помощью этого редактора
                    изменить страницу, которую не можем (например, при помощи <strong>Broken Access Control</strong>).
                  </P>
                </div>
              </li>
              <li>
                Отправить тег открытия комментария <code className="bg-muted px-1 py-0.5 rounded">&lt;!--</code>,
                что позволит полностью остановить работу, т.к. новые данные будут восприниматься как комментарий к коду.
              </li>
              <li>
                Выделять свои сообщения с помощью специальных тегов{' '}
                <code className="bg-muted px-1 py-0.5 rounded">&lt;h1-3&gt;</code>
                <code className="bg-muted px-1 py-0.5 rounded">&lt;i&gt;</code>
                <code className="bg-muted px-1 py-0.5 rounded">&lt;img&gt;</code>
                <code className="bg-muted px-1 py-0.5 rounded">&lt;button&gt;Click here!&lt;/b&gt;</code> или{' '}
                <code className="bg-muted px-1 py-0.5 rounded">&lt;form&gt;&lt;/form&gt;</code> и др.
              </li>
            </ol>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Домашнее задание</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Практические задачи есть на платформе <strong>bWAPP</strong>. Но её нужно устанавливать локально
              в <strong>VirtualBox</strong> и я не знаю проверенной платформы, где бы это было безопасно.
              Можете выполнить по желанию. Также есть <strong>room</strong> на <strong>TryHackMe</strong>, но там одно задание.
            </P>

            <P>Но прочесть немного статей вам придется :)</P>

            <ol className="list-decimal pl-6 space-y-2">
              <li>
                <a
                  href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  OWASP Testing Guide - HTML Injection <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
              <li>
                <a
                  href="https://infosecwriteups.com/html-injection-to-mass-phishing-5701d495cdc2"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  HTML Injection to Mass Phishing <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
              <li>
                <a
                  href="https://www.youtube.com/watch?v=VLk5QGZUUs0"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  YouTube: HTML Injection Tutorial <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
              <li>
                <a
                  href="https://discover.hubpages.com/technology/HTML-Injection-TryHackMe-OWASPBWA"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  HTML Injection TryHackMe OWASPBWA <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
              <li>
                <a
                  href="https://www.invicti.com/learn/html-injection/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Invicti - Learn About HTML Injection <ExternalLink className="ml-1 h-4 w-4" />
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
                  explanation={q.explanation}
                  link={q.link}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </ContentPageLayout>
  );
}
