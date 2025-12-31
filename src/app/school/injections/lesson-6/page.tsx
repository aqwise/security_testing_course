'use client';

import React from 'react';
import { ContentPageLayout } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink } from 'lucide-react';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

const P: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({ children, ...props }) => (
  <p className="mb-3 leading-relaxed" {...props}>{children}</p>
);

const H2: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h2 className="text-2xl font-bold mb-4 mt-6" {...props}>{children}</h2>
);

const H3: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ children, ...props }) => (
  <h3 className="text-xl font-semibold mb-3 mt-4" {...props}>{children}</h3>
);

export default function Lesson6Page() {
  // quizQuestions moved to separate file

  return (
    <ContentPageLayout
      title="Урок 6: XXE (XML External Entity)"
      subtitle="Источник: QA Wiki — XXE"
    >
      <div className="space-y-6">
        <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
          <CardContent className="pt-4">
            <P className="text-sm text-muted-foreground">
              Источник:{' '}
              <a
                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4041113655/XXE"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                Confluence — XXE <ExternalLink className="ml-1 h-3 w-3" />
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
              <strong>Xml eXternal Entity(XXE)</strong> — уязвимость, когда приложение парсит XML от пользователя
              и по ошибке позволяет этому XML ссылаться на внешние ресурсы (файлы на сервере, URL). Злоумышленник
              вставляет в XML специальную сущность, и парсер грузит её — например, читает <code>/etc/passwd</code> или
              делает запрос на внешний сервер.
            </P>
            <P>
              Причина уязвимости в том, что старые или плохо настроенные XML-процессоры обрабатывают ссылки на
              внешние сущности внутри документов. Эти сущности могут быть использованы для доступа к внутренним
              файлам через обработчики URI файлов, общие папки, сканирование портов, удаленное выполнения кода и
              отказ в обслуживании.
            </P>
            <P>
              В современных веб-приложениях все чаще и больше используются <strong>REST / GraphQL API</strong>, но
              по прежднему остается широко используемым форматом отправки и обработки данных. Даже если данные
              передаются по <strong>REST / GraphQL API</strong>, то мы можем загрузить файл, например в{' '}
              <strong>SVG</strong> формате, <strong>XML парсер ее обработает и выполнит</strong> наш злонамерренный
              запрос:
            </P>
            <div className="bg-muted p-3 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
                {`<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY secret SYSTEM "file:///etc/passwd">
]>
<root>&secret;</root>`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Влияние</CardTitle>
          </CardHeader>
          <CardContent>
            <P>
              Подобные уязвимости могут использоваться для получения данных, выполнения удаленных запросов с сервера,
              сканирования внутренней системы, провоцирования отказа в обслуживании, а также осуществления других атак.
              Последствия для бизнеса зависят от критичности защиты всех уязвимых приложений и данных.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Существует два основных вида</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="list-decimal pl-6 space-y-2">
              <li><strong>Однополосная</strong> – загрузили сущность, один запрос = один ответ.</li>
              <li><strong>Blind(Слепая)</strong> – загрузили сущность, она отработала на VPS сервер или Collaborator.</li>
            </ol>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Процесс эксплуатации</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Злоумышленники могут эксплуатировать уязвимые обработчики XML через загрузку XML или внедрение
              вредоносного контента в XML-документы, используя уязвимый код, зависимости или компоненты.
            </P>
            <P>
              В целях ознакомления можно глянуть статейку{' '}
              <a
                href="https://habr.com/ru/post/325270/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                https://habr.com/ru/post/325270/ <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              , но особо время не тратим, поскольку на данном этапе нам достаточно зафиксировать наличие уязвимости
              без ее эксплуатации.
            </P>
            <P>
              И{' '}
              <a
                href="https://www.securitylab.ru/analytics/491457.php"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                еще одна статья общими штрихами <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              {' '}описывающая процесс эксплуатации уязвимости.
            </P>
            <P>
              Главная задача, как и во всех разделах – понять логику и где это может встречаться в реальных
              веб-приложениях. На практике возможно никогда этого и не будет. Приложения развиваются, приходят новые
              архитектуры и подходы. Монолит заменяется микросервисами, а REST иногда переходит в gRPC.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Способы поиска уязвимости</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <H3>Этап 1:</H3>
            <P>
              Для проверки приложения нам необходимо определить, является ли приложение уязвимым? Для этого изучаем
              приложение и отвечаем сами себе на ряд вопросов. Например какой <strong>Content-Type</strong> поддерживает
              приложение. Для этого можно использовать этот список, для простоты можно <em>"загнать"</em> его в{' '}
              <strong>Intruder</strong>:
            </P>
            <ul className="list-disc pl-6 space-y-1">
              <li><code>application/xml</code></li>
              <li><code>text/xml</code></li>
              <li><code>application/soap+xml</code></li>
              <li><code>application/xhtml+xml</code></li>
              <li><code>application/xml; charset=utf-8</code></li>
              <li><code>text/plain</code> (чтобы проверить автодетект)</li>
              <li><code>application/json</code> (иногда API парсит тело независимо от заголовка)</li>
              <li><code>application/octet-stream</code></li>
              <li><code>multipart/form-data</code> (XML как часть формы)</li>
            </ul>
            <P className="mt-4">
              Приложения и, в частности, веб-службы на основе XML или последующие интеграции могут быть уязвимы для
              атак, если есть один из факторов риска:
            </P>
            <ol className="list-decimal pl-6 space-y-2">
              <li>
                Приложение принимает XML напрямую или загружает XML, особенно из ненадежных источников, или вставляет
                ненадежные данные в документы XML, которые затем анализируются процессором XML.
              </li>
              <li>
                Для любого из процессоров XML в приложении или веб-службах на основе SOAP включены определения типов
                документов (DTD).
              </li>
              <li>
                Если приложение использует SAML для обработки идентификаторов в целях федеративной безопасности или
                единого входа (SSO). SAML использует XML для подтверждения личности и может быть уязвимым.
              </li>
              <li>
                Если приложение использует SOAP до версии 1.2, оно может быть подвержено атакам XXE, если сущности
                XML передаются в инфраструктуру SOAP.
              </li>
              <li>
                Вероятность уязвимости к атакам XXE означает, что приложение уязвимо для атак отказа в обслуживании,
                включая атаку{' '}
                <a
                  href="https://en.wikipedia.org/wiki/Billion_laughs_attack"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  https://en.wikipedia.org/wiki/Billion_laughs_attack <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
            </ol>

            <H3 className="mt-6">Этап 2:</H3>
            <P>
              Следующий шаг для тестирования приложения на наличие уязвимости инъекции XML состоит в попытке вставить
              метасимволы в XML и таким образом повлиять на содержимое этого документа, в случае наличия DDT схемы нужно
              не забывать что итоговый документ должен быть валидным для этой схемы иначе он не подойдет под DDT схему и
              будет ошибка валидации документа, но это не означает что приложение уязвимо к атаке данного типа.
            </P>
            <P>
              <strong>Метасимволы XML:</strong> <code>', " , {'<>'}, {'<!--/-->'}, &, {'<![CDATA[ / ]]>'}, XXE, TAG</code> -
              это набор метасимволов, которые могут помочь в выявлении потенциальных уязвимостей.
            </P>
            <P>
              По завершении этого шага тестер получит некоторую информацию о структуре XML-документа.
            </P>
            <P>
              Можно проверять вставляя в документ уже написанные пейлоады, например{' '}
              <a
                href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#detect-the-vulnerability"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                AllTheThings <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              {' '}которые лежат в интернете. Но помним, что тут вам требуется понимание того как в вашей системе
              устроена работа с XMLфайлами.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Способы защиты от XXE</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="list-decimal pl-6 space-y-3">
              <li>
                По возможности используйте менее сложные форматы данных, такие как JSON, и избегайте сериализации
                конфиденциальных данных.
              </li>
              <li>
                Исправьте или обновите все процессоры и библиотеки XML, используемые приложением или в базовой
                операционной системе. Используйте проверки зависимостей. Обновите SOAP до SOAP 1.2 или выше.
              </li>
              <li>
                Отключите внешнюю сущность XML и обработку DTD во всех синтаксических анализаторах XML в приложении.
              </li>
              <li>
                Реализуйте положительную («белый список») проверку, фильтрацию или очистку входных данных на стороне
                сервера, чтобы предотвратить враждебные данные в документах, заголовках или узлах XML.
              </li>
              <li>
                Убедитесь, что функция загрузки файлов XML или XSL проверяет входящий XML с использованием проверки
                XSD или аналогичной.
              </li>
              <li>
                Инструменты SAST могут помочь обнаружить XXE в исходном коде, хотя ручная проверка кода — лучшая
                альтернатива для больших и сложных приложений со многими интеграциями.
              </li>
              <li>
                Если эти элементы управления невозможны, рассмотрите возможность использования виртуальных исправлений,
                шлюзов безопасности API или брандмауэров веб-приложений (WAF) для обнаружения, мониторинга и блокирования
                атак XXE.
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
              Пройти теорию на{' '}
              <a
                href="https://portswigger.net/web-security/xxe"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                Portswigger <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              {' '}и дополнительно ответить себе на вопросы{' '}
              <a
                href="https://portswigger.net/web-security/all-materials"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                тут <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              . А после переходим к:
            </P>
            <ol className="list-decimal pl-6 space-y-2">
              <li>
                <a
                  href="https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Exploiting XXE using external entities to retrieve files <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
              <li>
                <a
                  href="https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Exploiting XXE to perform SSRF attacks <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
              <li>
                <a
                  href="https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Exploiting blind XXE to retrieve data via error messages <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
              <li>
                <a
                  href="https://portswigger.net/web-security/xxe/lab-xinclude-attack"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Exploiting XInclude to retrieve files <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
              <li>
                <a
                  href="https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary hover:underline inline-flex items-center"
                >
                  Exploiting XXE via image file upload <ExternalLink className="ml-1 h-3 w-3" />
                </a>
              </li>
            </ol>
            <P className="mt-4">
              И совет из личного опыта – если фича загрузки аватарки поддерживает <strong>SVG</strong>, не забывать
              покрывать вектор <strong>XXE через аплоад модифицированного изображения</strong>. Пример{' '}
              <a
                href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection/Files"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline inline-flex items-center"
              >
                можно взять тут <ExternalLink className="ml-1 h-3 w-3" />
              </a>
              .
            </P>
            <P>
              Также, возможно, если приложение не позволяет загрузить через фронт <strong>SVG</strong> формат, то
              возможно через <strong>Repeater</strong> это получится. Но об этом рассмотрим во время{' '}
              <strong>File Upload vulnerabilities.</strong>
            </P>
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
