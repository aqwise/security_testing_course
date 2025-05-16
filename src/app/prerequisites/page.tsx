import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { CheckSquare, Computer, Server, HardDrive, Book, Code2, Wrench, Shield, AlertTriangle } from 'lucide-react';
import Link from 'next/link';

export default function PrerequisitesPage() {
  return (
    <ContentPageLayout
      title="IV. Предварительные Требования"
    >
      <P>
        Для эффективного освоения материала, изложенного в данном руководстве, и выполнения практических заданий рекомендуется иметь следующие знания, оборудование и программное обеспечение.
      </P>

      <H2><Book className="inline-block mr-2 h-6 w-6 text-primary" />A. Концептуальные Знания:</H2>
      <Ul items={[
        "Основы веб-технологий: Понимание клиент-серверной архитектуры, различий между front-end и back-end.80 Знание основ HTML, CSS и JavaScript.80",
        <>Протокол HTTP/HTTPS: Четкое понимание структуры HTTP-запросов и ответов, методов (GET, POST, PUT, DELETE и др.) 72, заголовков (например, Host, User-Agent, Content-Type, Cookie, Referer) 72, кодов состояния (2xx, 3xx, 4xx, 5xx) 72 и принципов управления состоянием (сессии, cookie).15 Рекомендуемый ресурс: TryHackMe "<Link href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">HTTP in Detail</Link>".72</>,
        "Основы сетей: Базовое понимание TCP/IP, DNS, IP-адресации, портов, межсетевых экранов и прокси-серверов.32",
        <>Осведомленность об уязвимостях: Общее представление о распространенных классах веб-уязвимостей, таких как инъекции (SQL, Command), межсайтовый скриптинг (XSS), нарушение контроля доступа (IDOR, эскалация привилегий), подделка межсайтовых запросов (CSRF), как описано в <Link href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Top 10</Link>.17 Данное руководство углубит понимание и научит их эксплуатации.</>
      ]} />

      <H2><Computer className="inline-block mr-2 h-6 w-6 text-primary" />B. Оборудование:</H2>
      <Ul items={[
        "Компьютер: Современный ноутбук или настольный компьютер.",
        "Оперативная память (RAM): Минимум 8 ГБ, рекомендуется 16 ГБ или больше для комфортной работы с виртуальными машинами и инструментами, такими как Burp Suite.103",
        <>Место на диске: Достаточное пространство для установки операционной системы, инструментов, виртуальных машин/контейнеров и словарей (например, <Link href="https://github.com/danielmiessler/SecLists" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">SecLists</Link> 104 могут занимать значительный объем).</>,
        "Интернет-соединение: Стабильное подключение к Интернету."
      ]} />

      <H2><Server className="inline-block mr-2 h-6 w-6 text-primary" />C. Программное Обеспечение:</H2>
      <H3><HardDrive className="inline-block mr-1 h-5 w-5" />Операционная система (ОС):</H3>
      <Ul items={[
        <>Рекомендуется: Linux-дистрибутив, ориентированный на безопасность, такой как <Link href="https://www.kali.org/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Kali Linux</Link> 105, поскольку он поставляется с предустановленным большинством необходимых инструментов.67 Другие дистрибутивы, такие как Debian, Ubuntu, Mint или Arch (с <Link href="https://blackarch.org/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">BlackArch</Link> 104), также подходят. Требуется уверенное владение командной строкой.</>,
        "Возможно: Windows или macOS.103 Потребуется ручная установка и настройка большинства инструментов и, возможно, использование подсистемы Windows для Linux (WSL).105"
      ]} />
      <H3><Wrench className="inline-block mr-1 h-5 w-5" />Виртуализация/Контейнеризация:</H3>
      <Ul items={[
        <>Docker: Крайне рекомендуется для запуска современных уязвимых приложений, таких как OWASP Juice Shop и DVWA.24 Официальный сайт: <Link href="https://www.docker.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Docker</Link>.115</>,
        "ПО для виртуализации (Опционально): VMware Workstation/Player или VirtualBox для запуска полноценных ОС (например, Kali Linux) или специализированных уязвимых виртуальных машин.63"
      ]} />
      <H3><Shield className="inline-block mr-1 h-5 w-5" />Основные Инструменты Безопасности:</H3>
      <Ul items={[
        <>Burp Suite:
          <Ul items={[
            <>Community Edition (Бесплатная): Необходимый минимум для выполнения большинства ручных задач.53 Скачать с <Link href="https://portswigger.net/burp/communitydownload" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">PortSwigger</Link>.117</>,
            "Professional Edition (Платная): Предоставляет значительные преимущества (автоматический сканер, полная версия Intruder, Collaborator, BApps) 8, но не обязательна для освоения основ.",
            "Требует Java Runtime Environment (JRE) версии 1.7 или новее.103"
          ]} />
        </>,
        <>OWASP ZAP (Zed Attack Proxy): Бесплатная, open-source альтернатива Burp Suite.3 Официальный сайт: <Link href="https://www.zaproxy.org/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">ZAP</Link>.119</>,
        <>Nmap: Сканер сетей и портов.49 Официальный сайт: <Link href="https://nmap.org/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Nmap</Link>.121</>,
        <>sqlmap: Инструмент для автоматизации обнаружения и эксплуатации SQL-инъекций.122 Официальный сайт: <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">sqlmap</Link>.129</>,
        <>Gobuster / Dirb: Инструменты для перебора директорий и файлов.120 Gobuster GitHub: <Link href="https://github.com/OJ/gobuster" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OJ/gobuster</Link>.142 Dirb (может быть устаревшим, часто заменяется Gobuster или ffuf).143</>,
        <>Hydra: Инструмент для перебора паролей к различным сетевым службам.36 Вероятно, <Link href="https://github.com/vanhauser-thc/thc-hydra" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">THC-Hydra</Link>.148</>,
        <>Словари (Wordlists): Необходимы для атак перебором (brute-force) и обнаружения контента. Рекомендуется SecLists.104 Часто доступны в /usr/share/wordlists в Kali Linux.107 GitHub: <Link href="https://github.com/danielmiessler/SecLists" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">danielmiessler/SecLists</Link>.104</>,
        <>Git: Система контроля версий, необходима для клонирования репозиториев инструментов или уязвимых приложений.64 Официальный сайт: <Link href="https://git-scm.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Git SCM</Link>.109</>
      ]} />
      <H3><AlertTriangle className="inline-block mr-1 h-5 w-5" />Уязвимые Приложения для Практики:</H3>
      <Ul items={[
        <>Damn Vulnerable Web Application (DVWA): Классическое приложение на PHP/MySQL, отлично подходит для изучения основ.12 Репозиторий: <Link href="https://github.com/digininja/DVWA" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">digininja/DVWA</Link> 64 или Docker-образ vulnerables/web-dvwa.110 Учетные данные по умолчанию: admin / password.13</>,
        <>OWASP Juice Shop: Современное приложение на JavaScript (Node.js/Angular), имитирующее реальный интернет-магазин с множеством уязвимостей разной сложности.10 Официальный сайт: <Link href="https://owasp-juice.shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Juice Shop</Link>.10 GitHub: <Link href="https://github.com/juice-shop/juice-shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">juice-shop/juice-shop</Link>.22</>
      ]} />

      <H2><Code2 className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Языки (для написания скриптов и понимания кода):</H2>
      <Ul items={[
        <>Python: Широко используется в сообществе ИБ для автоматизации задач, написания эксплойтов и разработки инструментов.32 Многие инструменты (например, sqlmap 129, Autorize 175) написаны на Python. Официальный сайт: <Link href="https://www.python.org/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Python.org</Link>.174</>,
        "JavaScript: Крайне важен для понимания и эксплуатации клиентских уязвимостей (XSS, DOM Clobbering, Prototype Pollution) и анализа современных веб-приложений (SPA, фреймворки типа Angular, React).10",
        "Bash/Shell Scripting: Полезен для автоматизации задач в Linux-среде и взаимодействия с инструментами командной строки.32",
        "(Опционально) PHP, SQL: Базовое понимание синтаксиса PHP и SQL поможет при анализе исходного кода уязвимых приложений, таких как DVWA 12, и при составлении запросов для SQL-инъекций.98"
      ]} />
      
      <P>
        Убедитесь, что ваше окружение соответствует этим требованиям, чтобы обеспечить плавное прохождение практических заданий и максимальную пользу от изучения материала.
      </P>
    </ContentPageLayout>
  );
}
