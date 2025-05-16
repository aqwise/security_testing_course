import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { CheckSquare, Computer, Server, HardDrive, Book, Code2, Wrench, Shield, AlertTriangle } from 'lucide-react';

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
        "Основы веб-технологий: Клиент-серверная архитектура, front-end/back-end, HTML, CSS, JavaScript.",
        "Протокол HTTP/HTTPS: Структура запросов/ответов, методы, заголовки, коды состояния, сессии, cookie.",
        "Основы сетей: TCP/IP, DNS, IP-адресация, порты, межсетевые экраны, прокси.",
        "Осведомленность об уязвимостях: Общее представление о классах веб-уязвимостей (SQLi, XSS, IDOR, CSRF, OWASP Top 10)."
      ]} />

      <H2><Computer className="inline-block mr-2 h-6 w-6 text-primary" />B. Оборудование:</H2>
      <Ul items={[
        "Компьютер: Современный ноутбук или настольный компьютер.",
        "Оперативная память (RAM): Минимум 8 ГБ, рекомендуется 16 ГБ+.",
        "Место на диске: Достаточное для ОС, инструментов, ВМ/контейнеров, словарей.",
        "Интернет-соединение: Стабильное."
      ]} />

      <H2><Server className="inline-block mr-2 h-6 w-6 text-primary" />C. Программное Обеспечение:</H2>
      <H3><HardDrive className="inline-block mr-1 h-5 w-5" />Операционная система (ОС):</H3>
      <Ul items={[
        "Рекомендуется: Linux (Kali, Debian, Ubuntu, Arch с BlackArch). Уверенное владение командной строкой.",
        "Возможно: Windows или macOS (потребуется ручная настройка, WSL)."
      ]} />
      <H3><Wrench className="inline-block mr-1 h-5 w-5" />Виртуализация/Контейнеризация:</H3>
      <Ul items={[
        "Docker: Крайне рекомендуется (OWASP Juice Shop, DVWA).",
        "ПО для виртуализации (Опционально): VMware, VirtualBox."
      ]} />
      <H3><Shield className="inline-block mr-1 h-5 w-5" />Основные Инструменты Безопасности:</H3>
      <Ul items={[
        "Burp Suite (Community/Professional)",
        "OWASP ZAP (альтернатива)",
        "Nmap",
        "sqlmap",
        "Gobuster / Dirb / ffuf",
        "Hydra",
        "Словари (Wordlists, SecLists)",
        "Git"
      ]} />
      <H3><AlertTriangle className="inline-block mr-1 h-5 w-5" />Уязвимые Приложения для Практики:</H3>
      <Ul items={[
        "Damn Vulnerable Web Application (DVWA)",
        "OWASP Juice Shop"
      ]} />

      <H2><Code2 className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Языки:</H2>
      <Ul items={[
        "Python: Автоматизация, эксплойты, инструменты.",
        "JavaScript: Клиентские уязвимости, анализ современных веб-приложений.",
        "Bash/Shell Scripting: Автоматизация в Linux.",
        "(Опционально) PHP, SQL: Анализ исходного кода, SQL-инъекции."
      ]} />
      
      <div className="mt-8 p-6 bg-green-500/10 rounded-lg border-l-4 border-green-500">
        <div className="flex items-center text-green-700 dark:text-green-400 mb-2">
          <CheckSquare className="h-6 w-6 mr-2"/>
          <h4 className="text-xl font-semibold">Готовность к обучению</h4>
        </div>
        <P>
          Убедитесь, что ваше окружение соответствует этим требованиям, чтобы обеспечить плавное прохождение практических заданий и максимальную пользу от изучения материала.
        </P>
      </div>
    </ContentPageLayout>
  );
}
