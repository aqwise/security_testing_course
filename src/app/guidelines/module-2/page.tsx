import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { Search, Map, Network, Eye } from 'lucide-react';

export default function ModuleTwoPage() {
  return (
    <ContentPageLayout
      title="Модуль II: Разведка и Картирование Приложения"
      imageUrl="https://placehold.co/600x400.png"
      imageAlt="Digital reconnaissance map"
      imageAiHint="digital map"
    >
      <H2><Eye className="inline-block mr-2 h-6 w-6 text-primary" />A. Пассивная и Активная Разведка (Reconnaissance)</H2>
      <P>
        Этот этап фокусируется на сборе информации о целевом приложении без активного взаимодействия (пассивная разведка) и с использованием запросов к приложению (активная разведка).
      </P>
      <H3>Пассивная Разведка:</H3>
      <P>Использование общедоступных источников: поисковые системы (Google Dorking), WHOIS, DNS-записи, социальные сети, GitHub, архивы веб-сайтов, утечки данных.</P>
      <H3>Активная Разведка:</H3>
      <P>Использование инструментов для взаимодействия с целью: сканирование портов (Nmap), определение технологий (Wappalyzer, BuiltWith), проверка заголовков HTTP, анализ robots.txt и sitemap.xml.</P>

      <H2><Map className="inline-block mr-2 h-6 w-6 text-primary" />B. Картирование Приложения (Application Mapping)</H2>
      <P>Цель этого этапа - понять структуру, основные функции и потоки данных веб-приложения.</P>
      <H3>Ручное Исследование:</H3>
      <P>Систематический просмотр страниц и функций, взаимодействие с элементами. Использование инструментов разработчика браузера.</P>
      <H3>Автоматизированное Картирование (Spidering/Crawling):</H3>
      <P>Использование Burp Suite Spider или OWASP ZAP Spider. Настройка области сканирования (scope).</P>
      <H3>Обнаружение Скрытого Контента (Content Discovery):</H3>
      <Ul items={[
        "Перебор по словарю: Dirb, Gobuster, ffuf, Burp Content Discovery, SecLists.",
        "Анализ JavaScript: Поиск скрытых путей API, комментариев.",
        "Использование Публичных Данных: Поиск в поисковых системах или архивах."
      ]} />
      <H3>Обнаружение Поддоменов (Subdomain Enumeration):</H3>
      <P>Идентификаторы поддоменов: Sublist3r, Amass, DNS-запросы (AXFR), сертификаты прозрачности (CT logs), поисковые системы.</P>
      <P>Автоматизированные инструменты ускоряют процесс, но требуют ручной проверки. Ручное исследование и анализ JavaScript остаются критически важными.</P>
      
      <H2><Network className="inline-block mr-2 h-6 w-6 text-primary" />C. Анализ Основных Механизмов Приложения</H2>
      <P>Глубокое изучение ключевых компонентов приложения.</P>
      <Ul items={[
        "Аутентификация: Анализ процессов входа, регистрации, восстановления пароля, механизмов \"запомнить меня\".",
        "Управление Сессиями: Исследование отслеживания состояния пользователя (cookies, токены). Анализ генерации токенов (Burp Sequencer), флагов безопасности cookie (HttpOnly, Secure).",
        "Контроль Доступа: Определение ролей и привилегий. Поиск возможностей для вертикального и горизонтального повышения привилегий.",
        "Обработка Пользовательского Ввода: Идентификация всех точек ввода данных. Анализ обработки и проверки данных. Поиск векторов для инъекций."
      ]} />

      <H2><ListChecks className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Лаборатории и Инструменты</H2>
      <Ul items={[
        "PortSwigger Academy: Лаборатории по Information disclosure, Path traversal, API testing.",
        "OWASP Juice Shop: Задания на поиск Score Board, Admin Section, исследование API, поиск скрытых файлов.",
        "DVWA: Модули Command Injection, File Inclusion. Использование Dirb/Gobuster.",
        "TryHackMe: Комнаты \"How The Web Works\", \"HTTP in Detail\", \"Content Discovery\", \"Subdomain Enumeration\", \"Walking An Application\".",
        "Инструменты: Burp Suite, Инструменты разработчика браузера, Nmap, Gobuster, Dirb, ffuf, Sublist3r, Amass."
      ]} />
    </ContentPageLayout>
  );
}
