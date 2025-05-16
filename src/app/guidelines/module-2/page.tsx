import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { Search, Map, Network, Eye, ListChecks } from 'lucide-react';

export default function ModuleTwoPage() {
  return (
    <ContentPageLayout
      title="Модуль II: Разведка и Картирование Приложения"
    >
      <H2><Eye className="inline-block mr-2 h-6 w-6 text-primary" />A. Пассивная и Активная Разведка (Reconnaissance)</H2>
      <P>
        Этот этап фокусируется на сборе информации о целевом приложении без активного взаимодействия (пассивная разведка) и с использованием запросов к приложению (активная разведка), как описано в WAHH2.
      </P>
      <H3>Пассивная Разведка:</H3>
      <P>
        Использование общедоступных источников: поисковые системы (
        <a href="https://www.edgenexus.io/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Google Dorking 54
        </a>
        ), WHOIS <a href="https://www.edgenexus.io/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">54</a>, DNS-записи (nslookup, dig <a href="https://www.edgenexus.io/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">54</a>
        ), социальные сети, GitHub, архивы веб-сайтов, утечки данных (например, через сервисы вроде Troy Hunt's Have I Been Pwned <a href="https://portswigger.net/web-security/all-topics" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">43</a>
        ). Цель - собрать информацию об инфраструктуре, технологиях, потенциальных пользователях и связанных доменах.
      </P>
      <H3>Активная Разведка:</H3>
      <P>
        Использование инструментов для взаимодействия с целью: сканирование портов (Nmap <a href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">54</a>
        ), определение технологий веб-сервера и приложения (Wappalyzer <a href="https://www.edgenexus.io/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">54</a>
        , BuiltWith <a href="https://www.edgenexus.io/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">54</a>
        ), проверка заголовков HTTP, анализ robots.txt и sitemap.xml.<a href="https://portswigger.net/web-security/cross-site-scripting/reflected" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">55</a> Важно действовать осторожно, чтобы не вызвать срабатывание систем обнаружения вторжений.
      </P>

      <H2><Map className="inline-block mr-2 h-6 w-6 text-primary" />B. Картирование Приложения (Application Mapping)</H2>
      <P>Цель этого этапа - понять структуру, основные функции и потоки данных веб-приложения. Это основа для последующего поиска уязвимостей.</P>
      <H3>Ручное Исследование:</H3>
      <P>
        Систематический просмотр всех видимых страниц и функций приложения, взаимодействие с формами, ссылками, кнопками. Использование инструментов разработчика браузера (Developer Tools) для анализа HTML, CSS, JavaScript, сетевых запросов (AJAX <a href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">56</a>
        ), хранилища (Cookies, Local/Session Storage).<a href="https://portswigger.net/support/using-burp-to-find-clickjacking-vulnerabilities" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">57</a> Это позволяет понять логику работы приложения с точки зрения пользователя.
      </P>
      <H3>Автоматизированное Картирование (Spidering/Crawling):</H3>
      <P>
        Использование инструментов, таких как Burp Suite Spider <a href="https://brightsec.com/blog/ssrf-server-side-request-forgery/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">22</a> или OWASP ZAP Spider <a href="https://www.vaadata.com/blog/exploiting-the-ssrf-vulnerability/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">12</a>
        , для автоматического обхода ссылок и обнаружения контента. Важно правильно настроить область сканирования (scope) <a href="https://portswigger.net/web-security/all-topics" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">43</a>
        , чтобы избежать выхода за пределы целевого приложения и сканирования ненужных ресурсов (например, ссылок на выход).
      </P>
      <H3>Обнаружение Скрытого Контента (Content Discovery):</H3>
      <P>Поиск файлов, каталогов и функций, которые не связаны напрямую с видимыми страницами. Используются техники:</P>
      <Ul items={[
        <>
          Перебор по словарю (Dictionary Attack): Применение инструментов, таких как Dirb <a href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">47</a>
          , Gobuster <a href="https://ilmubersama.com/tag/xss-dvwa-security-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">63</a>
          , ffuf <a href="https://www.indusface.com/learning/file-inclusion-attacks-lfi-rfi/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">65</a>
          , Burp Content Discovery <a href="https://github.com/OWASP/www-project-developer-guide/blob/main/draft/09-training-education/01-vulnerable-apps/01-juice-shop.md" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">67</a>
          , с использованием списков распространенных имен файлов и каталогов (например, из SecLists <a href="https://www.infosecinstitute.com/resources/penetration-testing/top-5-deliberately-vulnerable-web-applications-to-practice-your-skills-on/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">28</a>
          ). Это часто позволяет найти административные панели, файлы конфигурации, резервные копии <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">3</a> или устаревшие версии страниц.<a href="https://grietsdc.in/downloads/nasscom161121/pwning%20-%20JuiceShop.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">62</a>
        </>,
        "Анализ JavaScript: Изучение клиентского кода на предмет скрытых путей API, комментариев или переменных, указывающих на неочевидную функциональность.",
        "Использование Публичных Данных: Поиск информации о структуре сайта в поисковых системах или архивах."
      ]} />
      <H3>Обнаружение Поддоменов (Subdomain Enumeration):</H3>
      <P>
        Идентификация поддоменов целевого домена для расширения поверхности атаки. Используются инструменты и техники: Sublist3r <a href="https://www.edgenexus.io/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">54</a>
        , Amass <a href="https://seclab.stanford.edu/websec/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">68</a>
        , DNS-запросы (AXFR), поиск в сертификатах прозрачности (CT logs) <a href="https://seclab.stanford.edu/websec/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">68</a>
        , поисковые системы.<a href="https://github.com/gadoi/tryhackme/blob/main/HTTP%20in%20detail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">59</a> Найденные поддомены могут содержать тестовые или устаревшие версии приложений с меньшим уровнем безопасности.
      </P>
      <P>
        Автоматизированные инструменты значительно ускоряют процесс обнаружения контента и поддоменов, однако их результаты всегда требуют ручной проверки.<a href="https://www.imperva.com/learn/application-security/rfi-remote-file-inclusion/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">75</a> Серверы могут возвращать ложноположительные ответы (например, всегда 200 OK), а стандартные словари могут не содержать специфичных для приложения имен. Ручное исследование и анализ JavaScript остаются критически важными для полного понимания приложения.
      </P>
      
      <H2><Network className="inline-block mr-2 h-6 w-6 text-primary" />C. Анализ Основных Механизмов Приложения</H2>
      <P>Глубокое изучение ключевых компонентов приложения, как описано в WAHH2.</P>
      <Ul items={[
        <>
          Аутентификация: Анализ процесса входа (формы, многофакторная аутентификация <a href="https://www.reddit.com/r/tryhackme/comments/1ayxqm4/hi_everybody_here_is_a_walkthrough_of_the_fifth/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">13</a>
          ), регистрации, восстановления пароля <a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">76</a>
          , механизмов "запомнить меня".<a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">76</a> Поиск слабых мест, таких как предсказуемые учетные данные, отсутствие блокировки учетных записей, небезопасная передача паролей.
        </>,
        <>
          Управление Сессиями: Исследование того, как приложение отслеживает состояние пользователя между запросами (обычно с помощью cookies или токенов <a href="https://owasp.org/www-community/attacks/xss/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">77</a>
          ). Анализ генерации токенов сессии на предсказуемость (с помощью Burp Sequencer <a href="https://community.f5.com/kb/technicalarticles/cross-site-scripting-xss-exploit-paths/275166" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">21</a>
          ), проверка флагов безопасности cookie (HttpOnly, Secure <a href="https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">85</a>
          ), выявление уязвимостей фиксации сессии и недостатков завершения сессии.
        </>,
        <>
          Контроль Доступа: Определение различных ролей пользователей и их привилегий. Анализ того, как приложение применяет ограничения доступа к функциям и данным. Поиск возможностей для вертикального (повышение привилегий) и горизонтального (доступ к данным других пользователей) повышения привилегий.<a href="https://tryhackme.com/room/contentdiscovery" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">87</a>
        </>,
        "Обработка Пользовательского Ввода: Идентификация всех точек, где приложение принимает данные от пользователя (URL-параметры, POST-данные, HTTP-заголовки, cookies). Анализ того, как приложение обрабатывает и проверяет эти данные. Поиск потенциальных векторов для инъекционных атак (SQLi, XSS, Command Injection)."
      ]} />

      <H2><ListChecks className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Лаборатории и Инструменты</H2>
      <Ul items={[
        <>
          PortSwigger Academy: Лаборатории по Information disclosure <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">39</a>
          , Path traversal <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">39</a>
          , API testing (для понимания структуры API).<a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">39</a>
        </>,
        <>
          OWASP Juice Shop: Задания на поиск Score Board <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">21</a>
          , Admin Section <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">21</a>
          , исследование API (например, через /metrics <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">3</a>
          ), поиск скрытых файлов (backup files <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">3</a>
          ). Использование руководства "Pwning OWASP Juice Shop".<a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">21</a>
        </>,
        <>
          DVWA: Модули Command Injection (для понимания взаимодействия с ОС) <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">2</a>
          , File Inclusion (для понимания файловой системы).<a href="https://www.youtube.com/watch?v=htTEfokaKsM" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">88</a> Использование инструментов, таких как Dirb/Gobuster, против DVWA.<a href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">47</a> Учетные данные по умолчанию: admin/password.<a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">2</a>
        </>,
        <>
          TryHackMe: Комнаты "How The Web Works" <a href="https://portswigger.net/research/burp-clickbandit-a-javascript-based-clickjacking-poc-generator" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">57</a>
          , "HTTP in Detail" <a href="https://github.com/tharushkadinujaya05/TryHackMe-Learning-Path-From-Beginner-to-Expert" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">52</a>
          , "Content Discovery" <a href="https://brightsec.com/blog/local-file-inclusion-lfi/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">69</a>
          , "Subdomain Enumeration" <a href="https://www.kali.org/tools/dirb/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">59</a>
          , "Walking An Application".<a href="https://portswigger.net/support/using-burp-to-find-clickjacking-vulnerabilities" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">57</a>
        </>,
        <>
          Инструменты: Burp Suite (Proxy, Spider, Target, Repeater, Intruder, Content Discovery <a href="https://github.com/OWASP/www-project-developer-guide/blob/main/draft/09-training-education/01-vulnerable-apps/01-juice-shop.md" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">67</a>
          ), Инструменты разработчика браузера, Nmap, Gobuster, Dirb, ffuf, Sublist3r, Amass.
        </>
      ]} />
    </ContentPageLayout>
  );
}
