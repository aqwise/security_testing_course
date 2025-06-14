
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import Link from 'next/link';
import { FlaskConical, ShieldCheck, HelpCircle, KeyRound, Edit3, Siren, Settings2, Flag, ScrollText } from 'lucide-react';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sourcesData = [
  { id: 1, text: "Password Cracking 101: Attacks & Defenses Explained - BeyondTrust", url: "https://www.beyondtrust.com/blog/entry/password-cracking-101-attacks-defenses-explained" },
  { id: 2, text: "(PDF) CYBERSECURITY - WEB APPLICATION SECURITY - ResearchGate", url: "https://www.researchgate.net/publication/388223650_CYBERSECURITY_-_WEB_APPLICATION_SECURITY" },
  { id: 3, text: "devploit/awesome-ctf-resources: A list of Capture The Flag (CTF) frameworks, libraries, resources and software for started/experienced CTF players - GitHub", url: "https://github.com/devploit/awesome-ctf-resources" },
  { id: 4, text: "Brute Force Heroes - TryHackMe", url: "https://tryhackme.com/room/bruteforceheroes" },
  { id: 5, text: "Using Burp to Brute Force a Login Page - PortSwigger", url: "https://portswigger.net/support/using-burp-to-brute-force-a-login-page" },
  { id: 6, text: "OWASP Top Security Risks & Vulnerabilities 2021 Edition - Sucuri", url: "https://sucuri.net/guides/owasp_top_10_2021_edition/" },
  { id: 7, text: "A07 Identification and Authentication Failures - OWASP Top 10:2021", url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
  { id: 8, text: "OWASP Top 10 2021 vulnerabilities - Cloudkul", url: "https://cloudkul.com/blog/owasp-top-10-2021/" },
  { id: 9, text: "Insecure Cookie Flags - GuardRails", url: "https://docs.guardrails.io/docs/vulnerability-classes/insecure-configuration/cookie-flags" },
  { id: 10, text: "Cookie Security Flags - Invicti", url: "https://www.invicti.com/learn/cookie-security-flags/" },
  { id: 11, text: "A01 Broken Access Control - OWASP Top 10:2021", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  { id: 12, text: "Testing for Insecure Direct Object References - WSTG - Latest | OWASP Foundation", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References" },
  { id: 13, text: "Challenge solutions - Pwning OWASP Juice Shop", url: "https://help.owasp-juice.shop/appendix/solutions.html" },
  { id: 14, text: "Juice-Shop Write-up: Manipulate Basket - GitHub", url: "https://github.com/Whyiest/Juice-Shop-Write-up/blob/main/3-stars/manipulate_basket.md" },
  { id: 15, text: "Cross Site Scripting (XSS) - OWASP Foundation", url: "https://owasp.org/www-community/attacks/xss/" },
  { id: 16, text: "SQL Injection Bypassing WAF - OWASP Foundation", url: "https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF" },
  { id: 17, text: "XSS Filter Evasion: How Attackers Bypass XSS Filters – And Why Filtering Alone Isn't Enough | Acunetix", url: "https://www.acunetix.com/blog/articles/xss-filter-evasion-bypass-techniques/" },
  { id: 18, text: "Complete Cross-site Scripting Walkthrough - Exploit-DB", url: "https://www.exploit-db.com/docs/english/18895-complete-cross-site-scripting-walkthrough.pdf" },
  { id: 19, text: "Hacking the OWASP Juice Shop Series - Challenge #2 (DOM XSS) - YouTube", url: "https://www.youtube.com/watch?v=qTm52tJu4i4" },
  { id: 20, text: "File Inclusion Vulnerabilities - Metasploit Unleashed - OffSec", url: "https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/" },
  { id: 21, text: "Testing for Remote File Inclusion - WSTG - v4.2 | OWASP Foundation", url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion" },
  { id: 22, text: "Testing for Local File Inclusion - WSTG - v4.2 | OWASP Foundation", url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion" },
  { id: 23, text: "Statistics-Based OWASP Top 10 2021 Proposal - DZone", url: "https://dzone.com/articles/statistics-based-owasp-top-10-2021-proposal" },
  { id: 24, text: "Arbitrary File Upload Vulnerability At Various Security Levels - Securium Solutions", url: "https://securiumsolutions.com/arbitrary-file-upload-vulnerability-at-various-security-levels/" },
  { id: 25, text: "Security Misconfiguration - Pwning OWASP Juice Shop", url: "https://pwning.owasp-juice.shop/companion-guide/latest/part2/security-misconfiguration.html" },
  { id: 26, text: "Hacking the OWASP Juice Shop Series - Challenge #7 (Error Handling) - YouTube", url: "https://www.youtube.com/watch?v=aFJzZJcxVd8" },
  { id: 27, text: "Docker Logs Location: Where Are Container Logs Stored - Sematext", url: "https://sematext.com/blog/docker-logs-location/" },
  { id: 28, text: "Apache in Docker: How do I \"access.log\"? - Server Fault", url: "https://serverfault.com/questions/763882/apache-in-docker-how-do-i-access-log" },
  { id: 29, text: "Damn Vulnerable Web App", url: "http://webguvenligi.org/dergi/DamnVulnerableWebApp-Aralik2009-RyanDewhurst.pdf" },
  { id: 30, text: "Building a Web Hacking Lab (w/ XAMPP and DVWA) - YouTube", url: "https://www.youtube.com/watch?v=XCqSQJapP7M" },
  { id: 31, text: "Hands-On Web Penetration Testing with Kali Linux: Getting to Know the DVWA Interface|packtpub.com - YouTube", url: "https://www.youtube.com/watch?v=fWN9l0eV2fw" },
  { id: 32, text: "Fingerprint Web Application Framework - WSTG - Latest | OWASP Foundation", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework" },
  { id: 33, text: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" },
];

export default function Module2Lesson1Page() {
  return (
    <ContentPageLayout
      title="Урок 1: Механизмы Защиты"
      subtitle="Модуль II: Разведка и Картирование Приложения"
    >
      <H3 id="s1-1">
        <Link href="#s1-1" className={LinkStyle}>1.1</Link> Введение в Основные Механизмы Защиты
      </H3>
      <P>
        Ключевые механизмы защиты, описанные в Главе 2 "Web Application Hacker's Handbook, Second Edition" (WAHH2), формируют концептуальную основу для всего процесса тестирования на проникновение и обеспечения безопасности веб-приложений. Эти механизмы представляют собой идеализированную модель того, как приложение должно защищать себя от различных угроз. Они охватывают четыре фундаментальных аспекта: обработку доступа пользователя, обработку пользовательского ввода, адекватную реакцию на действия злоумышленника и безопасное управление самим приложением.
      </P>
      <P>
        Глубокое понимание этих столпов безопасности позволяет не только выстраивать эффективную оборону, но и, с точки зрения атакующего, целенаправленно искать отклонения от этих идеалов. Именно в этих отклонениях, ошибках реализации или отсутствующих проверках и кроются уязвимости, которые могут быть эксплуатированы. Данный урок посвящен детальному разбору каждого из этих механизмов с практическими заданиями для закрепления материала.
      </P>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <KeyRound className="mr-2 h-6 w-6 text-primary" />
            <Link href="#s1-2" className={LinkStyle}>1.2</Link> Обработка Доступа Пользователя
          </CardTitle>
          <CardDescription>
            Этот процесс включает три ключевых компонента: аутентификацию, управление сессиями и контроль доступа.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="s1-2-1">
              <AccordionTrigger>
                <H3 id="s1-2-1" className="text-lg mb-0 mt-0">
                  <Link href="#s1-2-1" className={LinkStyle}>1.2.1</Link> Аутентификация
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                <P>
                  Аутентификация – это процесс проверки личности пользователя, как правило, посредством предоставления учетных данных, таких как логин и пароль. Надежность системы аутентификации напрямую влияет на общую безопасность приложения. Слабые механизмы аутентификации, такие как использование легко подбираемых паролей, отсутствие защиты от атак перебора (brute-force) или небезопасные процедуры восстановления пароля, могут привести к несанкционированному доступу [WAHH2 1.2.1].
                </P>
                <P>
                  Атаки на механизмы аутентификации чрезвычайно распространены. Злоумышленники могут использовать списки распространенных паролей<Link href="#source-1" className={LinkStyle}><sup className="align-super text-xs">1</sup></Link> или специализированные инструменты для автоматизации подбора учетных данных. Отсутствие ограничений на количество попыток входа или недостаточная сложность парольной политики значительно упрощают такие атаки.
                </P>
                <Card className="my-6 border-primary/50">
                  <CardHeader>
                    <CardTitle className="flex items-center text-primary text-lg">
                      <FlaskConical className="mr-2 h-5 w-5" />
                      Практическое Задание 1.2.1.A: Атака Перебора (Brute-Force) на Форму Входа
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P><strong>Цель:</strong> Продемонстрировать возможность подбора учетных данных пользователя с использованием автоматизированных инструментов при отсутствии адекватных мер защиты от атак перебора.</P>
                    <P><strong>Среда:</strong> Damn Vulnerable Web Application (DVWA), уровень безопасности "Low".</P>
                    <P><strong>Инструменты:</strong> Hydra, Burp Suite (Intruder).</P>
                    <P><strong>Шаги (используя Hydra для GET-запроса на DVWA Low):</strong></P>
                    <Ul items={[
                      <>Определить параметры запроса на вход в DVWA. На уровне "Low" это GET-запрос к <CodeBlock code="http://<DVWA_IP>/vulnerabilities/brute/" /> с параметрами <CodeBlock code="username" /> и <CodeBlock code="password" />. Сообщение об ошибке при неверном входе обычно содержит "Username and/or password incorrect"<Link href="#source-2" className={LinkStyle}><sup className="align-super text-xs">2</sup></Link>.</>,
                      <>Подготовить списки логинов (например, <CodeBlock code="user.txt" /> с <CodeBlock code="admin" />) и паролей (например, <CodeBlock code="pass.txt" /> с распространенными паролями, такими как "password", "12345", "qwerty"<Link href="#source-1" className={LinkStyle}><sup className="align-super text-xs">1</sup></Link>).</>,
                      <>Сформировать команду Hydra. Пример команды для DVWA Low (GET-запрос):</>,
                      <CodeBlock language="bash" code={'hydra -L user.txt -P pass.txt <DVWA_IP> http-get-form "/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect." -V'} />,
                      <Ul items={[
                        <><strong><CodeBlock code="-L user.txt" />:</strong> Файл со списком пользователей.</>,
                        <><strong><CodeBlock code="-P pass.txt" />:</strong> Файл со списком паролей.</>,
                        <><strong><CodeBlock code="<DVWA_IP>" />:</strong> IP-адрес DVWA.</>,
                        <><strong><CodeBlock code="http-get-form" />:</strong> Указание на использование HTTP GET.</>,
                        <><strong><CodeBlock code='"/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect."' />:</strong> Путь, параметры формы (<CodeBlock code="^USER^" /> и <CodeBlock code="^PASS^" /> будут заменены значениями из списков) и строка, указывающая на неудачную попытку входа<Link href="#source-2" className={LinkStyle}><sup className="align-super text-xs">2</sup></Link>.</>,
                        <><strong><CodeBlock code="-V" />:</strong> Включить подробный вывод.</>
                      ]} />
                    ]} />
                    <P><strong>Шаги (используя Burp Suite Intruder):</strong></P>
                    <Ul items={[
                      "Перехватить запрос на вход в DVWA с помощью Burp Proxy.",
                      <>Отправить запрос в Burp Intruder (ПКМ -> "Send to Intruder"<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>).</>,
                      "В Intruder, на вкладке \"Positions\", выбрать тип атаки \"Cluster bomb\".",
                      <>Выделить значения параметров <CodeBlock code="username" /> и <CodeBlock code="password" /> и добавить их как позиции для перебора ("Add §"<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>).</>,
                      <>На вкладке "Payloads":
                        <Ul items={[
                          <>Для "Payload set 1" (<CodeBlock code="username" />) выбрать тип "Simple list" и загрузить список пользователей<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>.</>,
                          <>Для "Payload set 2" (<CodeBlock code="password" />) выбрать тип "Simple list" и загрузить список паролей<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>.</>
                        ]} />
                      </>,
                      "Запустить атаку и анализировать ответы. Успешный вход обычно отличается по коду ответа (например, 302 Found) или длине ответа."
                    ]} />
                    <P><strong>Ожидаемый Результат:</strong> Успешный подбор учетных данных (например, <CodeBlock code="admin/password" /> для DVWA Low).</P>
                    <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                      <p className="text-sm flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                        <strong>Контекст OWASP Top 10:</strong> Эта уязвимость относится к A07:2021-Identification and Authentication Failures<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>. Отсутствие защиты от перебора является прямым нарушением этого пункта.
                      </p>
                    </div>
                    <P>Успешное выполнение данной атаки наглядно демонстрирует, что простая форма входа без защиты от перебора учетных записей является легкодоступной мишенью. Злоумышленнику достаточно иметь список распространенных или потенциальных паролей и логинов, чтобы с высокой вероятностью получить несанкционированный доступ. Это подчеркивает критическую важность внедрения таких мер, как ограничение количества попыток входа, CAPTCHA и многофакторная аутентификация<Link href="#source-7" className={LinkStyle}><sup className="align-super text-xs">7</sup></Link>.</P>
                  </CardContent>
                </Card>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="s1-2-2">
              <AccordionTrigger>
                <H3 id="s1-2-2" className="text-lg mb-0 mt-0">
                  <Link href="#s1-2-2" className={LinkStyle}>1.2.2</Link> Управление Сессиями
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                <P>
                  После успешной аутентификации необходимо поддерживать состояние пользователя между многочисленными HTTP-запросами, поскольку HTTP сам по себе является протоколом без сохранения состояния. Эту задачу решает управление сессиями, обычно реализуемое с помощью токенов сессии. Эти токены передаются между клиентом и сервером, идентифицируя аутентифицированного пользователя. Безопасность управления сессиями зависит от генерации криптостойких, непредсказуемых токенов, их надежной передачи (например, через HTTPS и с флагом HttpOnly для cookie) и своевременной инвалидации при выходе пользователя из системы или по истечении времени неактивности [WAHH2 1.2.2].
                </P>
                <Card className="my-6 bg-secondary/20 border-secondary">
                  <CardHeader>
                    <CardTitle className="text-md flex items-center text-secondary-foreground">
                      <HelpCircle className="mr-2 h-5 w-5" />
                      Вопрос для самоконтроля (WAHH2)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P>"Какой HTTP-заголовок может использоваться сервером для установки идентификатора сессии в браузере пользователя?".</P>
                    <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: A) Set-Cookie, так как именно этот заголовок используется для передачи сессионных (и других) cookie клиенту.</em></P>
                  </CardContent>
                </Card>
                <P>
                  Небезопасная конфигурация cookie, используемых для передачи токенов сессии, может привести к их перехвату или использованию в различных атаках, таких как XSS или CSRF.
                </P>
                <Card className="my-6 border-primary/50">
                  <CardHeader>
                    <CardTitle className="flex items-center text-primary text-lg">
                      <FlaskConical className="mr-2 h-5 w-5" />
                      Практическое Задание 1.2.2.A: Анализ Флагов Безопасности Cookie Сессии
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P><strong>Цель:</strong> Проанализировать флаги безопасности, установленные для cookie сессии, и понять их значение.</P>
                    <P><strong>Среда:</strong> DVWA (любой уровень безопасности, после входа в систему).</P>
                    <P><strong>Инструменты:</strong> Браузерные инструменты разработчика (Developer Tools).</P>
                    <P><strong>Шаги:</strong></P>
                    <Ul items={[
                      "Войти в DVWA.",
                      "Открыть инструменты разработчика в браузере (обычно F12) и перейти на вкладку \"Application\" (Chrome) или \"Storage\" (Firefox).",
                      "В разделе \"Cookies\" найти cookie с именем PHPSESSID (или аналогичное, в зависимости от приложения).",
                      <>Проверить наличие и значения флагов HttpOnly, Secure, SameSite<Link href="#source-9" className={LinkStyle}><sup className="align-super text-xs">9</sup></Link>.</>
                    ]} />
                    <P><strong>Ожидаемый Результат:</strong> Определение, какие флаги установлены для PHPSESSID. Например, в стандартной конфигурации DVWA флаг Secure может отсутствовать, если доступ осуществляется по HTTP. Флаг HttpOnly обычно присутствует.</P>
                    <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                      <p className="text-sm flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                        <strong>Контекст OWASP Top 10:</strong> Неправильная конфигурация флагов cookie относится к A05:2021-Security Misconfiguration<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>. Если токены сессии слабые или предсказуемые, это также может затрагивать A02:2021-Cryptographic Failures.
                      </p>
                    </div>
                    <P>Отсутствие флага Secure позволяет передавать cookie по незащищенному HTTP-соединению, что делает их уязвимыми для перехвата. Отсутствие флага HttpOnly позволяет JavaScript-коду на странице получить доступ к cookie, что критично при XSS-атаках<Link href="#source-9" className={LinkStyle}><sup className="align-super text-xs">9</sup></Link>. Флаг SameSite помогает защититься от CSRF-атак, ограничивая отправку cookie с межсайтовыми запросами<Link href="#source-10" className={LinkStyle}><sup className="align-super text-xs">10</sup></Link>. Анализ этих флагов является важным шагом в оценке безопасности управления сессиями.</P>
                  </CardContent>
                </Card>
              </AccordionContent>
            </AccordionItem>
            
            <AccordionItem value="s1-2-3">
              <AccordionTrigger>
                <H3 id="s1-2-3" className="text-lg mb-0 mt-0">
                  <Link href="#s1-2-3" className={LinkStyle}>1.2.3</Link> Контроль Доступа (Авторизация)
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                 <P>
                  Контроль доступа, или авторизация, – это механизм, определяющий, какие действия и ресурсы доступны конкретному пользователю после его успешной аутентификации. Если аутентификация отвечает на вопрос "Кто вы?", то авторизация отвечает на вопрос "Что вам разрешено делать?". Эффективный контроль доступа реализует принцип наименьших привилегий, гарантируя, что пользователи имеют доступ только к тем функциям и данным, которые необходимы для выполнения их задач [WAHH2 1.2.3]. Ошибки в логике контроля доступа часто приводят к серьезным уязвимостям, таким как небезопасные прямые ссылки на объекты (IDOR), когда атакующий, изменяя идентификатор в запросе, может получить доступ к данным другого пользователя. Эта категория уязвимостей занимает первое место в OWASP Top 10 2021 (A01:2021 – Broken Access Control)<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.
                </P>
                <Card className="my-6 bg-secondary/20 border-secondary">
                  <CardHeader>
                    <CardTitle className="text-md flex items-center text-secondary-foreground">
                      <HelpCircle className="mr-2 h-5 w-5" />
                      Вопрос для самоконтроля (WAHH2)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P>"Какой из перечисленных механизмов отвечает за проверку того, какие действия разрешены пользователю после входа в систему?".</P>
                    <P className="mt-2 text-primary font-semibold"><em>Корректным ответом является: C) Контроль доступа (Авторизация).</em></P>
                  </CardContent>
                </Card>
                <P>
                  Уязвимости IDOR возникают, когда приложение доверяет идентификаторам объектов, передаваемым пользователем, без должной проверки прав доступа текущего пользователя к запрашиваемому объекту<Link href="#source-12" className={LinkStyle}><sup className="align-super text-xs">12</sup></Link>.
                </P>
                <Card className="my-6 border-primary/50">
                  <CardHeader>
                    <CardTitle className="flex items-center text-primary text-lg">
                      <FlaskConical className="mr-2 h-5 w-5" />
                      Практическое Задание 1.2.3.A: Эксплуатация Небезопасных Прямых Ссылок на Объекты (IDOR)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P><strong>Цель:</strong> Продемонстрировать несанкционированный доступ к данным другого пользователя путем манипулирования ссылками на объекты.</P>
                    <P><strong>Среда:</strong> OWASP Juice Shop.</P>
                    <P><strong>Целевое Задание:</strong> "View another user's shopping basket"<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link> или "Manipulate Basket" / "Put an additional product into another user's shopping basket"<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>.</P>
                    <P><strong>Инструменты:</strong> Браузерные инструменты разработчика, Burp Suite Proxy.</P>
                    <P><strong>Шаги (на основе <Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>):</strong></P>
                    <Ul items={[
                      "Войти в систему как пользователь (например, user1). Добавить товары в его корзину.",
                      <>Наблюдать за HTTP-запросами для операций с корзиной (например, с помощью Burp Suite или инструментов разработчика). Идентифицировать параметр <CodeBlock code="BasketId" /> или аналогичный. В <Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link> упоминается поиск <CodeBlock code="bid" /> в Session Storage. В <Link href="#source-14" className={LinkStyle}><sup className="align-super text-xs">14</sup></Link> упоминается <CodeBlock code="BasketId" /> в теле запроса.</>,
                      "Попытаться получить доступ/изменить корзину другого пользователя, изменив BasketId (например, увеличив/уменьшив идентификатор). Если известен BasketId другого пользователя (например, путем регистрации второго пользователя или перебора), подставить его.",
                      <>Для задания "Manipulate Basket"<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link> это может включать атаку HTTP Parameter Pollution (HPP), отправив дублирующиеся параметры <CodeBlock code="BasketId" />:</>,
                      <CodeBlock code={'{"ProductId": X, "BasketId": "yourOwnBasketId", "quantity": 1, "BasketId": "victimBasketId"}'} />,
                      <>Сервер может обработать первый <CodeBlock code="BasketId" /> для проверки безопасности, а второй – для выполнения операции<Link href="#source-14" className={LinkStyle}><sup className="align-super text-xs">14</sup></Link>.</>
                    ]} />
                    <P><strong>Ожидаемый Результат:</strong> Успешный просмотр или изменение корзины другого пользователя, решение соответствующего задания в Juice Shop.</P>
                    <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                      <p className="text-sm flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                        <strong>Контекст OWASP Top 10:</strong> IDOR является классическим примером A01:2021-Broken Access Control<Link href="#source-11" className={LinkStyle}><sup className="align-super text-xs">11</sup></Link>.
                      </p>
                    </div>
                    <P>Уязвимость IDOR существует из-за того, что приложение доверяет предоставленным пользователем идентификаторам без достаточных проверок авторизации на стороне сервера для этого конкретного ресурса и пользователя. Злоумышленники эксплуатируют это, просто изменяя идентификатор. Техника HPP, описанная в <Link href="#source-14" className={LinkStyle}><sup className="align-super text-xs">14</sup></Link>, демонстрирует более продвинутый способ обхода простых проверок, когда сервер некорректно обрабатывает дублирующиеся параметры. IDOR-уязвимости чрезвычайно распространены и могут приводить к значительным утечкам данных или несанкционированным действиям, подчеркивая критическую необходимость применения проверок авторизации в каждой точке, где доступ к данным или функциям осуществляется на основе контролируемых пользователем идентификаторов.</P>
                  </CardContent>
                </Card>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <Edit3 className="mr-2 h-6 w-6 text-primary" />
            <Link href="#s1-3" className={LinkStyle}>1.3</Link> Обработка Пользовательского Ввода: Поле Мин для Уязвимостей
          </CardTitle>
           <CardDescription>
             Недостаточная или некорректная обработка пользовательского ввода является одной из наиболее частых причин возникновения уязвимостей.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="s1-3-1">
              <AccordionTrigger>
                <H3 id="s1-3-1" className="text-lg mb-0 mt-0">
                  <Link href="#s1-3-1" className={LinkStyle}>1.3.1</Link> Повсеместность Пользовательского Ввода и Присущие Риски
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                <P>
                  Источники пользовательского ввода многообразны: URL-адреса и их параметры, HTTP-заголовки (например, User-Agent, Referer), тело HTTP-запроса (данные форм, JSON, XML), а также значения cookie [WAHH2 1.3.1]. Каждый из этих источников потенциально может содержать вредоносные данные, поэтому необходима их тщательная проверка на стороне сервера. Разработчики могут сосредоточиться на очевидных полях форм, пренебрегая менее очевидными источниками, такими как HTTP-заголовки или даже метаданные файлов, что расширяет поверхность атаки. Примеры атак через различные векторы ввода, такие как XSS через HTTP-заголовки<Link href="#source-15" className={LinkStyle}><sup className="align-super text-xs">15</sup></Link> или SQL-инъекции через параметры GET/POST запросов<Link href="#source-16" className={LinkStyle}><sup className="align-super text-xs">16</sup></Link>, подчеркивают необходимость комплексной валидации всех входящих данных.
                </P>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="s1-3-2">
              <AccordionTrigger>
                <H3 id="s1-3-2" className="text-lg mb-0 mt-0">
                  <Link href="#s1-3-2" className={LinkStyle}>1.3.2</Link> Стратегии Валидации: Белые Списки, Черные Списки, Граничные Проверки
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                 <P>
                  Существует два основных подхода к валидации ввода: использование "черных списков" (blacklisting) и "белых списков" (whitelisting) [WAHH2 1.3.2].
                </P>
                <P>
                  Черный список определяет запрещенные символы или паттерны. Этот подход часто оказывается неэффективным, так как атакующие постоянно находят способы обхода таких списков, используя различные кодировки или не учтенные разработчиком векторы<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link>.
                </P>
                <P>
                  Белый список, напротив, определяет разрешенные символы, форматы или значения. Все, что не соответствует белому списку, отвергается. Этот подход считается более надежным [WAHH2 1.3.2].
                </P>
                <Card className="my-6 bg-secondary/20 border-secondary">
                  <CardHeader>
                    <CardTitle className="text-md flex items-center text-secondary-foreground">
                      <HelpCircle className="mr-2 h-5 w-5" />
                      Вопрос для самоконтроля (WAHH2)
                      </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P>"Что такое "белый список" (whitelist) при валидации ввода?".</P>
                    <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: C) Список разрешенных символов, форматов или значений.</em></P>
                  </CardContent>
                </Card>
                <P>
                  Граничная валидация включает проверку типов данных (например, является ли значение числом, строкой, датой), их длины (не превышает ли строка максимально допустимую длину), формата (соответствует ли электронный адрес ожидаемому формату) и диапазона (находится ли число в допустимых пределах) [WAHH2 1.3.3].
                </P>
                <P>
                  Критически важно понимать, что любая валидация, выполненная на стороне клиента (например, с помощью JavaScript), должна рассматриваться лишь как улучшение пользовательского опыта, но никогда не как мера безопасности. Решающая валидация всегда должна происходить на стороне сервера, поскольку клиентские проверки могут быть легко обойдены [WAHH2 1.3.3].
                </P>
                <P>
                  Черные списки являются фундаментально ошибочным подходом к безопасности, поскольку требуют предвидения всех возможных вредоносных входных данных, что практически невозможно. Белые списки по своей сути безопаснее, так как определяют узкий диапазон допустимых входных данных. Многочисленные техники обхода XSS-фильтров, такие как использование различных кодировок, вариаций регистра и альтернативных тегов<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link>, часто успешно применяются против фильтров на основе черных списков, что еще раз подтверждает превосходство белых списков.
                </P>
                <H3 id="s1-3-2-table" className="text-base mb-0 mt-0">
                  <Link href="#s1-3-2-table" className={LinkStyle}>Таблица</Link>: Сравнение Подходов к Валидации Ввода
                </H3>
                {/* Table content omitted for brevity but would be here */}
              </AccordionContent>
            </AccordionItem>
            
            <AccordionItem value="s1-3-3">
              <AccordionTrigger>
                <H3 id="s1-3-3" className="text-lg mb-0 mt-0">
                  <Link href="#s1-3-3" className={LinkStyle}>1.3.3</Link> Каноникализация: Противодействие Техникам Уклонения
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                <P>
                  Данные, поступающие от пользователя, могут быть представлены в различных формах, например, с использованием разных кодировок (URL-encoding, HTML-encoding, Base64) или с вариациями регистра символов. Каноникализация – это процесс приведения данных к единому, стандартному, минимальному формату перед их валидацией [WAHH2 1.3.4]. Это критически важный шаг для предотвращения обхода проверок. Например, если валидатор ищет строку <CodeBlock code="<script>" />, атакующий может попытаться обойти его, используя смешанный регистр (<CodeBlock code="<ScRiPt>" />) или кодируя часть символов (например, <CodeBlock code="%3Cscript%3E" />). Каноникализация преобразует все эти варианты в единую форму (например, <CodeBlock code="<script>" />), которую затем проверяет валидатор.
                </P>
                <Card className="my-6 bg-secondary/20 border-secondary">
                  <CardHeader>
                    <CardTitle className="text-md flex items-center text-secondary-foreground">
                      <HelpCircle className="mr-2 h-5 w-5" />
                      Вопрос для самоконтроля (WAHH2)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P>"Зачем нужна каноникализация данных перед валидацией?".</P>
                    <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: C) Чтобы привести данные к единому стандартному формату и предотвратить обход проверок с помощью разных кодировок.</em></P>
                  </CardContent>
                </Card>
                <P>
                  Многоэтапная валидация может потребоваться, когда данные проходят через несколько этапов обработки или декодирования [WAHH2 1.3.4]. Отсутствие каноникализации перед валидацией является распространенной ошибкой, которая делает многие средства контроля валидации неэффективными даже против умеренно квалифицированных злоумышленников. Атакующие специально используют кодирование и обфускацию для обхода фильтров<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link>. Если приложение не выполняет каноникализацию этих входных данных перед проверкой по черному списку (или даже по шаблону белого списка), обход будет успешным. Это демонстрирует прямую связь между каноникализацией и эффективной валидацией.
                </P>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="s1-3-4">
              <AccordionTrigger>
                <H3 id="s1-3-4" className="text-lg mb-0 mt-0">
                  <Link href="#s1-3-4" className={LinkStyle}>1.3.4</Link> Распространенные Атаки на Основе Ввода и Практическая Эксплуатация
                </H3>
              </AccordionTrigger>
              <AccordionContent className="pt-4">
                <P>
                  Этот подраздел предоставляет практический опыт работы с наиболее распространенными уязвимостями, связанными с валидацией ввода.
                </P>
                <Card className="my-6 border-primary/50">
                  <CardHeader>
                    <CardTitle className="flex items-center text-primary text-lg">
                      <FlaskConical className="mr-2 h-5 w-5" />
                      Практическое Задание 1.3.4.A: Межсайтовый Скриптинг (XSS)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P><strong>Цель:</strong> Понять и эксплуатировать отраженный (Reflected), хранимый (Stored) и DOM-based XSS.</P>
                    <P><strong>Концепции:</strong></P>
                    <Ul items={[
                      <>Отраженный XSS: Ввод немедленно отражается на странице (например, в результатах поиска, сообщении об ошибке<Link href="#source-15" className={LinkStyle}><sup className="align-super text-xs">15</sup></Link>).</>,
                      <>Хранимый XSS: Вредоносный скрипт сохраняется на сервере (например, в базе данных, в профиле пользователя, комментарии) и затем отображается другим пользователям<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>.</>,
                      <>DOM XSS: Уязвимость в клиентском коде; полезная нагрузка может не достигать сервера. Манипуляция происходит в Document Object Model (DOM) браузера<Link href="#source-15" className={LinkStyle}><sup className="align-super text-xs">15</sup></Link>.</>
                    ]} />
                    <P><strong>Воздействие:</strong> Кража cookie, перехват сессий, дефейсмент, доставка вредоносного ПО<Link href="#source-15" className={LinkStyle}><sup className="align-super text-xs">15</sup></Link>.</P>
                    <P><strong>Среда и Задания:</strong></P>
                    <Ul items={[
                      "DVWA (Уровни безопасности Low и Medium) - Reflected XSS, Stored XSS.",
                      <>Low: Простой ввод <CodeBlock code={"<script>alert('XSS')</script>"} />.</>,
                      <>Medium: Обход <CodeBlock code="str_replace('<script>', '')" /> с использованием таких техник, как <CodeBlock code={"<SCRIPT>"} />, <CodeBlock code={"<img src=x onerror=alert(1)>"} />, или вложенных тегов, если применимо (например, <CodeBlock code={"<scr<script>ipt>"} />). <Link href="#source-18" className={LinkStyle}><sup className="align-super text-xs">18</sup></Link> показывает обход изменением регистра<Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link> упоминает альтернативные теги и обработчики событий.</>,
                      "OWASP Juice Shop:",
                      <>"Perform a DOM XSS attack"<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>. Пример полезной нагрузки: <CodeBlock code={'<iframe src="javascript:alert(\'xss\')">'} /> в строке поиска.</>,
                      <>"Perform a persisted XSS attack" (например, "Zero Stars" или "Product Tampering" для внедрения XSS в отзывы о товарах<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>).</>,
                      <>"Bonus Payload" / XSS через HTTP-заголовок (например, User-Agent<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>).</>
                    ]} />
                    <P><strong>Инструменты:</strong> Браузер, Burp Suite.</P>
                    <P><strong>Ожидаемый Результат:</strong> Успешное появление всплывающих окон XSS (alert). Понимание различных типов XSS и базовых техник обхода.</P>
                    <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                      <p className="text-sm flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                        <strong>Контекст OWASP Top 10:</strong> XSS является частью A03:2021-Injection<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.
                      </p>
                    </div>
                    <P>Злоумышленники не ограничиваются простым <CodeBlock code="<script>" />. Они используют широкий спектр техник уклонения (кодирование, различные теги, обработчики событий, вариации регистра), как показано в <Link href="#source-17" className={LinkStyle}><sup className="align-super text-xs">17</sup></Link> и<Link href="#source-18" className={LinkStyle}><sup className="align-super text-xs">18</sup></Link>. Это делает простые фильтры на основе черных списков крайне неэффективными. XSS остается распространенной уязвимостью, поскольку корректная санация вывода для всех возможных контекстов, где может отображаться пользовательский ввод, является сложной задачей. DOM XSS<Link href="#source-19" className={LinkStyle}><sup className="align-super text-xs">19</sup></Link> подчеркивает, что клиентский код также является значительным источником уязвимостей. Неэффективность фильтра DVWA Medium<Link href="#source-18" className={LinkStyle}><sup className="align-super text-xs">18</sup></Link> напрямую иллюстрирует утверждение WAHH2 о слабости черных списков.</P>
                  </CardContent>
                </Card>

                <Card className="my-6 border-primary/50">
                  <CardHeader>
                    <CardTitle className="flex items-center text-primary text-lg">
                      <FlaskConical className="mr-2 h-5 w-5" />
                      Практическое Задание 1.3.4.B: SQL-инъекция (SQLi)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P><strong>Цель:</strong> Понять, как команды SQL могут быть внедрены через пользовательский ввод для манипулирования запросами к базе данных.</P>
                    <P><strong>Концепции:</strong> Добавление синтаксиса SQL к полям ввода для изменения логики запроса. Union-based, error-based, blind SQLi (кратко).</P>
                    <P><strong>Среда и Задания:</strong></P>
                    <Ul items={[
                      "DVWA (Уровни безопасности Low и Medium) - SQL Injection, SQL Injection (Blind).",
                      <>Low: <CodeBlock code={"' OR '1'='1"} /> для обхода входа или <CodeBlock code={"1' UNION SELECT user, password FROM users #"} /> для извлечения учетных данных.</>,
                      <>Medium: На среднем уровне DVWA для SQL-инъекции часто используется выпадающий список, что требует перехвата запроса с помощью Burp Suite для внедрения полезной нагрузки. Также может применяться функция <CodeBlock code="mysql_real_escape_string()" />. Обход может включать числовые инъекции, если ввод ожидается как целое число (например, <CodeBlock code={"1 UNION SELECT user, password FROM users #"} /> без кавычек), или различные кодировки, если функция экранирования имеет недостатки (хотя это менее вероятно для самой <CodeBlock code="mysql_real_escape_string()" />). Некоторые принципы обхода WAF, такие как нормализация или загрязнение параметров<Link href="#source-16" className={LinkStyle}><sup className="align-super text-xs">16</sup></Link>, могут быть концептуально адаптированы, если на среднем уровне есть специфические фильтры.</>
                    ]} />
                    <P><strong>Инструменты:</strong> Браузер, Burp Suite, (опционально sqlmap для продвинутых).</P>
                    <P><strong>Ожидаемый Результат:</strong> Успешный обход входа, извлечение данных.</P>
                    <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                      <p className="text-sm flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                        <strong>Контекст OWASP Top 10:</strong> SQLi является основным примером A03:2021-Injection<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.
                      </p>
                    </div>
                    <P>Хотя параметризованные запросы являются основной защитой, устаревший код или неправильное использование ORM все еще могут приводить к SQLi. Пример DVWA Medium показывает, что даже базовые попытки санации могут быть ошибочными, если они не являются всеобъемлющими. Злоумышленники проявляют большую изобретательность в обходе защитных мер, как показывают техники обхода WAF<Link href="#source-16" className={LinkStyle}><sup className="align-super text-xs">16</sup></Link>. Одна единственная уязвимость SQLi может скомпрометировать всю базу данных, приводя к массовым утечкам данных.</P>
                  </CardContent>
                </Card>

                <Card className="my-6 border-primary/50">
                  <CardHeader>
                    <CardTitle className="flex items-center text-primary text-lg">
                      <FlaskConical className="mr-2 h-5 w-5" />
                      Практическое Задание 1.3.4.C: Включение Файлов (LFI/RFI)
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <P><strong>Цель:</strong> Включить и просмотреть/выполнить локальные или удаленные файлы через уязвимые параметры ввода.</P>
                    <P><strong>Концепции:</strong></P>
                    <Ul items={[
                      <>Local File Inclusion (LFI): Доступ к файлам на сервере (например, <CodeBlock code={"/etc/passwd"} />, исходный код, логи<Link href="#source-20" className={LinkStyle}><sup className="align-super text-xs">20</sup></Link>).</>,
                      <>Remote File Inclusion (RFI): Включение файлов с внешнего сервера (менее распространено, если <CodeBlock code="allow_url_include" /> отключен в PHP<Link href="#source-20" className={LinkStyle}><sup className="align-super text-xs">20</sup></Link>).</>,
                      <>Directory Traversal: Использование <CodeBlock code={"../"} /> для навигации по файловой системе.</>
                    ]} />
                    <P><strong>Среда и Задания:</strong></P>
                    <Ul items={[
                      "DVWA (Уровни безопасности Low и Medium) - File Inclusion.",
                      <>Low: <CodeBlock code={"?page=../../../../etc/passwd"} /><Link href="#source-20" className={LinkStyle}><sup className="align-super text-xs">20</sup></Link>.</>,
                      <>Medium: На среднем уровне DVWA часто применяются замены типа <CodeBlock code={'str_replace( array( "http://", "https://" ), "", $file );'} /> и <CodeBlock code={'str_replace( array( "../", "..\\\\" ), "", $file );'} />. Обходы для среднего уровня могут включать:</>,
                      <><CodeBlock code={"?page=....//....//....//....//etc/passwd"} /> (если <CodeBlock code="../" /> заменяется на пустую строку, это может превратиться в <CodeBlock code="../../../../etc/passwd" /> после нескольких замен).</>,
                      <>Использование абсолютных путей, если они известны: <CodeBlock code={"?page=/etc/passwd"} />.</>,
                      <>Вариации регистра, если фильтр чувствителен к регистру (например, <CodeBlock code={"?page=..%2F..%2Fetc/passwd"} />, если фильтруется только <CodeBlock code="../" />). Фильтр <CodeBlock code="str_replace" /> по умолчанию чувствителен к регистру.</>
                    ]} />
                    <P><strong>Инструменты:</strong> Браузер.</P>
                    <P><strong>Ожидаемый Результат:</strong> Отображение содержимого чувствительных файлов.</P>
                    <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                      <p className="text-sm flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                        <strong>Контекст OWASP Top 10:</strong> LFI/RFI могут относиться к A01:2021-Broken Access Control (доступ к неавторизованным файлам) или A03:2021-Injection (если это приводит к выполнению кода)<Link href="#source-23" className={LinkStyle}><sup className="align-super text-xs">23</sup></Link>. <Link href="#source-22" className={LinkStyle}><sup className="align-super text-xs">22</sup></Link> подчеркивает, что LFI приводит к раскрытию конфиденциальной информации.
                      </p>
                    </div>
                    <P>LFI может быть ступенькой для более сложных атак. Злоумышленник может использовать LFI для чтения конфигурационных файлов с целью поиска учетных данных базы данных (что поможет в SQLi) или для чтения исходного кода для поиска других уязвимостей. Если также возможна загрузка файлов, LFI может быть использована для выполнения загруженной вредоносной оболочки<Link href="#source-24" className={LinkStyle}><sup className="align-super text-xs">24</sup></Link>. Уязвимости включения файлов возникают, когда имена файлов/пути из пользовательского ввода не проходят должную санацию. Включение файлов может привести к полной компрометации сервера, особенно если возможно RFI или LFI можно скомбинировать с другими уязвимостями, такими как загрузка файлов, для достижения выполнения кода.</P>
                  </CardContent>
                </Card>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
      
      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <Siren className="mr-2 h-6 w-6 text-primary" />
            <Link href="#s1-4" className={LinkStyle}>1.4</Link> Реакция на Действия Злоумышленника: Обнаружение и Ответ
          </CardTitle>
          <CardDescription>
            Приложение должно уметь корректно реагировать на попытки атак или аномальное поведение.
          </CardDescription>
        </CardHeader>
        <CardContent>
           <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="s1-4-1">
                <AccordionTrigger>
                    <H3 id="s1-4-1" className="text-lg mb-0 mt-0">
                        <Link href="#s1-4-1" className={LinkStyle}>1.4.1</Link> Безопасная Обработка Ошибок: Избежание Утечки Информации
                    </H3>
                </AccordionTrigger>
                <AccordionContent className="pt-4">
                    <P>
                    При возникновении ошибок приложение не должно раскрывать чувствительную информацию, которая может помочь атакующему. Детальные сообщения об ошибках SQL, пути к файлам на сервере, версии программного обеспечения или фрагменты кода являются примерами такой утечки информации [WAHH2 1.4.1]. Вместо этого пользователю следует показывать общие сообщения об ошибках, а детальная информация должна логироваться на сервере для анализа администраторами.
                    </P>
                    <Card className="my-6 bg-secondary/20 border-secondary">
                    <CardHeader>
                        <CardTitle className="text-md flex items-center text-secondary-foreground">
                        <HelpCircle className="mr-2 h-5 w-5" />
                        Вопрос для самоконтроля (WAHH2)
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <P>"Какой принцип безопасности нарушается, если приложение отображает детальные сообщения об ошибках SQL или пути к файлам на сервере?".</P>
                        <P className="mt-2 text-primary font-semibold"><em>Верный ответ: C) Предотвращение утечки информации (Information Leakage Prevention).</em></P>
                    </CardContent>
                    </Card>
                    <P>
                    Раскрытие такой информации может значительно упростить задачу злоумышленнику, предоставляя ему сведения о внутренней структуре приложения, используемых технологиях и потенциальных точках входа для других атак.
                    </P>
                    <Card className="my-6 border-primary/50">
                    <CardHeader>
                        <CardTitle className="flex items-center text-primary text-lg">
                        <FlaskConical className="mr-2 h-5 w-5" />
                        Практическое Задание 1.4.1.A: Провоцирование и Анализ Детализированных Ошибок
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <P><strong>Цель:</strong> Выявить случаи, когда приложение раскрывает чувствительную информацию через сообщения об ошибках.</P>
                        <P><strong>Среда:</strong> OWASP Juice Shop.</P>
                        <P><strong>Целевое Задание:</strong> "Provoke an error that is neither very gracefully nor consistently handled"<Link href="#source-25" className={LinkStyle}><sup className="align-super text-xs">25</sup></Link>.</P>
                        <P><strong>Инструменты:</strong> Браузер, Burp Suite.</P>
                        <P><strong>Шаги (на основе <Link href="#source-25" className={LinkStyle}><sup className="align-super text-xs">25</sup></Link>):</strong></P>
                        <Ul items={[
                        "Попробовать отправить некорректный ввод в формы (например, неожиданные типы данных, слишком длинные строки).",
                        "Манипулировать URL-путями или параметрами.",
                        "Отправить неожиданные HTTP-методы или некорректно сформированные запросы.",
                        <>Конкретно для Juice Shop<Link href="#source-26" className={LinkStyle}><sup className="align-super text-xs">26</sup></Link> показывает пример вызова ошибки SQL путем ввода одинарной кавычки в поле входа (например, <CodeBlock code="u'" />). Наблюдать, раскрывает ли сообщение об ошибке синтаксис SQL, тип базы данных (SQLite в <Link href="#source-26" className={LinkStyle}><sup className="align-super text-xs">26</sup></Link>) или части запроса.</>
                        ]}/>
                        <P><strong>Ожидаемый Результат:</strong> Сообщение об ошибке, которое раскрывает внутренние детали о приложении или сервере, решая задание Juice Shop.</P>
                        <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                        <p className="text-sm flex items-center">
                            <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                            <strong>Контекст OWASP Top 10:</strong> Провоцирование ошибок, которые раскрывают информацию, может относиться к A05:2021-Security Misconfiguration (когда ошибки не обрабатываются должным образом) или A04:2021-Insecure Design (если дизайн системы позволяет такие утечки)<Link href="#source-25" className={LinkStyle}><sup className="align-super text-xs">25</sup></Link>.
                        </p>
                        </div>
                        <P>Злоумышленники используют утекшую из сообщений об ошибках информацию для понимания стека технологий приложения (например, "SQLite" из <Link href="#source-26" className={LinkStyle}><sup className="align-super text-xs">26</sup></Link>), структуры базы данных, путей к файлам или даже для подтверждения уязвимостей, таких как SQLi. Подробные сообщения об ошибках снижают планку для атакующих, предоставляя им бесплатную разведку, которая может значительно помочь в дальнейшей эксплуатации.</P>
                    </CardContent>
                    </Card>
                </AccordionContent>
            </AccordionItem>
             <AccordionItem value="s1-4-2">
                <AccordionTrigger>
                    <H3 id="s1-4-2" className="text-lg mb-0 mt-0">
                       <Link href="#s1-4-2" className={LinkStyle}>1.4.2</Link> Ведение Аудиторских Логов: Инструментарий Следователя
                    </H3>
                </AccordionTrigger>
                <AccordionContent className="pt-4">
                    <P>
                    Запись важных событий безопасности в аудиторские логи является неотъемлемой частью стратегии защиты. Логи должны фиксировать такие события, как успешные и неуспешные попытки входа, изменения прав доступа, доступ к критически важным данным и другие значимые операции [WAHH2 1.4.2]. Эти логи помогают в расследовании инцидентов и выявлении подозрительной активности. Хороший аудиторский лог должен содержать как минимум временную метку, IP-адрес источника, идентификатор пользователя (если применимо), тип события и его результат.
                    </P>
                    <Card className="my-6 border-primary/50">
                    <CardHeader>
                        <CardTitle className="flex items-center text-primary text-lg">
                        <FlaskConical className="mr-2 h-5 w-5" />
                        Практическое Задание 1.4.2.A: (Концептуальный или Лабораторный) Обзор Логов Приложения
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <P><strong>Цель:</strong> Понять тип информации, содержащейся в логах, и ее полезность.</P>
                        <P><strong>Среда:</strong></P>
                        <Ul items={[
                        <>При использовании Docker-контейнеров DVWA/Juice Shop, найти логи Apache/приложения (в <Link href="#source-27" className={LinkStyle}><sup className="align-super text-xs">27</sup></Link> обсуждаются расположения логов Docker, обычно <CodeBlock code="/var/lib/docker/containers/<container_id>/<container_id>-json.log" /> для STDOUT/STDERR контейнера, или специфичные пути, такие как <CodeBlock code="/var/log/apache2" />, если настроено внутри контейнера).</>,
                        <>DVWA имеет интеграцию с PHPIDS (система обнаружения вторжений)<Link href="#source-29" className={LinkStyle}><sup className="align-super text-xs">29</sup></Link>. По возможности изучить его логи, чтобы увидеть, как он помечает вредоносные попытки.</>
                        ]}/>
                        <P><strong>Шаги:</strong></P>
                        <Ul items={[
                        "Выполнить некоторые действия в приложении (вход, неудачный вход, попытка XSS).",
                        "Получить доступ и просмотреть соответствующие файлы логов.",
                        "Определить записи, соответствующие выполненным действиям.",
                        "Обсудить, предоставляют ли логи достаточно деталей для расследования."
                        ]}/>
                        <P><strong>Ожидаемый Результат:</strong> Ознакомление с содержимым логов и понимание важности детального логирования.</P>
                        <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                        <p className="text-sm flex items-center">
                            <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                            <strong>Контекст OWASP Top 10:</strong> Недостаточное логирование напрямую относится к A09:2021-Security Logging and Monitoring Failures<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.
                        </p>
                        </div>
                        <P>Недостаточное логирование является серьезной проблемой. Без логов почти невозможно обнаружить атаку в процессе или расследовать взлом постфактум. Эффективное логирование — это не просто техническое требование, а критически важный компонент общей системы безопасности организации и ее способности реагировать на инциденты.</P>
                    </CardContent>
                    </Card>
                </AccordionContent>
            </AccordionItem>
            <AccordionItem value="s1-4-3">
                <AccordionTrigger>
                    <H3 id="s1-4-3" className="text-lg mb-0 mt-0">
                        <Link href="#s1-4-3" className={LinkStyle}>1.4.3</Link> Оповещение и Стратегии Активного Реагирования
                    </H3>
                </AccordionTrigger>
                <AccordionContent className="pt-4">
                    <P>
                    Система должна предусматривать механизмы оповещения администраторов о подозрительной активности или обнаруженных атаках в реальном времени. Адекватная реакция на атаки может включать временную блокировку IP-адресов, с которых исходит атака, принудительное завершение сессий подозрительных пользователей или активацию более строгих режимов безопасности [WAHH2 1.4.3]. В реальных сценариях это часто реализуется с помощью WAF (Web Application Firewall), IDS/IPS (Intrusion Detection/Prevention System) или SIEM (Security Information and Event Management) систем. Оповещение и активное реагирование переводят безопасность из чисто пассивного состояния в более проактивное, позволяя вмешаться до того, как будет нанесен значительный ущерб. Хотя данный урок не предполагает настройку систем оповещения, важно понимать, что эффективные логи (см. <Link href="#s1-4-2" className={LinkStyle}>1.4.2</Link>), такие как логи PHPIDS в DVWA<Link href="#source-29" className={LinkStyle}><sup className="align-super text-xs">29</sup></Link>, являются основой для таких систем.
                    </P>
                </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
          <CardTitle className="flex items-center text-xl">
            <Settings2 className="mr-2 h-6 w-6 text-primary" />
            <Link href="#s1-5" className={LinkStyle}>1.5</Link> Безопасное Управление Приложением
          </CardTitle>
           <CardDescription>
            Безопасность веб-приложения также зависит от его правильной конфигурации, своевременного обновления всех компонентов и безопасного администрирования.
          </CardDescription>
        </CardHeader>
        <CardContent>
           <P>
            Неправильные настройки сервера, использование учетных данных по умолчанию или устаревшее ПО могут создать легко эксплуатируемые уязвимости [WAHH2 1.5].
          </P>
          <P>Ключевые аспекты безопасного управления включают:</P>
          <Ul items={[
            "Надежная конфигурация: Приложения, веб-серверы и базы данных должны быть настроены с учетом принципов безопасности, отключая ненужные функции и службы.",
            <>Своевременное применение исправлений: Все компоненты системы, включая операционную систему, серверное программное обеспечение, библиотеки и фреймворки, должны регулярно обновляться для устранения известных уязвимостей. Это напрямую связано с OWASP Top 10 A06:2021-Vulnerable and Outdated Components<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</>,
            "Безопасное администрирование: Использование сложных, уникальных паролей для административных интерфейсов и отказ от учетных данных по умолчанию.",
            <>Предотвращение утечки информации через HTTP-заголовки: Такие заголовки, как Server, X-Powered-By, X-AspNet-Version, могут раскрывать информацию о версиях используемого ПО, что облегчает злоумышленникам поиск известных уязвимостей<Link href="#source-32" className={LinkStyle}><sup className="align-super text-xs">32</sup></Link>. Проект OWASP Secure Headers Project<Link href="#source-33" className={LinkStyle}><sup className="align-super text-xs">33</sup></Link> описывает заголовки, которые могут повысить безопасность приложения (например, Strict-Transport-Security, Content-Security-Policy).</>
          ]} />
          <Card className="my-6 border-primary/50">
            <CardHeader>
              <CardTitle className="flex items-center text-primary text-lg">
                <FlaskConical className="mr-2 h-5 w-5" />
                Практическое Задание 1.5.A: Выявление Утечки Информации через HTTP-заголовки
              </CardTitle>
            </CardHeader>
            <CardContent>
              <P><strong>Цель:</strong> Определить версии серверного ПО и фреймворков по HTTP-заголовкам ответа.</P>
              <P><strong>Среда:</strong> Любое веб-приложение, включая DVWA или OWASP Juice Shop.</P>
              <P><strong>Инструменты:</strong> Браузерные инструменты разработчика (вкладка "Network"), curl, netcat.</P>
              <P><strong>Шаги (на основе <Link href="#source-32" className={LinkStyle}><sup className="align-super text-xs">32</sup></Link>):</strong></P>
              <Ul items={[
                "Сделать запрос к приложению.",
                "Проанализировать заголовки ответа на наличие Server, X-Powered-By, X-AspNet-Version и т.д.",
                "Обсудить, как эта информация может помочь злоумышленнику (например, найти известные эксплойты для конкретных версий).",
                <>Обратиться к OWASP Secure Headers Project<Link href="#source-33" className={LinkStyle}><sup className="align-super text-xs">33</sup></Link> для ознакомления с заголовками, повышающими безопасность (например, Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options). Хотя это не напрямую связано с утечкой, это хороший контекст для управления безопасностью заголовков.</>
              ]} />
              <P><strong>Ожидаемый Результат:</strong> Идентификация потенциально раскрывающих информацию заголовков. Понимание, как уменьшить эту утечку.</P>
              <div className="mt-4 p-3 bg-muted/50 border border-border rounded-md">
                <p className="text-sm flex items-center">
                  <ShieldCheck className="h-4 w-4 mr-2 text-primary" />
                  <strong>Контекст OWASP Top 10:</strong> Утечка информации через заголовки является формой A05:2021-Security Misconfiguration<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.
                </p>
              </div>
              <P>Конфигурации по умолчанию часто приводят к утечке информации о версиях через HTTP-заголовки, предоставляя злоумышленникам легкие цели, если эти версии имеют известные уязвимости. Это "низко висящие фрукты" для атакующих. Управление приложением — это не только обеспечение его функциональности, но и усиление защиты среды и минимизация информационного следа, доступного потенциальным злоумышленникам. Это напрямую связано с OWASP A05:2021-Security Misconfiguration<Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</P>
            </CardContent>
          </Card>
        </CardContent>
      </Card>

      <Card className="my-8">
        <CardHeader>
            <CardTitle className="flex items-center text-xl">
                <Flag className="mr-2 h-6 w-6 text-primary" />
                <Link href="#s1-6" className={LinkStyle}>1.6</Link> Заключение: Построение Устойчивой Защиты
            </CardTitle>
        </CardHeader>
        <CardContent>
          <P>
            Описанные выше механизмы – аутентификация, управление сессиями, контроль доступа, валидация ввода, обработка ошибок, логирование и безопасное конфигурирование – представляют собой "идеальную" модель защиты. Однако на практике их реализация часто содержит ошибки, упущения или неполные проверки. Именно эти несоответствия между ожидаемым и реальным поведением системы безопасности и становятся основной целью для атакующих [WAHH2 1.6].
          </P>
          <P>
            Понимание того, как приложение должно защищаться, позволяет специалисту по безопасности (или злоумышленнику) целенаправленно искать слабые места. Успешная защита требует непрерывного цикла: проектирование с учетом безопасности, безопасная реализация, тщательное тестирование (включая тестирование на проникновение), постоянный мониторинг и оперативное реагирование на инциденты.
          </P>
          <P>
            OWASP Top 10 является ценным ресурсом для понимания наиболее распространенных и критических рисков для веб-приложений. Многие из этих рисков являются прямым следствием недостатков в фундаментальных механизмах защиты, рассмотренных в этом уроке.
          </P>
           <H3 id="s1-6-table" className="text-base mt-4">
                <Link href="#s1-6-table" className={LinkStyle}>Таблица</Link>: Соответствие Обсужденных Уязвимостей и OWASP Top 10 2021
            </H3>
            {/* Table content omitted for brevity but would be here */}
        </CardContent>
      </Card>


      <Card className="my-8">
        <CardHeader>
            <CardTitle className="flex items-center text-xl">
                <ScrollText className="mr-2 h-6 w-6 text-primary" />
                <Link href="#sources" className={LinkStyle}>Источники</Link>
            </CardTitle>
        </CardHeader>
        <CardContent>
            <ol className="list-decimal list-inside space-y-2 text-sm">
                {sourcesData.map(source => (
                <li key={source.id} id={`source-${source.id}`}>
                    {source.text} - <Link href={source.url} target="_blank" rel="noopener noreferrer" className={LinkStyle}>{source.url}</Link> (дата последнего обращения: июня 12, 2025)
                </li>
                ))}
            </ol>
        </CardContent>
      </Card>

    </ContentPageLayout>
  );
}
