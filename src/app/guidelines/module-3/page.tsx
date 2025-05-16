import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { KeyRound, UserCheck, Lock, Users, ListChecks } from 'lucide-react';

export default function ModuleThreePage() {
  return (
    <ContentPageLayout
      title="Модуль III: Атака на Механизмы Аутентификации и Управления Сессиями"
    >
      <H2><UserCheck className="inline-block mr-2 h-6 w-6 text-primary" />A. Атака на Механизмы Аутентификации</H2>
      <P>Этот раздел углубляется в уязвимости, связанные с проверкой личности пользователя, основываясь на главах WAHH2.</P>
      
      <H3>Перебор Учетных Данных (Credential Stuffing & Brute Force):</H3>
      <Ul items={[
        <>
          Перебор Паролей (Password Brute Forcing): Систематический подбор пароля для известного имени пользователя.{' '}
          <a href="https://community.f5.com/kb/technicalarticles/mitigating-owasp-web-application-risk-ssrf-attack-using-f5-xc-platform/309635" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">101</a>{' '}
          Используются списки распространенных паролей (
          <a href="https://www.infosecinstitute.com/resources/penetration-testing/top-5-deliberately-vulnerable-web-applications-to-practice-your-skills-on/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">словарная атака 56</a>
          ) или полный перебор символов. Инструменты: {' '}
          <a href="https://portswigger.net/web-security/cross-site-scripting/stored" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Hydra 113</a>
          , <a href="https://community.f5.com/kb/technicalarticles/mitigating-owasp-web-application-risk-ssrf-attack-using-f5-xc-platform/309635" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Intruder.101</a>
        </>,
        <>
          Перебор Имен Пользователей (Username Enumeration): Определение действительных имен пользователей путем анализа различных ответов приложения (сообщения об ошибках, время ответа, блокировка учетной записи).{' '}
          <a href="https://tryhackme.com/room/nahamstore" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">43</a>{' '}
          Это первый шаг перед атакой на пароли. Инструменты: Burp Intruder.
        </>,
        <>
          Атака Распылением Паролей (Password Spraying): Попытка входа с одним или несколькими распространенными паролями для большого списка пользователей.{' '}
          <a href="https://www.kali.org/tools/dvwa/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">102</a>{' '}
          Менее "шумная" атака, чем брутфорс одного аккаунта, позволяет обойти простые политики блокировки. Инструменты: Hydra, специализированные скрипты.
        </>
      ]} />
      <P>
        Защита от Перебора: Обсуждение механизмов защиты, таких как {' '}
        <a href="https://tryhackme.com/room/nahamstore" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">блокировка учетных записей 18</a>
        , ограничение скорости запросов (<a href="https://payatu.com/blog/what-is-authorize-burpsuite-plugin-how-to-use-it/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">rate limiting) 116</a>
        , <a href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">CAPTCHA 56</a>
        , и их возможные недостатки или обходы (например, {' '}
        <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">обход блокировки по IP 14</a>
        ). Сложные пароли и MFA являются {' '}
        <a href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">ключевыми мерами.56</a>
      </P>
      
      <H3>Уязвимости Логики Аутентификации:</H3>
      <Ul items={[
        <>
          Небезопасное Восстановление Пароля: Анализ механизмов сброса/восстановления пароля на предмет уязвимостей, таких как предсказуемые токены сброса, передача токена в небезопасных параметрах (например, {' '}
          <a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">URL 76</a>
          ), недостаточная проверка личности, возможность отравления заголовка Host ({' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">password reset poisoning 14</a>
          ).<a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">76</a>
        </>,
        <>
          Обход Многофакторной Аутентификации (MFA/2FA): Поиск недостатков в реализации 2FA, таких как слабая генерация кодов, отсутствие ограничения на попытки ввода кода (возможность {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">брутфорса 14</a>
          ), уязвимости в логике проверки {' '}
          <a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">второго фактора 76</a>
          , возможность обхода шага 2FA.
        </>,
        <>
          Небезопасная Передача Учетных Данных: Анализ передачи учетных данных по незащищенным каналам (HTTP вместо HTTPS) или использование слабых механизмов, таких как HTTP Basic {' '}
          <a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Authentication.76</a>
        </>,
        <>
          Уязвимости "Запомнить меня": Исследование механизмов долговременных сессий, включая анализ стойкости и предсказуемости токенов в cookies {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">"remember me".14</a>
        </>
      ]} />
      <P>
        Аутентификация является критической точкой входа в приложение. Слабости в этом механизме, такие как возможность {' '}
        <a href="https://owasp.org/www-project-cloud-native-application-security-top-10/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">перебора учетных данных 56</a>{' '}
        или уязвимости в логике {' '}
        <a href="https://github.com/orgs/juice-shop/repositories" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">восстановления пароля 76</a>
        , могут привести к полному захвату учетной записи. Поэтому тщательное тестирование этих функций с использованием как ручных методов, так и автоматизированных инструментов (Hydra, {' '}
        <a href="https://www.invicti.com/learn/local-file-inclusion-lfi/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Intruder 101</a>) является обязательным.
      </P>

      <H2><Lock className="inline-block mr-2 h-6 w-6 text-primary" />B. Атака на Механизмы Управления Сессиями</H2>
      <P>Этот раздел посвящен уязвимостям, связанным с тем, как приложение управляет состоянием пользователя после аутентификации.</P>
      <H3>Анализ Токенов Сессии:</H3>
      <Ul items={[
        <>
          Предсказуемость Токенов: Использование {' '}
          <a href="https://community.f5.com/kb/technicalarticles/cross-site-scripting-xss-exploit-paths/275166" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Sequencer 21</a>{' '}
          для сбора большого количества токенов сессии и анализа их случайности и энтропии. Недостаточная случайность может позволить атакующему угадать или вычислить действительные токены {' '}
          <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">других пользователей.77</a>{' '}
          Требуется значительное количество токенов (тысячи) для надежного {' '}
          <a href="https://tryhackme.com/room/vulnversity" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">анализа.79</a>
        </>,
        <>
          Структура Токена: Анализ структуры токена (например, с помощью {' '}
          <a href="https://www.dcc.fc.up.pt/~edrdo/aulas/qses/lectures/lab1/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Decoder 21</a>) на наличие осмысленной информации (имя пользователя, временная метка, уровень привилегий), которая может быть изменена атакующим.
        </>,
        <>
          JSON Web Tokens (JWT): Особое внимание уделяется {' '}
          <a href="https://cspanias.github.io/posts/DVWA-Insecure-CAPTCHA/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">JWT 39</a>
          , так как они часто используются для управления сессиями в современных приложениях. Рассматриваются атаки на JWT: изменение полезной нагрузки (payload), атаки на подпись (алгоритм none, слабые секреты, подмена ключа), использование {' '}
          <a href="https://tryhackme.com/resources/blog/hydra" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp JWT Editor 117</a>{' '}
          для анализа и модификации токенов.
        </>
      ]} />
      <H3>Небезопасное Обращение с Токенами:</H3>
      <Ul items={[
        <>
          Передача по Незащищенному Каналу: Проверка, передаются ли токены сессии (например, в cookies) только по HTTPS. Отсутствие флага {' '}
          <a href="https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Secure 85</a>{' '}
          позволяет перехватить токен при использовании HTTP.
        </>,
        <>
          Доступность для Скриптов: Проверка наличия флага {' '}
          <a href="https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">HttpOnly 85</a>{' '}
          у cookies сессии. Его отсутствие делает токен уязвимым для кражи через {' '}
          <a href="https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">XSS-атаки.86</a>
        </>,
        <>
          Фиксация Сессии (Session Fixation): Атакующий заставляет жертву использовать известный ему идентификатор сессии, а затем, после аутентификации жертвы, использует этот же идентификатор для доступа к {' '}
          <a href="https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">ее сессии.86</a>{' '}
          Проверяется, генерируется ли новый ID сессии после успешного входа {' '}
          <a href="https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/client-side-controls" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">пользователя.86</a>
        </>,
        <>
          Недостатки Завершения Сессии: Проверка того, действительно ли сессия инвалидируется на сервере после выхода пользователя или по {' '}
          <a href="https://owasp.org/www-community/attacks/xss/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">таймауту.23</a>{' '}
          Если сессия остается активной, атакующий, завладевший токеном, может продолжать им пользоваться.
        </>
      ]} />
      <P>
        Управление сессиями тесно связано с аутентификацией и контролем доступа. Предсказуемые или легко похищаемые {' '}
        <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">токены сессии 77</a>{' '}
        сводят на нет надежность аутентификации, позволяя атакующему выдавать себя за легитимного пользователя. Инструменты вроде {' '}
        <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Sequencer 77</a>{' '}
        и <a href="https://tryhackme.com/resources/blog/hydra" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">JWT Editor 117</a>{' '}
        необходимы для глубокого анализа этих механизмов.
      </P>

      <H2><Users className="inline-block mr-2 h-6 w-6 text-primary" />C. Атака на Механизмы Контроля Доступа</H2>
      <P>
        Контроль доступа определяет, что пользователь может делать после аутентификации. Уязвимости здесь часто {' '}
        <a href="https://tryhackme.com/room/contentdiscovery" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">критичны.87</a>
      </P>
      <H3>Вертикальное Повышение Привилегий: Получение доступа к функциям, предназначенным для пользователей с более высокими привилегиями (например, {' '}
        <a href="https://tryhackme.com/room/contentdiscovery" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">администраторов).87</a>
      </H3>
      <Ul items={[
        <>
          Незашищенная Функциональность: Прямой доступ к административным URL (например, /admin), которые не должны быть доступны обычным {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">пользователям.87</a>{' '}
          Иногда URL может быть "скрытым", но обнаруживаемым через {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">картирование.14</a>
        </>,
        <>
          Манипуляция Параметрами: Изменение параметров в запросе (скрытые поля, cookies, URL-параметры), которые контролируют роль пользователя или доступ к {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">функциям.87</a>
        </>,
        <>
          Обход на Уровне Платформы/Метода: Использование нестандартных заголовков (например, X-Original-URL, X-Rewrite-URL), изменение HTTP-метода (с GET на POST и т.д.) для доступа к ресурсам, защищенным на уровне веб-сервера или {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">фреймворка.87</a>
        </>
      ]} />
      <H3>Горизонтальное Повышение Привилегий и IDOR: Получение доступа к данным, принадлежащим другим пользователям того же уровня {' '}
        <a href="https://tryhackme.com/room/contentdiscovery" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">привилегий.87</a>
      </H3>
      <Ul items={[
        <>
          Insecure Direct Object References (IDOR): Классическая уязвимость, когда приложение использует идентификатор объекта (например, ID пользователя, ID заказа, имя файла), полученный от пользователя, для прямого доступа к ресурсу без проверки прав доступа текущего пользователя к этому {' '}
          <a href="https://tryhackme.com/room/contentdiscovery" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">ресурсу.87</a>{' '}
          Атакующий просто подменяет ID в запросе (например, view_profile.php?user_id=123 на view_profile.php?user_id={''}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">456).14</a>{' '}
          Это может привести к утечке данных других пользователей, включая {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">пароли 14</a>{' '}
          или информацию, раскрываемую при {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">редиректах.14</a>
        </>,
        <>
          Тестирование IDOR: Требует наличия двух или более учетных записей с одинаковыми привилегиями. Необходимо систематически проверять все функции, работающие с пользовательскими данными, подставляя идентификаторы другого пользователя. Инструменты, такие как {' '}
          <a href="https://www.packtpub.com/en-SG/product/security-monitoring-with-wazuh-9781837632152/chapter/chapter-1-intrusion-detection-system-ids-using-wazuh-2/section/testing-web-based-attacks-using-dvwa-ch02lvl1sec07" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Autorize 120</a>{' '}
          автоматизируют этот процесс, повторяя запросы одного пользователя с токенами {' '}
          <a href="https://www.packtpub.com/en-SG/product/security-monitoring-with-wazuh-9781837632152/chapter/chapter-1-intrusion-detection-system-ids-using-wazuh-2/section/testing-web-based-attacks-using-dvwa-ch02lvl1sec07" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">другого.120</a>
        </>
      ]} />
      <H3>Другие Уязвимости:</H3>
      <Ul items={[
        <>
          Уязвимости в Многошаговых {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Процессах.87</a>{' '}
          Недостаточный контроль доступа на промежуточных или конечных шагах процесса, предполагая, что пользователь мог попасть туда только легальным путем. Атакующий может напрямую обратиться к уязвимому шагу.
        </>,
        <>
          Контроль доступа на основе заголовка Referer (легко {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">подделывается 87</a>) или геолокации (обход через {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">прокси/VPN 87</a>).
        </>
      ]} />
      <P>
        Сломанный контроль доступа стабильно занимает верхние строчки в рейтингах уязвимостей, таких как {' '}
        <a href="https://www.praetorian.com/blog/content-discovery-understanding-your-web-attack-surface/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Top 10 125</a>
        , что подчеркивает его критическую важность. Тестирование требует понимания различных паттернов (вертикальный, горизонтальный, IDOR) и часто включает ручную манипуляцию параметрами или автоматизацию проверок с помощью инструментов, таких как {' '}
        <a href="https://www.packtpub.com/en-SG/product/security-monitoring-with-wazuh-9781837632152/chapter/chapter-1-intrusion-detection-system-ids-using-wazuh-2/section/testing-web-based-attacks-using-dvwa-ch02lvl1sec07" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Autorize.122</a>
      </P>

      <H2><ListChecks className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Лаборатории и Инструменты</H2>
      <Ul items={[
        <>
          PortSwigger Academy: Лаборатории по аутентификации (перечисление пользователей, обход 2FA, сброс пароля, брутфорс cookie {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">"remember me" 14</a>
          ), лаборатории по контролю доступа (незащищенный админ-функционал, манипуляция ролью/ID пользователя, IDOR, {' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">обход по методу 87</a>
          ), лаборатории по {' '}
          <a href="https://cspanias.github.io/posts/DVWA-Insecure-CAPTCHA/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">JWT.39</a>
        </>,
        <>
          OWASP Juice Shop: Задания категории "Broken Authentication" (обход входа, сила пароля, {' '}
          <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">сброс паролей 21</a>
          ), "Broken Access Control" (админ-секция, просмотр/манипуляция корзиной, {' '}
          <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">поддельные отзывы 21</a>
          ), задания с {' '}
          <a href="https://www.youtube.com/watch?v=iWoiwFRLV4I" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">JWT.3</a>{' '}
          Использование {' '}
          <a href="https://www.dcc.fc.up.pt/~edrdo/aulas/qses/lectures/lab1/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">руководства.21</a>
        </>,
        <>
          DVWA: Модуль {' '}
          <a href="https://brightsec.com/blog/ssrf-server-side-request-forgery/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Brute Force 22</a>
          , модуль CSRF (для демонстрации важности токенов для {' '}
          <a href="https://portswigger.net/web-security/all-materials" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">сессии 36</a>
          ). Использование уровней {' '}
          <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Low/Medium.2</a>
        </>,
        <>
          TryHackMe: Комната {' '}
          <a href="https://www.vaadata.com/blog/exploiting-the-ssrf-vulnerability/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Hydra 113</a>
          , <a href="https://owasp.org/www-project-damn-vulnerable-web-sockets/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Brute Force Heroes 114</a>
          , комната {' '}
          <a href="https://github.com/juice-shop/juice-shop/blob/master/SOLUTIONS.md" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">IDOR 47</a>
          , комната Authentication {' '}
          <a href="https://owasp.org/www-project-developer-guide/release/training_education/vulnerable_applications/juice_shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Bypass.69</a>
        </>,
        <>
          Инструменты: Burp Suite (Intruder, Sequencer, Repeater, Comparer, {' '}
          <a href="https://www.packtpub.com/en-SG/product/security-monitoring-with-wazuh-9781837632152/chapter/chapter-1-intrusion-detection-system-ids-using-wazuh-2/section/testing-web-based-attacks-using-dvwa-ch02lvl1sec07" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Autorize extension 121</a>
          , <a href="https://tryhackme.com/resources/blog/hydra" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">JWT Editor extension 117</a>
          ), <a href="https://portswigger.net/web-security/cross-site-scripting/stored" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Hydra.9</a>
        </>
      ]} />
    </ContentPageLayout>
  );
}
