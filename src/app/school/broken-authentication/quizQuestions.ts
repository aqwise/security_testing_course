interface QuizQuestion {
    question: string;
    answers: string[];
    correctAnswerIndex: number;
    explanation: string;
    link: {
        label: string;
        url: string;
    };
}

export const quizQuestions: QuizQuestion[] = [
    {
        question: "Что является основной причиной уязвимости Broken Authentication?",
        answers: [
            "Неправильная реализация функций управления сессиями, идентификацией и защиты учётных данных пользователей",
            "Ошибки в SQL запросах базы данных",
            "Отсутствие SSL/TLS сертификата на сервере",
            "Использование устаревшей версии браузера пользователем",
            " Недостаточная мощность серверного оборудования",
            "Плохой дизайн пользовательского интерфейса",
            "Отсутствие документации проекта"
        ],
        correctAnswerIndex: 0,
        explanation: "Broken Authentication возникает из-за недоработок в механизмах управления идентификацией, сессиями и credentials. Это включает слабые пароли, уязвимые токены, некорректное управление сессиями, отсутствие MFA.",
        link: {
            label: "OWASP: Broken Authentication",
            url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        }
    },
    {
        question: "Что такое Credential Stuffing?",
        answers: [
            "Атака с использованием пар логин/пароль, утекших с других сайтов, для автоматического перебора на целевом ресурсе",
            "Заполнение форм входа случайными данными для тестирования",
            "Тип SQL-инъекции, специфичный для формы логина",
            "Переполнение буфера паролей на стороне сервера",
            "Автоматическое заполнение формы браузером",
            "Фишинговая атака с подменой формы входа",
            "Метод социальной инженерии для выманивания паролей"
        ],
        correctAnswerIndex: 0,
        explanation: "Credential Stuffing — автоматизированная атака, когда бот пробует миллионы пар логин:пароль из утечек (например, Collection #1). Успех = 0.1-2% из-за переиспользования паролей.",
        link: {
            label: "OWASP: Credential Stuffing",
            url: "https://owasp.org/www-community/attacks/Credential_stuffing"
        }
    },
    {
        question: "Чем Password Spraying отличается от классического Brute Force?",
        answers: [
            "Spraying пробует несколько популярных паролей для многих аккаунтов, Brute Force перебирает множество паролей для одного аккаунта",
            "Password Spraying работает значительно быстрее по времени",
            "Spraying используется исключительно для взлома WiFi-сетей",
            "Это одинаковые атаки с разными названиями",
            "Brute Force требует физического доступа к серверу",
            "Spraying — это легальная technique пентестинга",
            "Brute Force работает только с числовыми PIN-кодами"
        ],
        correctAnswerIndex: 0,
        explanation: "Password Spraying обходит блокировки по попыткам: вместо 100 паролей для user1, пробуется 'Password123!' для user1, user2... user100. Это предотвращает account lockout.",
        link: {
            label: "PortSwigger: Password Attacks",
            url: "https://portswigger.net/web-security/authentication/password-based"
        }
    },
    {
        question: "Какой уровень гарантии аутентификации NIST AAL требует аппаратный токен?",
        answers: [
            "AAL 3 — требует криптографический аппаратный ключ или многофакторную аутентификацию с устойчивостью к фишингу",
            "AAL 1 — однофакторная аутентификация паролем",
            "AAL 2 — двухфакторная аутентификация любого типа",
            "Ни один из уров ней не требует аппаратного токена",
            "AAL 0 — самый базовый уровень без требований",
            "AAL 4 — экспериментальный уровень для военных систем",
            "Любой уровень в зависимости from политики компании"
        ],
        correctAnswerIndex: 0,
        explanation: "NIST AAL 3 — самый строгий уровень. Требует multi-factor authentication с hardware cryptographic authenticator (FIDO2/WebAuthn, Smart Card).",
        link: {
            label: "NIST SP 800-63B",
            url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
    },
    {
        question: "Почему даже сложного пароля недостаточно для критичных систем?",
        answers: [
            "Пароль может быть украден через фишинг, кейлоггер, утечку базы данных — MFA защищает от компрометации credentials",
            "Пользователи часто забывают сложные пароли и не могут войти",
            "Сложные пароли занимают слишком много места в базе данных",
            "Это требование усложняет пользовательский интерфейс",
            "Хеширование сложных паролей замедляет сервер",
            "Сложные пароли плохо работают с автозаполнением браузера",
            "Это требование только для compliance, а не реальной безопасности"
        ],
        correctAnswerIndex: 0,
        explanation: "Принцип Defense in Depth: даже если пароль утёк (phishing, malware, breach), MFA блокирует атакующего. Пароль — это 'что вы знаете', MFA добавляет 'что у вас есть' или 'кто вы'.",
        link: {
            label: "OWASP: Multi-Factor Authentication",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое Session Fixation атака?",
        answers: [
            "Атака, при которой злоумышленник навязывает жертве известный Session ID, чтобы войти в аккаунт после успешной авторизации",
            "Зависание или замерзание сессии из-за ошибки сервера",
            "Автоматическая фиксация времени входа пользователя в систему",
            "Жёсткая привязка сессии к конкретному IP-адресу клиента",
            "Сохранение сессии в постоянном storage вместо временного",
            "Метод восстановления сессии после разрыва соединения",
            "Техника синхронизации сессий между несколькими серверами"
        ],
        correctAnswerIndex: 0,
        explanation: "Session Fixation: атакующий получает session_id (например, PHPSESSID=abc123), отправляет жертве ссылку с этим ID. Жертва логинится → session_id=abc123 становится авторизованным. Атакующий использует abc123 для доступа.",
        link: {
            label: "OWASP: Session Fixation",
            url: "https://owasp.org/www-community/attacks/Session_fixation"
        }
    },
    {
        question: "Где безопаснее всего хранить Session ID на стороне клиента?",
        answers: [
            "В HttpOnly Cookie с флагами Secure и SameSite для защиты от XSS и CSRF",
            "В LocalStorage для постоянного хранения",
            "В SessionStorage как временное хранилище",
            "В URL параметрах для удобства передачи",
            "В скрытых полях HTML-форм на странице",
            "В переменных JavaScript в памяти браузера",
            "В IndexedDB как структурированное хранилище"
        ],
        correctAnswerIndex: 0,
        explanation: "HttpOnly Cookie предотвращает доступ JavaScript к session_id (защита от XSS). Secure — только HTTPS. SameSite — защита от CSRF. LocalStorage/SessionStorage доступны для JS и уязвимы к XSS.",
        link: {
            label: "OWASP: Session Management",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Что делает флаг HttpOnly для Cookie?",
        answers: [
            "Запрещает доступ к cookie через JavaScript (document.cookie), защищая session ID от кражи при XSS-атаках",
            "Шифрует содержимое cookie с использованием AES-256",
            "Разрешает передачу cookie только по незащищённому HTTP без HTTPS",
            "Автоматически удаляет cookie сразу после закрытия вкладки браузера",
            "Ограничивает размер cookie до 4KB байт",
            "Делает cookie видимой только для GET-запросов",
            "Отключает SameSite политику для данной cookie"
        ],
        correctAnswerIndex: 0,
        explanation: "HttpOnly — ключевая защита от Session Hijacking через XSS. Если на сайте есть XSS, атакующий НЕ сможет выполнить document.cookie для кражи session_id.",
        link: {
            label: "MDN: HttpOnly Cookies",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"
        }
    },
    {
        question: "Что делает флаг Secure для Cookie?",
        answers: [
            "Разрешает передачу cookie только по зашифрованному HTTPS-соединению, предотвращая перехват через MitM",
            "Запрещает любое изменение или удаление cookie из браузера",
            "Автоматически проверяет сложность пароля пользователя при входе",
            "Скрывает cookie от панели разработчика DevTools",
            "Шифрует значение cookie на стороне кли ента",
            "Требует двухфакторную аутентификацию для доступа к cookie",
            "Блокирует отправку cookie на поддомены сайта"
        ],
        correctAnswerIndex: 0,
        explanation: "Secure flag предотвращает отправку session cookie по незащищённому HTTP. Это защищает от перехвата в публичных WiFi сетях (MitM attacks).",
        link: {
            label: "MDN: Secure Cookies",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies"
        }
    },
    {
        question: "Какое требование к сложности пароля устарело согласно NIST SP 800-63B?",
        answers: [
            "Принудительная периодическая смена пароля (каждые 60-90 дней) без признаков компрометации — ведёт к слабым паролям",
            "Минимальная длина пароля 8 символов для пользовательских аккаунтов",
            "Полный запрет на использование простых и часто встречающихся паролей",
            "Проверка паролей по базам известных утечек (Have I Been Pwned)",
            "Требование использования букв верхнего и нижнего регистра",
            "Обязательное наличие специальных символов в пароле",
            "Запрет на повторное использование последних 5 паролей"
        ],
        correctAnswerIndex: 0,
        explanation: "NIST отказался от forced periodic password changes. Это приводит к предсказуемым изменениям (Password1 → Password2) и запутыванию пользователей. Меняйте пароли только при подозрении на компрометацию.",
        link: {
            label: "NIST SP 800-63B: Password Guidelines",
            url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
    },
    {
        question: "Почему нельзя хранить пароли в открытом виде (plaintext)?",
        answers: [
            "При утечке базы данных злоумышленники мгновенно получают доступ ко всем аккаунтам без дополнительных усилий",
            "Открытые пароли занимают слишком много дискового пространства",
            "Это нарушает физический закон Ома в электронике",
            "Браузеры не смогут корректно автозаполнять такие пароли",
            "Открытое хранение замедляет процесс аутентификации",
            "Это приводит к конфликтам в системе контроля версий",
            "База данных не сможет индексировать текстовые пароли"
        ],
        correctAnswerIndex: 0,
        explanation: "Plaintext passwords — критическая уязвимость. При breach атакующий получает немедленный доступ + пользователи переиспользуют пароли (доступ к email, банкам). Всегда используйте strong hashing!",
        link: {
            label: "OWASP: Password Storage",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Какой алгоритм НЕ рекомендуется для хеширования паролей?",
        answers: [
            "MD5 — слишком быстрый, уязвим к rainbow tables, collision attacks, GPU brute-force",
            "Argon2 — современный winner PHC (Password Hashing Competition)",
            "Bcrypt — проверенный временем, memory-hard алгоритм",
            "PBKDF2 — используется в многих enterprise-стандартах",
            "Scrypt — memory-hard алгоритм, устойчивый к ASIC",
            "Argon2id — гибридный вариант Argon2 (рекомендован OWASP)",
            "Bcrypt с cost factor 12 или выше"
        ],
        correctAnswerIndex: 0,
        explanation: "MD5 и SHA1 — криптографически сломаны, слишком быстрые (миллиарды хешей/сек на GPU). Используйте Argon2id (лучший), bcrypt или scrypt с солью и высоким work factor.",
        link: {
            label: "OWASP: Password Hashing Algorithms",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое 'Соль' (Salt) при хешировании паролей?",
        answers: [
            "Уникальная случайная строка, добавляемая к паролю перед хешированием для защиты от Rainbow Tables и dictionary attacks",
            "Секретный master-ключ сервера для шифрования базы данных",
            "Дополнительный резервный пароль для восстановления доступа",
            "Химический элемент для улучшения производительности сервера",
            "Префикс для создания более читаемых хешей",
            "Дополнительный фактор аутентификации после пароля",
            "Механизм ротации ключей шифрования"
        ],
        correctAnswerIndex: 0,
        explanation: "Salt делает каждый хеш уникальным даже для одинаковых паролей: hash(password1 + salt_A) ≠ hash(password1 + salt_B). Это предотвращает использование pre-computed rainbow tables.",
        link: {
            label: "OWASP: Password Salting",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое JWT (JSON Web Token)?",
        answers: [
            "Стандарт для создания компактных URL-safe токенов, содержащих JSON claims и криптографическую подпись для stateless аутентификации",
            "Формат базы данных для хранения пользовательских данных в JSON",
            "Новый язык программирования для веб-разработки",
            "Протокол шифрования данных между клиентом и сервером",
            "JavaScript-библиотека для работы с токенами",
            "Расширение формата XML для передачи credentials",
            "Механизм сжатия JSON-данных для оптимизации трафика"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT = Header.Paylaod.Signature (Base64). Stateless: сервер не хранит сессии, все данные в токене. Используется в API, microservices, OAuth 2.0. Важно: проверять подпись, не хранить secrets в payload!",
        link: {
            label: "JWT.io Introduction",
            url: "https://jwt.io/introduction"
        }
    },
    {
        question: "В чём опасность алгоритма 'None' в заголовке JWT?",
        answers: [
            "Позволяет полностью отключить проверку подписи, давая возможность подделать любой токен без знания secret key",
            "Делает токен слишком большим по размеру для HTTP-заголовков",
            "Несовместим с современными веб-браузерами и мобильными приложениями",
            "Требует избыточные вычислительные ресурсы процессора",
            "Автоматически истекает через 1 минуту после создания",
            "Делает токен нечитаемым для debugging и логирования",
            "Не поддерживается спецификацией RFC 7519"
        ],
        correctAnswerIndex: 0,
        explanation: "CVE-2015-9235: атакующий меняет alg: 'RS256' → 'none', удаляет подпись. Vulnerable серверы игнорируют проверку. Всегда явно указывайте whitelist алгоритмов (RS256, HS256) и reject 'none'!",
        link: {
            label: "Critical JWT Vulnerability",
            url: "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
        }
    },
    {
        question: "Должен ли Session ID быть предсказуемым (например, user_1, user_2, user_3)?",
        answers: [
            "Нет, он должен быть длинным (минимум 128 бит) и криптографически случайным для предотвращения Session Hijacking",
            "Да, последовательные ID удобнее для отладки и мониторинга",
            "Да, это значительно экономит память сервера и базы данных",
            "Зависит от типа используемой СУБД (MySQL vs PostgreSQL)",
            "Да, но только для внутренних корпоративных приложений",
            "Нет, но только если используется HTTPS",
            "Да, если дополнительно проверять IP-адрес пользователя"
        ],
        correctAnswerIndex: 0,
        explanation: "Предсказуемый session ID = Session Hijacking. Если ID последовательные, атакующий может перебрать соседние значения. Используйте crypto.randomBytes() или аналог с энтропией ≥128 бит.",
        link: {
            label: "OWASP: Session ID Generation",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое Brute Force атака на аутентификацию?",
        answers: [
            "Полный систематический перебор всех возможных комбинаций пароля или PIN-кода для получения доступа к аккаунту",
            "Атака через методы социальной инженерии и фишинга",
            "Физическое удаление базы данных с сервера",
            "Перехват и анализ сетевого трафика",
            "Эксплуатация уязвимостей нулевого дня (0-day)",
            "Атака на DNS-серверы для подмены записей",
            "Внедрение вредоносного кода в клиентское приложение"
        ],
        correctAnswerIndex: 0,
        explanation: "Brute Force: перебор всех возможных паролей. Для 6-значного PIN = 1,000,000 вариантов. Для 8-символьного пароля (a-z, A-Z, 0-9, symbols) ≈ 6.6 квадриллионов. Защита: rate limiting, account lockout, strong passwords.",
        link: {
            label: "PortSwigger: Brute-Force Attacks",
            url: "https://portswigger.net/web-security/authentication/password-based"
        }
    },
    {
        question: "Как эффективно защититься от Brute Force атак?",
        answers: [
            "Внедрить Rate Limiting, временную блокировку после N неудачных попыток, CAPTCHA и требовать сильные пароли",
            "Просто сделать поля ввода логина и пароля длиннее",
            "Использовать только транспортное шифрование трафика HTTPS",
            "Применять SVG-иконки вместо растровых изображений",
            "Ограничить длину пароля максимум 8 символами",
            "Отключить возможность восстановления пароля",
            "Требовать смену пароля каждый день"
        ],
        correctAnswerIndex: 0,
        explanation: "Комплексная защита: exponential backoff (задержка растёт: 1с, 2с, 4с...), account lockout на 30 мин после 5 попыток, CAPTCHA после 3 попыток, IP-based rate limiting (max 100 req/час).",
        link: {
            label: "OWASP: Blocking Brute Force",
            url: "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
        }
    },
    {
        question: "Что такое Username Enumeration (перечисление пользователей)?",
        answers: [
            "Способность определить существование пользователя в системе по различающимся ответам сервера ('Неверный пароль' vs 'Пользователь не найден')",
            "Автоматическая процедура нумерации всех пользователей в базе данных",
            "Публичный вывод полного списка зарегистрированных пользователей на странице",
            "Подсчёт общего количества активных онлайн-пользователей на сайте",
            "Функция сортировки пользователей по алфавиту в админ-панели",
            "Автоматическое присвоение порядковых номеров новым регистрациям",
            "Экспорт списка email-адресов для маркетинговой рассылки"
        ],
        correctAnswerIndex: 0,
        explanation: "User Enumeration — information disclosure. Разные ответы ('User not found' vs 'Wrong password') или время ответа (200ms vs 500ms) позволяют выяснить действительные логины для таргетированных атак.",
        link: {
            label: "PortSwigger: Username Enumeration",
            url: "https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses"
        }
    },
    {
        question: "Как исправить уязвимость Username Enumeration в форме входа?",
        answers: [
            "Возвращать одинаковое generic сообщение для всех случаев: 'Неверный логин или пароль', с одинаковым временем ответа",
            "Полностью удалить форму входа с веб-сайта",
            "Выводить 'Логин верный, пожалуйста введите правильный пароль'",
            "Показывать user_id пользователя, если он найден в системе",
            "Отображать CAPTCHA только для несуществующих логинов",
            "Логировать все попытки входа в публичный файл",
            "Отправлять email владельцу при каждой попытке входа"
        ],
        correctAnswerIndex: 0,
        explanation: "Generic error message + constant-time comparison. Также: одинаковый HTTP status (400 всегда), одинаковая длина ответа. Timing attack защита: добавить случайную задержку или hash даже для несуществующих users.",
        link: {
            label: "OWASP: Authentication Error Messages",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        }
    },
    {
        question: "Безопасно ли передавать Session ID в URL (например, ?sessionid=abc123)?",
        answers: [
            "Нет, URL сохраняется в browser history, server logs, proxy logs, Referer headers — высокий риск Session Hijacking",
            "Да, это стандартная и безопасная практика для Java-приложений",
            "Да, если обязательно используется HTTPS-соединение",
            "Безопасно только для аккаунтов администраторов",
            "Да, современные браузеры автоматически шифруют URL",
            "Безопасно, если session ID короче 16 символов",
            "Да, если дополнительно проверяется User-Agent header"
        ],
        correctAnswerIndex: 0,
        explanation: "Session ID в URL: сохраняется в истории браузера, логах веб-сервера/прокси, передаётся через Referer header. Атака: злоумышленник получает доступ к логам или жертва кликает внешнюю ссылку → session ID утёк.",
        link: {
            label: "OWASP: Session ID in URL",
            url: "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"
        }
    },
    {
        question: "Какое максимальное время жизни (Idle Timeout) должно быть у сессии?",
        answers: [
            "Минимально возможное, балансируя безопасность и UX — обычно 15-30 минут для банков, 1-2 часа для обычных сайтов",
            "Сессия должна жить бесконечно для удобства пользователей",
            "Строго ровно 24 часа без исключений",
            "Минимум 1 год для снижения нагрузки на сервер",
            "Зависит от цвета логотипа компании",
            "Idle timeout не влияет на безопасность",
            "Всегда 5 минут независимо от типа приложения"
        ],
        correctAnswerIndex: 0,
        explanation: "Idle timeout — это компромисс Security vs UX. Банки: 5-15 mins. E-commerce: 30-60 mins. Social: 1-24 hours. Учитывайте: риск компрометации, ценность данных, PCI DSS (15 mins для карточных данных).",
        link: {
            label: "OWASP: Session Timeouts",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Что нужно делать с Session ID после успешного входа пользователя?",
        answers: [
            "Сгенерировать новый Session ID (Session Rotation/Regeneration), чтобы предотвратить Session Fixation атаки",
            "Оставить тот же самый Session ID для удобства отладки",
            "Записать старый Session ID в лог-файл на сервере",
            "Отправить старый Session ID пользователю по электронной почте",
            "Увеличить значение Session ID на единицу",
            "Сохранить Session ID в LocalStorage браузера",
            "Конвертировать Session ID в Base64 кодировку"
        ],
        correctAnswerIndex: 0,
        explanation: "Session Regeneration после login — защита от Session Fixation. Старый ID (возможно известный атакующему) → новый криптостойкий ID после авторизации. Также regenerate при изменении прав (privilege elevation).",
        link: {
            label: "OWASP: Session Fixation Prevention",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое функционал 'Remember Me' и какие риски он несёт?",
        answers: [
            "Долгоживущая (weeks/months) сессия для convenience. Риск: если устройство украдено/скомпрометировано — полный доступ к аккаунту",
            "Автоматическое напоминание пароля пользователю через SMS",
            "Встроенная функция браузера для автозаполнения",
            "Всплывающее окно с подсказкой при забытом пароле",
            "Email-уведомление о последнем времени входа",
            "Синхронизация сессии между разными устройствами",
            "Функция резервного копирования учётных данных"
        ],
        correctAnswerIndex: 0,
        explanation: "'Remember Me' = persistent cookie (expiry: 30 days). Риски: физический доступ к устройству, malware. Лучшие практики: отдельный remember_token (не session_id), IP binding, device fingerprinting, обязательный re-auth для sensitive actions.",
        link: {
            label: "OWASP: Persistent Login",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Какой атрибут Cookie помогает защититься от CSRF атак?",
        answers: [
            "SameSite (Strict или Lax) — предотвращает отправку cookies при cross-site запросах с других доменов",
            "HttpOnly — защищает от доступа через JavaScript",
            "Secure — требует HTTPS для передачи cookie",
            "Domain — определяет область видимости cookie",
            "Path — ограничивает URL-пути для cookie",
            "Max-Age — устанавливает время жизни cookie",
            "Expires — задаёт дату истечения cookie"
        ],
        correctAnswerIndex: 0,
        explanation: "SameSite: Strict = cookies не отправляются при любых cross-site запросах. Lax = отправляются при top-level navigation (клик по ссылке), но не при iframe/fetch. Это core защита от CSRF наряду с CSRF tokens.",
        link: {
            label: "MDN: SameSite Cookies",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
        }
    },
    {
        question: "Являются ли SMS OTP надёжным вторым фактором аутентификации?",
        answers: [
            "Нет, SMS уязвимы к SIM Swapping, SS7-атакам, interception — лучше использовать TOTP-приложения (Google/Microsoft Authenticator)",
            "Да, это самый безопасный и надёжный метод MFA",
            "Да, но только если мобильный телефон выключен",
            "Работает надёжно только на iPhone, не на Android",
            "Безопасно только в странах с продвинутой телеком-инфраструктурой",
            "SMS безопаснее аппаратных ключей типа YubiKey",
            "Да, если используется 5G вместо 4G сети"
        ],
        correctAnswerIndex: 0,
        explanation: "SMS 2FA лучше, чем ничего, но уязвимы: SIM Swapping (social engineering оператора), SS7 exploits (перехват SMS), phishing (жертва вводит код на фейковом сайте). TOTP (RFC 6238) или WebAuthn — намного безопаснее.",
        link: {
            label: "NIST: SMS Authentication",
            url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
    },
    {
        question: "Что такое TOTP (Time-based One-Time Password)?",
        answers: [
            "Временный одноразовый 6-значный код, генерируемый на базе shared secret и текущего времени (обновляется каждые 30 сек)",
            "Top Of The Page — позиция элемента на веб-странице",
            "Total Online Transaction Protocol для банковских переводов",
            "Type Of Token Padding в криптографии",
            "Технология оптимизации производительности сервера",
            "Торговая платформа для криптовалют",
            "Temporary Offline Transfer Protocol для мобильных платежей"
        ],
        correctAnswerIndex: 0,
        explanation: "TOTP (RFC 6238): HMAC(secret_key, floor(current_time / 30)) → 6-digit code. Google Authenticator, Microsoft Authenticator используют TOTP. Offline, не требует SMS/интернета, устойчив к phishing лучше SMS.",
        link: {
            label: "RFC 6238: TOTP",
            url: "https://datatracker.ietf.org/doc/html/rfc6238"
        }
    },
    {
        question: "Как работает атака на функцию восстановления пароля через 'Секретный вопрос'?",
        answers: [
            "Злоумышленник находит ответ через социальные сети жертвы (девичья фамилия матери, школа, кличка питомца) и сбрасывает пароль",
            "Хакер напрямую взламывает почтовый ящик пользователя",
            "Атакующий звонит в службу техподдержки под видом жертвы",
            "Это полностью безопасный метод восстановления пароля",
            "Взлом через перебор всех возможных ответов",
            "Атака требует физического доступа к устройству жертвы",
            "Использование SQL-инъекции в форме секретного вопроса"
        ],
        correctAnswerIndex: 0,
        explanation: "Security Questions — слабое звено! Ответы легко гуглятся (LinkedIn, Facebook). Пример: Sarah Palin email hack (2008). Альтернативы: email/SMS recovery tokens, backup codes, support verification.",
        link: {
            label: "OWASP: Forgot Password",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
        }
    },
    {
        question: "Безопасно ли отправлять новый пароль напрямую на email при восстановлении?",
        answers: [
            "Нет, лучше отправлять временную ссылку для сброса (reset token с TTL), чтобы пользователь сам установил новый пароль",
            "Да, это удобно и безопасно для пользователей",
            "Безопасно только если пароль достаточно сложный",
            "Да, если почтовый ящик находится на Gmail",
            "Нет, но только для корпоративных email-адресов",
            "Да, если пароль отправляется в зашифрованном виде",
            "Безопасно только для временных тестовых аккаунтов"
        ],
        correctAnswerIndex: 0,
        explanation: "Пароль в email — риски: email может быть перехвачен, хранится в почте навсегда, админы email-сервера видят пароль. Best practice: отправить одноразовую ссылку с токеном (expires 1 hour), пользователь сам задаёт новый пароль.",
        link: {
            label: "OWASP: Password Reset",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
        }
    },
    {
        question: "Может ли функция Logout (выход) быть небезопасной?",
        answers: [
            "Да, если сессия не инвалидируется на сервере, злоумышленник с украденной cookie сможет продолжать её использовать",
            "Нет, logout просто удаляет cookie на клиенте — этого достаточно",
            "Logout небезопасен только по пятницам после 18:00",
            "Да, но только если кнопка выхода красного цвета",
            "Нет, HTTPS автоматически защищает logout",
            "Logout не влияет на безопасность сессии",
            "Да, если пользователь выходит слишком быстро после входа"
        ],
        correctAnswerIndex: 0,
        explanation: "Proper logout: удалить cookie на клиенте + инвалидировать session_id на сервере (удалить из Redis/DB). Иначе: атакующий с украденной cookie продолжит иметь доступ даже после logout жертвы!",
        link: {
            label: "OWASP: Session Termination",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Где НЕЛЬЗЯ хранить секретные ключи для подписи JWT?",
        answers: [
            "В коде фронтенда, публичном Git-репозитории или hardcoded в исходниках — всегда используйте переменные окружения или Secrets Manager",
            "В переменных окружения сервера (environment variables)",
            "В специализированном хранилище секретов (HashiCorp Vault, AWS Secrets Manager)",
            "В конфигурационных файлах с ограниченными правами доступа",
            "В зашифрованной базе данных на сервере",
            "В защищённом Key Management Service (KMS)",
            "В Hardware Security Module (HSM) для критичных систем"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT secret в коде/репозитории = full compromise. Любой с доступом к коду может подделать токены. Используйте: env variables (минимум), Vault/Secrets Manager (лучше), rotate keys регулярно.",
        link: {
            label: "OWASP: Cryptographic Storage",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое Default Credentials?",
        answers: [
            "Стандартные логины и пароли (admin/admin, root/root), установленные производителем оборудования или софта по умолчанию",
            "Наилучшие рекомендованные настройки безопасности системы",
            "Банковские кредитные карты по умолчанию",
            "Стандартные настройки браузера для автозаполнения",
            "Название команды разработчиков по умолчанию",
            "Дефолтные цвета интерфейса приложения",
            "Стандартный размер шрифта в системе"
        ],
        correctAnswerIndex: 0,
        explanation: "Default credentials — огромная проблема IoT, роутеров, камер. Mirai botnet (2016) — 600k устройств взломано через admin/admin. ВСЕГДА меняйте дефолтные пароли при первом входе! Сканеры: Shodan ищут такие устройства.",
        link: {
            label: "OWASP: Default Passwords",
            url: "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
        }
    },
    {
        question: "Какая минимальная длина должна быть у криптографически стойкого Session ID?",
        answers: [
            "Минимум 128 бит энтропии (16 байт), что даёт 2^128 возможных комбинаций для предотвращения brute-force",
            "Достаточно 4 символов для удобства",
            "Длина зависит от имени пользователя в системе",
            "Одна цифра или буква для оптимизации",
            "Максимум 8 символов по стандарту безопасности",
            "16 символов, но только буквы без цифр",
            "Длина Session ID не влияет на безопасность"
        ],
        correctAnswerIndex: 0,
        explanation: "128 бит = 32 hex символа или 22 Base64 символа. Это даёт ~3.4×10^38 комбинаций. Даже при 1 млрд попыток/сек потребуется 10^22 лет для перебора. Используйте crypto.randomBytes(16).",
        link: {
            label: "OWASP: Session ID Entropy",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Является ли Base64 шифрованием или хешированием?",
        answers: [
            "Нет, это просто обратимая кодировка (encoding) — любой может легко декодировать Base64 без ключа",
            "Да, это очень сильное военное шифрование",
            "Да, но работает только для изображений",
            "Это односторонняя хеш-функция как MD5",
            "Да, это современный стандарт асимметричного шифрования",
            "Base64 — это протокол аутентификации",
            "Это метод сжатия данных без потерь"
        ],
        correctAnswerIndex: 0,
        explanation: "Base64 — encoding, не encryption! Используется для передачи бинарных данных в текстовом формате (JWT, email attachments). НЕ скрывает данные: atob('SGVsbG8=') → 'Hello'. Никогда не используйте для паролей!",
        link: {
            label: "MDN: Base64",
            url: "https://developer.mozilla.org/en-US/docs/Glossary/Base64"
        }
    },
    {
        question: "Как ограничить время действия JWT токена?",
        answers: [
            "Использовать claim 'exp' (expiration timestamp) в payload и обязательно проверять его на сервере при каждом запросе",
            "Просто удалить токен из браузера через JavaScript",
            "JWT токены всегда живут вечно без возможности истечения",
            "Попросить пользователя вручную выйти из системы",
            "Установить короткий TTL для HTTP-заголовков",
            "Использовать только symmetric алгоритмы подписи",
            "Отправить уведомление пользователю когда токен истёк"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT exp claim (Unix timestamp): { exp: 1704672000 }. Сервер ОБЯЗАН проверять: if (Date.now() > token.exp * 1000) reject(). Также используйте 'iat' (issued at), 'nbf' (not before). Short TTL (15 min) + refresh token — best practice.",
        link: {
            label: "JWT Claims",
            url: "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1"
        }
    },
    {
        question: "Что делать если секретный ключ подписи JWT скомпрометирован?",
        answers: [
            "Немедленно сменить ключ (Key Rotation) и принудительно разлогинить всех пользователей — старые токены станут невалидными",
            "Ничего страшного, просто тихо сменить ключ без уведомлений",
            "Полностью закрыть веб-сайт до расследования",
            "Отправить извинения пользователям по email",
            "Продолжить использовать скомпрометированный ключ",
            "Переключиться на симметричное шифрование",
            "Добавить дополнительный слой Base64 encoding"
        ],
        correctAnswerIndex: 0,
        explanation: "Compromised JWT secret = атакующий может forge любые токены. Действия: 1) Rotate key немедленно 2) Invalidate все активные токены (denylist или increment key version) 3) Re-auth всех пользователей 4) Incident response, audit logs.",
        link: {
            label: "JWT Security Best Practices",
            url: "https://tools.ietf.org/html/rfc8725"
        }
    },
    {
        question: "Можно ли использовать GET-запросы для передачи логина и пароля?",
        answers: [
            "Нет, GET-параметры остаются в browser history, server logs, proxy logs — всегда используйте POST с телом запроса",
            "Да, если обязательно используется HTTPS",
            "Да, это стандартная практика REST API",
            "Безопасно только для администраторских аккаунтов",
            "Да, современные браузеры автоматически шифруют GET-параметры",
            "Нет, но только на production серверах",
            "Да, если параметры закодированы в URL-encoding"
        ],
        correctAnswerIndex: 0,
        explanation: "GET с credentials: https://site.com/login?user=admin&pass=secret123. Проблемы: 1) Browser history 2) Server access logs 3) Proxy/CDN logs 4) Referer headers. Всегда используйте POST с credentials в request body!",
        link: {
            label: "OWASP: Authentication Mechanisms",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое Magic Link аутентификация?",
        answers: [
            "Passwordless вход: пользователю на email приходит одноразовая ссылка с временным токеном для автоматической авторизации",
            "Вход в систему с помощью магических заклинаний",
            "Стандартная OAuth 2.0 аутентификация через соцсети",
            "Вход по биометрическому отпечатку пальца",
            "Специальная ссылка только для премиум-пользователей",
            "Секретный URL для доступа к admin-панели",
            "Технология NFC для бесконтактного входа"
        ],
        correctAnswerIndex: 0,
        explanation: "Magic Links (Passwordless): user вводит email → сервер отправляет https://app.com/auth?token=xyz123 → клик → auto-login. Плюсы: нет паролей. Минусы: зависимость от email security, email в plain text. Используют: Slack, Medium.",
        link: {
            label: "Auth0: Passwordless Authentication",
            url: "https://auth0.com/docs/authenticate/passwordless"
        }
    },
    {
        question: "Нужно ли требовать повторный ввод пароля (Re-authentication) перед сменой email или пароля?",
        answers: [
            "Да обязательно — это подтверждает, что именно владелец аккаунта инициирует критичное действие, защищая от Session Hijacking",
            "Нет, пользователь уже залогинен и авторизован",
            "Только для очень старых аккаунтов (> 1 года)",
            "Нет, это слишком раздражает пользователей",
            "Только если пользователь заходит через VPN",
            "Да, но только на мобильных устройствах",
            "Нет, достаточно проверки CAPTCHA"
        ],
        correctAnswerIndex: 0,
        explanation: "Re-auth для sensitive actions защищает от: 1) Session Hijacking (украденная cookie) 2) XSS/CSRF с активной сессией 3) Shared computers. GitHub, Google требуют password при смене email/password, даже если вы залогинены!",
        link: {
            label: "OWASP: Re-authentication",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое CAPTCHA и для чего она используется?",
        answers: [
            "Тест для отличия людей от ботов (Completely Automated Public Turing test) — защищает от автоматизированных атак типа Brute Force",
            "Приложение для группового чата и видеоконференций",
            "Служба курьерской доставки посылок",
            "Специальный протокол end-to-end шифрования",
            "Система управления базами данных",
            "Метод двухфакторной аутентификации",
            "Алгоритм машинного обучения для классификации"
        ],
        correctAnswerIndex: 0,
        explanation: "CAPTCHA: решение задач (распознать текст, выбрать картинки с автобусами). Защищает от: account enumeration bots, credential stuffing, spam registration. Современные: reCAPTCHA v3 (invisible, risk scoring), hCaptcha.",
        link: {
            label: "OWASP: CAPTCHA",
            url: "https://owasp.org/www-community/controls/CAPTCHA"
        }
    },
    {
        question: "Почему не стоит разрабатывать собственные криптографические алгоритмы?",
        answers: [
            "Велик риск допустить критическую ошибку — всегда используйте проверенные стандартные библиотеки и алгоритмы (OpenSSL, NaCl)",
            "Это занимает слишком много времени разработки",
            "Собственные алгоритмы стоят дорого в поддержке",
            "Это запрещено международным законодательством",
            "Custom crypto работает только на определённых ОС",
            "Нужна специальная лицензия на разработку",
            "Это нарушает авторские права на существующие алгоритмы"
        ],
        correctAnswerIndex: 0,
        explanation: "Schneier's Law: 'Anyone can invent crypto they can't break themselves'. История полна broken custom crypto. Даже эксперты делают ошибки. Используйте battle-tested: AES, RSA, ECDSA, Argon2, проверенные библиотеки.",
        link: {
            label: "OWASP: Cryptographic Failures",
            url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        }
    },
    {
        question: "Что содержит Payload (второй раздел) JWT токена?",
        answers: [
            "Claims (утверждения) о пользователе: user_id, роль, имя + служебные данные: exp (expiration), iat (issued at), iss (issuer)",
            "Только криптографическую подпись токена",
            "Пароль пользователя в открытом текстовом виде",
            "Исходный код серверной части приложения",
            "Зашифрованный приватный ключ сервера",
            "HTML-разметку страницы пользователя",
            "Логи всех действий пользователя в системе"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT payload — это JSON, закодированный в Base64 (НЕ зашифрован!): {sub: 'user123', role: 'admin', exp: 1704672000}. НИКОГДА не храните пароли, secrets, sensitive PII в payload — это публичные данные!",
        link: {
            label: "JWT Claims",
            url: "https://datatracker.ietf.org/doc/html/rfc7519#section-4"
        }
    },
    {
        question: "Как предотвратить успешный login с украденными credentials (Credential Stuffing)?",
        answers: [
            "Внедрить MFA, проверять пароли по базам утечек (HaveIBeenPwned API), использовать device fingerprinting и behavioral analysis",
            "Полностью отключить доступ к интернету",
            "Никак невозможно защититься от этой атаки",
            "Использовать только устаревший Flash Player",
            "Требовать смену пароля каждый час",
            "Блокировать все IP-адреса кроме локальных",
            "Отключить форму входа полностью"
        ],
        correctAnswerIndex: 0,
        explanation: "Credential Stuffing defense: 1) MFA (ключевая защита) 2) Check passwords vs breach DBs 3) Rate limiting 4) IP reputation (block VPN/Tor) 5) Device fingerprinting (новое устройство → email alert) 6) CAPTCHA 7) Monitor anomalous logins.",
        link: {
            label: "OWASP: Credential Stuffing",
            url: "https://owasp.org/www-community/attacks/Credential_stuffing"
        }
    },
    {
        question: "Если приложение разрешает слабые пароли (123456, password), это уязвимость?",
        answers: [
            "Да, это Weak Password Policy — критическая уязвимость, позволяющая легко взломать аккаунты через brute-force или словарные атаки",
            "Нет, это свободный выбор каждого пользователя",
            "Уязвимость только для администраторских аккаунтов",
            "Нет, если дополнительно используется CAPTCHA",
            "Да, но только на финансовых платформах",
            "Нет, браузер защитит слабый пароль автоматически",
            "Уязвимость только если пользователь младше 18 лет"
        ],
        correctAnswerIndex: 0,
        explanation: "Weak Passwords — топовая причина взломов. Защита: 1) Min length 8+ chars 2) Проверка по blacklist (top 10k passwords) 3) Reject breached passwords (HIBP) 4) Password strength meter 5) Не enforce символы, но encourage длину (12-16+).",
        link: {
            label: "NIST Password Guidelines",
            url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
    },
    {
        question: "Нужно ли защищать API Bearer tokens так же строго, как пароли?",
        answers: [
            "Да, кража Bearer token эквивалентна краже пароля — атакующий получает полный доступ до истечения токена",
            "Нет, токены временные и не требуют защиты",
            "Защита нужна только для очень длинных токенов",
            "Нет, это ответственность клиентского приложения",
            "Да, но только для symmetric токенов",
            "Токены защищены HTTPS автоматически",
            "Нет, Bearer tokens самоуничтожаются при атаке"
        ],
        correctAnswerIndex: 0,
        explanation: "Bearer Token = доступ! Authorization: Bearer xyz123. Защита: 1) HttpOnly cookies (не localStorage!) 2) Short TTL (15 min) 3) HTTPS only 4) Bind to IP/device (опционально) 5) Token rotation 6) Никогда не логировать tokens.",
        link: {
            label: "OAuth 2.0: Bearer Tokens",
            url: "https://datatracker.ietf.org/doc/html/rfc6750"
        }
    },
    {
        question: "Что такое SSO (Single Sign-On)?",
        answers: [
            "Технология, позволяющая входить в множество разных приложений используя одну центральную аутентификацию (один логин для всех сервисов)",
            "Один пароль который используется всю жизнь",
            "Режим одиночной игры в онлайн-играх",
            "Сервер без установленной операционной системы",
            "Специальный тип SSL-сертификата",
            "Алгоритм симметричного шифрования",
            "Протокол для синхронизации времени"
        ],
        correctAnswerIndex: 0,
        explanation: "SSO: логин в Google → автоматический доступ к Gmail, Drive, YouTube. Протоколы: SAML 2.0, OAuth 2.0 + OpenID Connect, Kerberos. Плюсы: UX, централизованное управление. Минусы: single point of failure.",
        link: {
            label: "OWASP: SSO",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html"
        }
    },
    {
        question: "Какие риски несёт открытая регистрация без CAPTCHA или email verification?",
        answers: [
            "Массовое создание bot/spam аккаунтов, засорение БД, DoS через регистрацию, создание фейковых профилей для атак",
            "Никаких рисков, больше пользователей — лучше метрики",
            "Сервер начнёт работать быстрее от нагрузки",
            "Пользователи будут более довольны отсутствием проверок",
            "Автоматическое улучшение SEO-рейтинга сайта",
            "Снижение стоимости хостинга приложения",
            "Увеличение конверсии регистраций до 100%"
        ],
        correctAnswerIndex: 0,
        explanation: "Open registration risks: 1) Bot armies (spam, DDoS) 2) Fake accounts (scam, fraud) 3) Email bombing 4) Resource exhaustion. Защита: CAPTCHA, email verification (double opt-in), rate limiting, phone verification для sensitive apps.",
        link: {
            label: "OWASP: Account Registration",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        }
    },
    {
        question: "Что означает Sensitive Data Exposure в контексте URL?",
        answers: [
            "Передача токенов, паролей или session IDs в query-параметрах URL, которые сохраняются в логах и истории браузера",
            "Использование красивых человекочитаемых URL-адресов",
            "Обязательное применение HTTPS для всех запросов",
            "Создание коротких ссылок для удобства шаринга",
            "Использование динамических роутов в приложении",
            "SEO-оптимизация структуры URL сайта",
            "Локализация URL на разные языки"
        ],
        correctAnswerIndex: 0,
        explanation: "URL exposure: https://site.com/reset?token=secret123. Проблемы: 1) Referer header утекает на внешние сайты 2) Browser history 3) Server/proxy logs 4) Browser extensions читают URLs. Используйте POST + request body или cookies!",
        link: {
            label: "OWASP: Sensitive Data in URL",
            url: "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"
        }
    },
    {
        question: "Как часто нужно проводить аудит учётных записей администраторов?",
        answers: [
            "Регулярно (ежемесячно/ежеквартально) — удалять неиспользуемые аккаунты, проверять права доступа, убирать уволенных сотрудников",
            "Никогда не нужно проводить аудит",
            "Только после подтверждённого взлома системы",
            "Один раз в високосный год",
            "Аудит нужен только для рядовых пользователей",
            "Автоматически через Windows Update",
            "Только по запросу правоохранительных органов"
        ],
        correctAnswerIndex: 0,
        explanation: "Admin Account Audit: 1) Review: кому есть admin? зачем? 2) Offboarding: уволенные удалены? 3) Principle of Least Privilege: нужны ли все права? 4) Dormant accounts: >90 дней без входа → disable. 5) MFA enabled? 6) Strong passwords?",
        link: {
            label: "CIS Controls: Account Management",
            url: "https://www.cisecurity.org/controls"
        }
    },
    {
        question: "Достаточно ли client-side валидации (JavaScript) для формы входа?",
        answers: [
            "Нет, все проверки ОБЯЗАТЕЛЬНО дублировать на сервере — клиентский код легко обойти через DevTools или Burp Suite",
            "Да, client-side валидация снижает нагрузку на сервер",
            "Да, если использовать современный React-фреймворк",
            "Да, если JavaScript-код минифицирован и обфусцирован",
            "Достаточно только для мобильных приложений",
            "Да, браузеры не позволяют обойти JS-валидацию",
            "Нет, но только на production окружении"
        ],
        correctAnswerIndex: 0,
        explanation: "Client-side validation — только UX! Атакующий: отключить JS, изменить код через DevTools, перехватить request в Burp. ВСЕГДА валидируйте на сервере: длину, формат, санитизацию. 'Never trust user input'.",
        link: {
            label: "OWASP: Input Validation",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое WebAuthn (FIDO2)?",
        answers: [
            "Современный стандарт беспарольной аутентификации через биометрию или аппаратные ключи (YubiKey), устойчивый к фишингу",
            "Новый веб-браузер от Microsoft",
            "Плагин для WordPress для управления контентом",
            "Почтовый протокол для secure email",
            "JavaScript-библиотека для OAuth 2.0",
            "Система управления пользователями в Active Directory",
            "Протокол для distributed authentication в blockchain"
        ],
        correctAnswerIndex: 0,
        explanation: "WebAuthn (W3C standard): passwordless auth через public-key cryptography. Authenticators: 1) Platform (TouchID, FaceID, Windows Hello) 2) Roaming (YubiKey, Google Titan). Phishing-resistant! Атакующий не может переиспользовать credentials.",
        link: {
            label: "WebAuthn Guide",
            url: "https://webauthn.guide/"
        }
    },
    {
        question: "Чем опасны Секретные вопросы (Security Questions) для восстановления пароля?",
        answers: [
            "Ответы часто публичны или легко угадываются через соцсети (девичья фамилия матери, первая школа, кличка  питомца)",
            "Секретные вопросы абсолютно безопасны",
            "Они слишком сложные для запоминания пользователями",
            "Занимают слишком много места в базе данных",
            "Несовместимы с мобильными устройствами",
            "Требуют дополнительного HTTP-запроса",
            "Не поддерживаются международными стандартами"
        ],
        correctAnswerIndex: 0,
        explanation: "Security Questions: weak link! Примеры взломов: Sarah Palin (2008), Mat Honan/Apple (2012). Информация в LinkedIn, Facebook. Лучшие альтернативы: email/SMS recovery codes, backup codes, account recovery через support с ID verification.",
        link: {
            label: "NIST on Knowledge-Based Authentication",
            url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
    },
    {
        question: "Что такое параметр 'state' в OAuth 2.0 authorization flow?",
        answers: [
            "Случайный токен для защиты от CSRF-атак во время OAuth-авторизации через третью сторону (Google, Facebook)",
            "Название штата США пользователя",
            "Текущий статус сервера (online/offline)",
            "Административный пароль системы",
            "Версия протокола OAuth",
            "Идентификатор сессии пользователя",
            "Географическое местоположение клиента"
        ],
        correctAnswerIndex: 0,
        explanation: "OAuth 'state' — CSRF protection. Поток: 1) App генерирует random state, сохраняет в session 2) Redirect: https://oauth.com/auth?state=abc123 3) Callback: ?state=abc123&code=xyz 4) App проверяет: state из callback == state из session.",
        link: {
            label: "OAuth 2.0: State Parameter",
            url: "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12"
        }
    },
    {
        question: "Как работает JWT Algorithm Confusion Attack?",
        answers: [
            "Атакующий меняет алгоритм в header с asymmetric RS256 на symmetric HS256 и подписывает токен публичным ключом сервера как секретом",
            "Это просто удаление алгоритма из JWT header",
            "Смена языка программирования для обработки токенов",
            "Подмена алгоритма хеширования с SHA256 на MD5",
            "Запутывание порядка claims в payload секции",
            "Использование нескольких алгоритмов одновременно",
            "Конвертация JWT в формат XML"
        ],
        correctAnswerIndex: 0,
        explanation: "Algorithm Confusion: сервер ожидает RS256 (проверка через public key), но принимает HS256. Атакующий: 1) скачивает public key 2) меняет 'RS256'→'HS256' 3) подписывает через HMAC(public_key, data). Сервер проверяет с public_key как symmetric secret → успех!",
        link: {
            label: "Auth0: JWT Algorithm Confusion",
            url: "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
        }
    },
    {
        question: "Что такое JTI (JWT ID) claim и зачем он нужен?",
        answers: [
            "Уникальный идентификатор (UUID) токена для предотвращения Replay-атак и отслеживания отозванных токенов в denylist",
            "Идентификатор пользователя в системе",
            "Дата рождения владельца токена",
            "Тип токена (access vs refresh)",
            "JavaScript Token Interface для браузера",
            "Номер версии JWT спецификации",
            "Географический регион пользователя"
        ],
        correctAnswerIndex: 0,
        explanation: "JTI (unique identifier): {jti: 'uuid-123', sub: 'user1'}. Use cases: 1) Revoc ation: denylist содержит jti отозванных токенов 2) One-time use: сохранить jti после использования 3) Audit: tracking token usage.",
        link: {
            label: "RFC 7519: JTI Claim",
            url: "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7"
        }
    },
    {
        question: "Можно ли отозвать (revoke) stateless JWT токен до истечения exp?",
        answers: [
            "Сложно: нужен denylist (blacklist) с jti или короткое время жизни + refresh token strategy для implicit revocation",
            "Да, легко — просто удалить токен из браузера",
            "Да, отправить команду на отзыв всем клиентам",
            "Да, просто перезагрузить сервер",
            "Невозможно теоретически для любых JWT",
            "Да, через специальный REVOKE HTTP метод",
            "Автоматически происходит при logout"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT Revocation проблема stateless природы. Решения: 1) Short-lived access (15 min) + refresh tokens 2) Denylist: Redis с jti до exp 3) Token versioning: increment user.token_version 4) Accept small revocation delay 5) Stateful sessions для critical apps.",
        link: {
            label: "JWT Revocation Strategies",
            url: "https://tools.ietf.org/html/rfc8725"
        }
    },
    {
        question: "Что такое Account Lockout и в чём его потенциальная опасность?",
        answers: [
            "Временная блокировка после N неудачных попыток входа. Риск: DoS-атака через намеренную блокировку массы аккаунтов",
            "Полное удаление аккаунта из системы",
            "Смена пароля администратором",
            "Автоматический вход пользователя в систему",
            "Блокировка только IP-адреса злоумышленника",
            "Отключение двухфакторной аутентификации",
            "Временное отключение уведомлений"
        ],
        correctAnswerIndex: 0,
        explanation: "Account Lockout defense vs attack: Defense: блокирует brute-force. Attack: атакующий блокирует легальных пользователей. Балансировка: 1) Exponential backoff вместо hard lock 2) CAPTCHA после 3 попыток 3) IP-based limiting 4) Admin notification.",
        link: {
            label: "OWASP: Account Lockout",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое Timing Attack на форму входа?",
        answers: [
            "Определение существования пользователя по разнице во времени ответа сервера (хеширование vs б ыстрый reject)",
            "Атака по расписанию в определённое время суток",
            "DDoS-атака с временной синхронизацией",
            "Взлом через манипуляцию системным временем",
            "Перебор паролей с учётом часовых поясов",
            "Использование setTimeout для обхода защиты",
            "Атака на NTP-серверы для десинхронизации"
        ],
        correctAnswerIndex: 0,
        explanation: "Timing Attack: если user существует — сервер проверяет hash (200ms), если нет — immediate return (10ms). Атакующий измеряет время → enumeration. Защита: constant-time operations или hash для несуществующих users тоже (dummy hash).",
        link: {
            label: "Timing Attacks",
            url: "https://en.wikipedia.org/wiki/Timing_attack"
        }
    },
    {
        question: "Почему Host Header Injection опасен при сбросе пароля?",
        answers: [
            "Приложение использует Host header для построения reset link в email — атакующий подменяет на свой домен и перехватывает токен",
            "Это только ломает CSS стили письма",
            "Email вообще не отправится пользователю",
            "Получатель получит спам вместо письма",
            "Это нарушает MIME-type email",
            "Атака влияет только на SMTP-серверы",
            "Host Header не используется в email"
        ],
        correctAnswerIndex: 0,
        explanation: "Host Header Injection: код использует request.headers.host для генерации ссылки: `https://${Host}/reset?token=xyz`. Атака: Host: evil.com → письмо содержит https://evil.com/reset?token=xyz. User кликает → токен утёк! Используйте hardcoded domain!",
        link: {
            label: "PortSwigger: Password Reset Poisoning",
            url: "https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware"
        }
    },
    {
        question: "Что такое NoSQL Injection в контексте аутентификации?",
        answers: [
            "Использование операторов NoSQL ($ne, $gt) в JSON для обхода проверки пароля: {username: 'admin', password: {$ne: null}}",
            "Внедрение SQL-запросов в MongoDB",
            "Взлом MySQL через NoSQL интерфейс",
            "Ошибка синтаксиса в JavaScript коде",
            "Атака только на CouchDB, не MongoDB",
            "Injection через GraphQL мутации",
            "Подмена schema validation в Mongoose"
        ],
        correctAnswerIndex: 0,
        explanation: "NoSQL Injection (MongoDB): db.users.findOne({user: req.body.user, pass: req.body.pass}). Атака: {user: 'admin', pass: {$ne: ''}} → query: {user: 'admin', pass: {$ne: ''}} → match! Всегда валидируйте/санитизируйте input!",
        link: {
            label: "OWASP: NoSQL Injection",
            url: "https://owasp.org/www-community/attacks/NoSQL_Injection"
        }
    },
    {
        question: "Безопасно ли привязывать сессию к IP-адресу пользователя?",
        answers: [
            "Повышает безопасность, но ломает UX для пользователей с динамическим IP (mobile, WiFi-hopping, VPN, корпоративные proxy с multiple IPs)",
            "Да, абсолютно безопасно без недостатков",
            "Нет, IP-адрес нельзя технически определить на сервере",
            "Это запрещено протоколом HTTP/2",
            "Да, но только для пользователей IPv6",
            "IP binding эффективен только на localhost",
            "Нет, IP подменяется автоматически браузером"
        ],
        correctAnswerIndex: 0,
        explanation: "IP Binding: session привязана к IP. Если IP меняется → invalidate session. Проблемы: 1) Mobile users (cell tower changes) 2) Corporate NAT 3) VPN users 4) Legitimate IP changes. Альтернатива: device fingerprinting + геолокация аномалий.",
        link: {
            label: "OWASP: Session Binding",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое Offline Dictionary Attack на password hashes?",
        answers: [
            "После кражи БД хешей атакующий перебирает словарь паролей на мощных GPU offline без обращения к серверу — очень быстро",
            "Атака без подключения к интернету на роутер",
            "Чтение физической адресной книги жертвы",
            "Взлом через распечатанные словари",
            "Brute-force атака на выключенный сервер",
            "Перебор паролей через offline браузер",
            "Атака на backup копии базы данных"
        ],
        correctAnswerIndex: 0,
        explanation: "Offline Attack: после breach атакующий имеет файл с хешами. GPU может проверить billions hashes/sec (MD5: ~50 млрд/сек). Защита: 1) Slow hash (Argon2, bcrypt) 2) Salt (unique per user) 3) High work factor 4) Monitor for breaches.",
        link: {
            label: "Password Cracking",
            url: "https://en.wikipedia.org/wiki/Password_cracking"
        }
    },
    {
        question: "Помогает ли CAPTCHA от Offline-атаки на украденные хеши?",
        answers: [
            "Нет, CAPTCHA защищает online форму входа, но бесполезна если база хешей уже украдена и взламывается offline",
            "Да, CAPTCHA защищает БД от кражи",
            "Да, но только Google reCAPTCHA v3",
            "Да, если CAPTCHA сложная с аудио",
            "Нет, но hCaptcha защищает от offline атак",
            "Да, CAPTCHA шифрует хеши в базе",
            "Да, блокирует GPU для вычислений"
        ],
        correctAnswerIndex: 0,
        explanation: "CAPTCHA: online defense (блокирует боты на login). Offline attack: атакующий уже украл db_dump.sql, хеши локально. CAPTCHA не поможет! Защита от offline: strong hashing (Argon2id, cost 19+), unique salts, detect breaches early.",
        link: {
            label: "Defense in Depth",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Что делает Argon2 лучше MD5 для хеширования паролей?",
        answers: [
            "Argon2 — memory-hard алгоритм, делающий GPU/ASIC brute-force экономически нецелесообразным. MD5 слишком быстрый (миллиарды хешей/сек)",
            "Argon2 просто быстрее работает на сервере",
            "Argon2 создаёт более короткие хеши",
            "MD5 и Argon2 одинаковы по безопасности",
            "Argon2 работает только на Linux серверах",
            "MD5 более современный алгоритм",
            "Argon2 требует меньше CPU ресурсов"
        ],
        correctAnswerIndex: 0,
        explanation: "Argon2 (PHC winner 2015): memory-hard + time-hard. Настройки: memory cost (64 MB+), iterations (3+), parallelism. MD5: 50 млрд hash/sec на GPU. Argon2: ~10-100 hash/sec. Делает offline brute-force крайне дорогим.",
        link: {
            label: "Argon2 Spec",
            url: "https://github.com/P-H-C/phc-winner-argon2"
        }
    },
    {
        question: "Что такое Service Account и как его защитить?",
        answers: [
            "Техническая учётная запись для автоматизации/скриптов. Защита: без пароля (API keys/certificates), минимальные права, no UI access, rotation",
            "Аккаунт службы технической поддержки",
            "Основной административный аккаунт сервера",
            "Гостевой доступ для демонстраций",
            "Резервный аккаунт администратора",
            "Временный аккаунт для подрядчиков",
            "Shared аккаунт команды разработчиков"
        ],
        correctAnswerIndex: 0,
        explanation: "Service Accounts (bots, CI/CD, integrations): Risks: shared secrets, over-privileged. Best practices: 1) API keys/certificates (не пароли) 2) Least privilege 3) Short-lived tokens 4) No interactive login 5) Audit trail 6) Rotate credentials 7) Use managed identities (AWS IAM roles).",
        link: {
            label: "Google: Service Accounts Best Practices",
            url: "https://cloud.google.com/iam/docs/best-practices-service-accounts"
        }
    },
    {
        question: "Что такое SIM Swapping атака?",
        answers: [
            "Social engineering: атакующий убеждает мобильного оператора перевести номер жертвы на свою SIM для перехвата SMS с 2FA кодами",
            "Обмен SIM-картами между друзьями для роуминга",
            "Покупка новой SIM-карты того же оператора",
            "Технический взлом вышки сотовой связи 5G",
            "Клонирование SIM через Bluetooth",
            "Физическая кража телефона и извлечение SIM",
            "Перехват сигнала через SDR радио"
        ],
        correctAnswerIndex: 0,
        explanation: "SIM Swapping (SIM Hijacking): атакующий: 1) собирает info о жертве (social media) 2) звонит оператору, выдаёт себя за жертву 3) просит перенести номер на новую SIM 4) получает SMS 2FA → захват аккаунтов. Защита: PIN на SIM, TOTP вместо SMS, WebAuthn.",
        link: {
            label: "FBI: SIM Swapping",
            url: "https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-scams-and-crimes/sim-swap"
        }
    },
    {
        question: "Спасает ли SMS 2FA от реального phishing сайта?",
        answers: [
            "Нет, жертва вводит пароль И SMS-код на фейковом сайте → бот атакующего мгновенно использует их на real site → успешный вход",
            "Да, SMS код работает only на real сайте",
            "Защищает только на Android устройствах",
            "Да, если SMS приходит более 60 секунд",
            "Нет, SMS вообще не доходят до пользователя",
            "Защищает если использовать airplane mode",
            "Да, современные телефоны блокируют фишинг"
        ],
        correctAnswerIndex: 0,
        explanation: "Phishing + SMS 2FA bypass: Real-time relay attack. 1) Жертва → fake site: login+pass+SMS code 2) Бот → real site: login+pass 3) Real site → SMS → жертва 4) Жертва → fake site: код 5) Бот → real site: код → SUCCESS. Защита: WebAuthn/FIDO (domain-bound).",
        link: {
            label: "Evilginx2: Phishing с  2FA Bypass",
            url: "https://github.com/kgretzky/evilginx2"
        }
    },
    {
        question: "Что такое Phishing-Resistant MFA?",
        answers: [
            "Hardware security keys (FIDO2/WebAuthn/U2F), криптографически привязанные к домену — на фишинговом домене физически не сработают",
            "SMS одноразовые коды с шифрованием",
            "Push-уведомления в мобильном приложении",
            "Коды на бумажке (backup codes)",
            "Биометрия через веб-камеру",
            "Email с ссылкой для подтверждения",
            "Секретные вопросы с CAPTCHA"
        ],
        correctAnswerIndex: 0,
        explanation: "Phishing-Resistant MFA = FIDO2/WebAuthn (YubiKey, Windows Hello, TouchID). Криптография привязана к origin (https://real-bank.com). На https://fake-bank.com ключ НЕ сработает — атака провалится. SMS/TOTP уязвимы к phishing.",
        link: {
            label: "FIDO Alliance",
            url: "https://fidoalliance.org/"
        }
    },
    {
        question: "Что такое Race Condition при использовании одноразового кода/купона?",
        answers: [
            "Параллельная отправка нескольких запросов позволяет использовать код/купон многократно до того, как сервер пометит его как использованный",
            "Соревнование между пользователями за код",
            "Гонка автомобилей с промокодами",
            "Таймаут при медленном интернете",
            "Истечение срока действия купона",
            "Конкуренция за доменные имена",
            "Параллельное выполнение JavaScript кода"
        ],
        correctAnswerIndex: 0,
        explanation: "Race Condition: сервер проверяет 'код не использован?' → применяет → помечает 'использован'. Если 2 запроса параллельно → оба проверки pass → код сработает дважды. Защита: database locks, atomic operations, idempotency keys.",
        link: {
            label: "Race Conditions in Web Apps",
            url: "https://portswigger.net/web-security/race-conditions"
        }
    },
    {
        question: "Нужно ли ограничивать количество одновременных сессий пользователя?",
        answers: [
            "Рекомендуется для критичных сервисов — предотвращает sharing аккаунтов и помогает обнаружить компрометацию (аномальные locations)",
            "Нет, пользователь может иметь неограниченное количество",
            "Да, строго только одна сессия всегда",
            "Это нужно только для стриминговых сервисов (Netflix)",
            "Нет, современные браузеры это контролируют",
            "Да, но только на мобильных устройствах",
            "Нет, это нарушает GDPR правила"
        ],
        correctAnswerIndex: 0,
        explanation: "Concurrent Session Limits: банки часто ограничивают до 1-3 активных сессий. Причины: 1) Anti-sharing (один логин = один user) 2) Compromise detection (сессии из NY и Tokyo одновременно?) 3) Resource limits. Trade-off с UX (phone+laptop+tablet).",
        link: {
            label: "Session Management Best Practices",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое /etc/shadow файл в Linux?",
        answers: [
            "Защищённый файл с хешами паролей пользователей (доступ только root). /etc/passwd содержит user info без паролей",
            "Теневой профиль для анонимного доступа",
            "Файл с резервными копиями паролей",
            "Логи неудачных попыток входа",
            "Конфигурация графических теней в UI",
            "Список заблокированных пользователей",
            "Database паролей от Wi-Fi сетей"
        ],
        correctAnswerIndex: 0,
        explanation: "/etc/shadow: формат `user:$algo$salt$hash:lastchange:min:max:warn`. Только root может читать. Алгоритмы: $1$=MD5, $5$=SHA-256, $6$=SHA-512, $y$=yescrypt. /etc/passwd: публичный файл с UID/GID/shell, password field = 'x'.",
        link: {
            label: "Linux Shadow Password Suite",
            url: "https://www.cyberciti.biz/faq/understanding-etcshadow-file/"
        }
    },
    {
        question: "Безопасна ли аутентификация только по IP-адресу?",
        answers: [
            "Нет, IP можно подделать (spoofing в UDP), перехватить (BGP hijacking, ARP spoofing), плюс NAT скрывает тысячи users за одним IP",
            "Да, IP-адрес уникален и неподделываем",
            "Безопасно только в локальной корпоративной сети",
            "Да, если IP статический и не динамический",
            "Безопасно для IPv6, небезопасно для IPv4",
            "Да, если дополнительно проверять MAC-адрес",
            "Да, современные файрволы защищают от подделки"
        ],
        correctAnswerIndex: 0,
        explanation: "IP-based auth: слабая! 1) IP spoofing (UDP легко, TCP сложнее) 2) Corporate NAT (весь офис = 1 IP) 3) Dynamic IPs (DHCP) 4) Shared IPs (cafe WiFi) 5) IP не = identity. Используйте как дополнительный сигнал, не основной auth.",
        link: {
            label: "IP Spoofing",
            url: "https://en.wikipedia.org/wiki/IP_address_spoofing"
        }
    },
    {
        question: "Что такое IDOR в контексте функций аутентификации?",
        answers: [
            "Insecure Direct Object Reference: возможность сменить пароль/email чужого пользователя через /api/users/{user_id}/reset_password без проверки ownership",
            "Идол для поклонения в храме безопасности",
            "Ошибка в дизайне дверных замков",
            "Внутренний ID базы данных пользователя",
            "Internet Domain Object Registry",
            "Интегрированная система обнаружения вторжений",
            "Идентификатор сессии в формате UUID"
        ],
        correctAnswerIndex: 0,
        explanation: "IDOR in auth: POST /api/users/123/change-password {new: '...'}. Атакующий меняет 123→456 в request → меняет пароль чужого user. Защита: проверять owner: if (userId !== currentUser.id) return 403. Пример: GitHub Reset Password (2020).",
        link: {
            label: "OWASP: IDOR",
            url: "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
        }
    },
    {
        question: "Чем опасен LDAP Injection в поле логина?",
        answers: [
            "Манипуляция LDAP-фильтром позволяет обойти проверку пароля: '(uid=admin*)(|(uid=*' →  всегда true authentication",
            "LDAP injection = обычная SQL инъекция",
            "Это только XSS-уязвимость в LDAP",
            "Инъекция влияет только на Active Directory",
            "LDAP injection невозможна технически",
            "Это проблема только Windows-серверов",
            "Влияет только на email валидацию"
        ],
        correctAnswerIndex: 0,
        explanation: "LDAP Injection: filter = `(uid=${username})(userPassword=${password})`. Injection: username='admin*)(|(uid=*' → filter = `(uid=admin*)(|(uid=*)(userPassword=anything)` → bypass! Защита: escape special chars: *, (, ), \\, /, NUL.",
        link: {
            label: "OWASP: LDAP Injection",
            url: "https://owasp.org/www-community/attacks/LDAP_Injection"
        }
    },
    {
        question: "Какой Cookie Domain scope безопаснее?",
        answers: [
            "Отсутствие Domain attribute (cookie только для текущего хоста) — предотвращает отправку на потенциально скомпрометированные поддомены",
            "Domain=.example.com для всех поддоменов",
            "Domain=com для максимальной совместимости",
            "Domain=* для глобального доступа",
            "Domain должен всегда включать www префикс",
            "Domain=localhost для разработки",
            "Domain с IP-адресом вместо имени"
        ],
        correctAnswerIndex: 0,
        explanation: "Cookie Domain: 1) No Domain → текущий хост только 2) Domain=.example.com → все *.example.com. Риск: если dev.example.com скомпрометирован (XSS) → украдёт cookies от www.example.com. Principle of Least Privilege: no Domain attribute!",
        link: {
            label: "MDN: Cookie Domain",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent"
        }
    },
    {
        question: "Что такое SameSite=Lax для Cookie?",
        answers: [
            "Cookie отправляется при top-level navigation (переход по ссылке), но НЕ при cross-site subrequests (img, iframe, fetch) — баланс security/UX",
            "Cookie передаётся везде без ограничений",
            "Cookie никогда не отправляется cross-site",
            "Lax — это ошибка в настройке",
            "Означает что cookie не зашифрована",
            "Cookie видна только на HTTP, не HTTPS",
            "Это deprecated атрибут из старых браузеров"
        ],
        correctAnswerIndex: 0,
        explanation: "SameSite=Lax (default в Chrome): 1) Клик на ссылку с google.com → bank.com (top navigation) → cookies отправлены 2) <img src='bank.com/api'> на evil.com (subrequest) → cookies НЕ отправлены. Защита от CSRF с minimal UX impact.",
        link: {
            label: "SameSite Cookie Explained",
            url: "https://web.dev/articles/samesite-cookies-explained"
        }
    },
    {
        question: "Что такое SameSite=Strict для Cookie?",
        answers: [
            "Cookie отправляется ТОЛЬКО при запросах с того же сайта. Переход по внешней ссылке не залогинит user — максимальная CSRF защита, но хуже UX",
            "Cookie полностью удаляется при закрытии браузера",
            "Cookie шифруется перед отправкой на сервер",
            "Режим строгой валидации формата cookie",
            "Cookie доступна только для HTTPS запросов",
            "Strict означает обязательную двухфакторную аутентификацию",
            "Cookie активна только в приватном режиме браузера"
        ],
        correctAnswerIndex: 0,
        explanation: "SameSite=Strict: никогда не отправляется cross-site. User кликает ссылку в email → bank.com → appears logged out (cookie не отправлена). Для авторизации нужен переход внутри сайта. Подходит для admin panels, финансов, где UX < security.",
        link: {
            label: "SameSite Strict vs Lax",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
        }
    },
    {
        question: "Что такое Golden Ticket атака в Kerberos?",
        answers: [
            "Создание поддельного Ticket Granting Ticket (TGT) с захваченным KRBTGT hash — даёт вечный доступ ко всем ресурсам домена Windows",
            "Золотой билет в кинотеатр для бесплатного просмотра",
            "Специальный ключ для расшифровки сертификатов",
            "Бонусная программа лояльности клиентов",
            "Backdoor в BIOS материнской платы",
            "Privilege escalation через USB флешку",
            "Атака на  Bitcoin кошельки"
        ],
        correctAnswerIndex: 0,
        explanation: "Golden Ticket (Mimikatz): 1) Domain Admin compromise → extract KRBTGT hash 2) Forge TGT {user: any, groups: Domain Admins, expires: 10 years} 3) Неограниченный доступ ко всем сервисам. Защита: регулярная смена KRBTGT password 2x, detect anomalies.",
        link: {
            label: "Kerberos Golden Ticket",
            url: "https://attack.mitre.org/techniques/T1558/001/"
        }
    },
    {
        question: "Опасно ли оставлять тестовые аккаунты (demo/demo, test/test) на production?",
        answers: [
            "Да, это backdoor с известными credentials — первое что проверяют атакующие. Всегда удаляйте test accounts перед деплоем",
            "Нет, test accounts безопасны на production",
            "Опасно только если у них есть admin права",
            "Нет, они полезны для демонстраций клиентам",
            "Безопасно если пароль длиннее 6 символов",
            "Нет risk если аккаунт создан недавно",
            "Опасно только для open-source проектов"
        ],
        correctAnswerIndex: 0,
        explanation: "Test accounts = easy targets! Сканеры автоматически пробуют: admin/admin, test/test, demo/demo, user/user. Даже с low privileges — entry point для lateral movement. Best practice: automated cleanup на deploy, different creds per environment.",
        link: {
            label: "Default Credentials Lists",
            url: "https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials"
        }
    },
    {
        question: "Что такое Dormant Account (спящий аккаунт)?",
        answers: [
            "Аккаунт неактивный >90-180 дней (no login). Риск: owner forgot about it, не мониторит, outdated password — prime target для attackers",
            "Аккаунт в режиме гибернации операционной системы",
            "Temporаrily заблокированный администратором аккаунт",
            "Аккаунт bot скрипта или автоматизации",
            "Резервный аккаунт для emergency доступа",
            "Аккаунт удалённого сотрудника",
            "Тестовый аккаунт QA отдела"
        ],
        correctAnswerIndex: 0,
        explanation: "Dormant Accounts: забытые, устаревшие пароли, no MFA updates, owner not monitoring. Атака: brute-force old account → успех → lateral movement. Policy: auto-disable after 90 дней inactivity, quarterly review, re-authentication для reactivation.",
        link: {
            label: "Account Lifecycle Management",
            url: "https://www.cisecurity.org/controls/v8"
        }
    },
    {
        question: "Что делает Password Manager более безопасным чем запоминание паролей?",
        answers: [
            "Позволяет использовать уникальные сложные пароли для каждого сайта без необходимости помнить их — защищает от credential reuse и stuffing",
            "Password managers автоматически меняют пароли каждый день",
            "Они шифруют трафик между браузером и сервером",
            "Password managers блокируют phishing-сайты на DNS-уровне",
            "Автоматически включают 2FA на всех сайтах",
            "Они запоминают пароли быстрее чем человек",
            "Password managers защищают от XSS-атак"
        ],
        correctAnswerIndex: 0,
        explanation: "Password Managers (1Password, Bitwarden, LastPass): 1) Unique strong passwords (40 chars random) per site 2) No reuse → credential stuffing protection 3) Auto-fill only on correct domain → phishing protection 4) Master password + MFA 5) Audit weak passwords.",
        link: {
            label: "NIST: Password Manager Guidance",
            url: "https://pages.nist.gov/800-63-3/sp800-63b.html"
        }
    },
    {
        question: "Как работает биометрическая аутентификация (fingerprint, Face ID)?",
        answers: [
            "Биометрия хранится локально на устройстве в Secure Enclave/TPM, сравнение происходит on-device, сервер получает только success/fail сигнал",
            "Отпечаток пальца отправляется на сервер в зашифрованном виде",
            "Биометрия заменяет пароль полностью без шифрования",
            "Face ID работает через сравнение с фото в соцсетях",
            "Биометрические данные хранятся в cloud провайдера",
            "Fingerprint сканируется и отправляется в открытом виде",
            "Биометрия работает только offline без интернета"
        ],
        correctAnswerIndex: 0,
        explanation: "Biometric Auth (WebAuthn): 1) Биометрия никогда не покидает device 2) Match в Secure Enclave (iOS) / TPM (Android/Windows) 3) On success: sign challenge private key 4) Server проверяет signature. Privacy + phishing-resistant!",
        link: {
            label: "Apple: Face ID Security",
            url: "https://support.apple.com/en-us/HT208108"
        }
    },
    {
        question: "Что такое Password Spray атака в enterprise environment?",
        answers: [
            "Попытка входа с одним популярным паролем (Summer2024!) для тысяч пользователей компании — обходит individual account lockout",
            "Случайное распыление паролей по сети",
            "DDoS атака на password хеши",
            "Атака только на spray painting компании",
            "Automated password generator для rainbow tables",
            "Физическое распыление краски на серверы",
            "Метод шифрования паролей в памяти"
        ],
        correctAnswerIndex: 0,
        explanation: "Password Spraying: атакующий знает паттерны паролей (Company2024!, Summer2024!). Пробует для всех users из LinkedIn. 10000 users × 1 попытка = no lockout trigger, но 100+ successful logins. Защита: MFA, monitor auth patterns, ban common passwords.",
        link: {
            label: "Microsoft: Password Spray Detection",
            url: "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray"
        }
    },
    {
        question: "Нужно ли хранить старые хеши паролей для защиты от переиспользования?",
        answers: [
            "Да, для критичных систем: сохранить хеши последних 5-10 паролей и проверять новый пароль против них при смене",
            "Нет, это нарушает приватность пользователя",
            "Да, но только в plaintext для быстрой проверки",
            "Нет, database слишком разрастётся",
            "Да, храните все пароли с момента регистрации",
            "Нет, GDPR запрещает хранение старых паролей",
            "Да, но only для admin аккаунтов"
        ],
        correctAnswerIndex: 0,
        explanation: "Password History: некоторые compliance требуют (PCI DSS: 4 passwords, NIST SP 800-53). Храните: hashes (не plaintext!) последних N паролей. При смене: проверить bcrypt(new_pass) не совпадает с history[]. Prevents: Password1 → Password2 → Password1 rotation.",
        link: {
            label: "PCI DSS Password Requirements",
            url: "https://www.pcisecuritystandards.org/"
        }
    },
    {
        question: "Защищает ли HTTPS от Password Brute-Force атак?",
        answers: [
            "Нет, HTTPS шифрует транспорт, но не предотвращает множественные попытки входа — нужны rate limiting, CAPTCHA, account lockout",
            "Да, HTTPS полностью блокирует brute-force",
            "Защищает только если используется TLS 1.3",
            "Да, но только с perfect forward secrecy",
            "HTTPS делает brute-force в 10 раз медленнее",
            "Защищает только на серверах с HSTS",
            "Да, Certificate Pinning блокирует brute-force"
        ],
        correctAnswerIndex: 0,
        explanation: "HTTPS vs Brute-Force: HTTPS защищает credentials в transit (от MitM), но НЕ останавливает атакующего отправлять 10000 POST /login. Нужны application-level защиты: rate limiting (10 req/min), progressive delays, IP blocking, CAPTCHA.",
        link: {
            label: "Layer 7 vs Layer 4 Attacks",
            url: "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
        }
    },
    {
        question: "Что такое OAuth Authorization Code flow с PKCE?",
        answers: [
            "Enhanced OAuth для public clients (SPA, mobile): code_verifier (random) + code_challenge (hash) предотвращают authorization code interception",
            "Устаревший OAuth flow для desktop приложений",
            "Simplified OAuth без state parameter",
            "OAuth только для enterprise B2B интеграций",
            "Метод шифрования refresh tokens",
            "OAuth extension для blockchain apps",
            "Альтернативное название Implicit Grant"
        ],
        correctAnswerIndex: 0,
        explanation: "PKCE (Proof Key for Code Exchange): 1) App: code_verifier = random(128bit), code_challenge = SHA256(verifier) 2) Auth: redirect?code_challenge=... 3) Callback: code=xyz 4) Token: POST {code, code_verifier} 5) Server: verify SHA256(verifier)==challenge. Защита от code interception!",
        link: {
            label: "OAuth 2.0 PKCE",
            url: "https://datatracker.ietf.org/doc/html/rfc7636"
        }
    },
    {
        question: "Можно ли доверять User-Agent header для аутентификации или авторизации?",
        answers: [
            "Нет, User-Agent легко подменяется клиентом — используйте только для аналитики и device fingerprinting, не для security decisions",
            "Да, User-Agent криптографически подписан браузером",
            "Да, но только для mobile устройств",
            "User-Agent защищён на уровне TCP/IP",
            "Да, если используется HTTPS соединение",
            "Нет, но только на HTTP/1.1, на HTTP/2 защищён",
            "Да, современные браузеры не позволяют подделку"
        ],
        correctAnswerIndex: 0,
        explanation: "User-Agent Spoofing: любой HTTP client может установить произвольный UA: curl -H 'User-Agent: iPhone'. Не используйте для: access control, feature flags (security), bot detection (основной метод). OK для: analytics, responsive design, progressive enhancement.",
        link: {
            label: "MDN: User-Agent",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent"
        }
    },
    {
        question: "Как правильно тестировать аутентификацию приложения при penetration testing?",
        answers: [
            "Комплексно: username enumeration, brute-force, credential stuffing lists, password policy, session management, MFA bypass, reset functions, IDOR, privilege escalation",
            "Только попробовать admin/admin и SQL injection",
            "Достаточно automated scan через Nessus",
            "Только проверка наличия HTTPS сертификата",
            "Brute-force одного test-аккаунта",
            "Проверка только формы регистрации",
            "Social engineering CEO для получения пароля"
        ],
        correctAnswerIndex: 0,
        explanation: "Auth Pentest Checklist: 1) Enumeration (different responses?) 2) Brute-force protection (rate limits?) 3) Password policy (weak allowed?) 4) Credential stuffing (common passwords?) 5) Session (fixation, hijacking, logout?) 6) MFA (bypass, backup codes?) 7) Password reset (IDOR, token prediction?) 8) Privilege escalation.",
        link: {
            label: "OWASP Testing Guide: Authentication",
            url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README"
        }
    },
    {
        question: "Что такое API Key и где её безопасно хранить?",
        answers: [
            "Секретный токен для аутентификации API-запросов. Хранить: server env variables, secrets manager. НЕ: frontend код, git репозитории",
            "Публичный идентификатор для аналитики",
            "Открытый ключ для шифрования данных",
            "Номер версии API спецификации",
            "ID пользователя в системе",
            "Порт на котором работает API",
            "Доменное имя API сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "API Keys: секреты как пароли! Риски: hardcoded keys в коде → GitHub scan → compromised. Best practices: rotate regularly, scope (read-only vs full access), monitor usage, revoke unused, server-side only для sensitive keys.",
        link: {
            label: "OWASP: API Key Management",
            url: "https://owasp.org/www-project-api-security/"
        }
    },
    {
        question: "В чём разница между Access Token и Refresh Token?",
        answers: [
            "Access (short TTL: 15 min) для API запросов, Refresh (long TTL: days) только для получения нового access token — снижает риск кражи",
            "Access для чтения, Refresh для записи данных",
            "Это одинаковые токены с разными названиями",
            "Access для пользователей, Refresh для админов",
            "Access работает по HTTP, Refresh по HTTPS",
            "Refresh токен это просто backup Access токена",
            "Access хранится на сервере, Refresh на клиенте"
        ],
        correctAnswerIndex: 0,
        explanation: "Token Rotation: Access token в каждом request (риск кражи через XSS/MitM) → short-lived. Refresh token используется редко (только для /refresh endpoint) → меньше exposure. Если access украден → compromised на 15 min max.",
        link: {
            label: "OAuth 2.0: Refresh Tokens",
            url: "https://datatracker.ietf.org/doc/html/rfc6749#section-1.5"
        }
    },
    {
        question: "Должны ли Refresh Tokens быть одноразовыми (one-time use)?",
        answers: [
            "Рекомендуется: каждый refresh выдаёт новый access + новый refresh (token rotation) — предотвращает token replay при краже",
            "Нет, refresh token perpetual и переиспользуется",
            "Только если токен короче 10 символов",
            "Да, но только на мобильных устройствах",
            "Нет, это усложняет архитектуру",
            "Только для OAuth 2.0, не для JWT",
            "Да, но только в production окружении"
        ],
        correctAnswerIndex: 0,
        explanation: "Refresh Token Rotation: use once → get {new_access, new_refresh}. Если старый refresh используется → fraud detected → revoke all tokens пользователя. Защита: если токен украден, окно атаки = 1 refresh cycle.",
        link: {
            label: "OAuth 2.0 Security Best Practices",
            url: "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics"
        }
    },
    {
        question: "Что такое Client Certificate Authentication (mTLS)?",
        answers: [
            "Взаимная TLS аутентификация: не только сервер, но и клиент предъявляет X.509 сертификат — очень strong auth для машина-машина",
            "Сертификат только для SSL/TLS на сервере",
            "Специальный тип cookie для клиента",
            "Лицензия на использование программного обеспечения",
            "Email сертификат для S/MIME шифрования",
            "Сертификат DNS для domain validation",
            "Backup ключ для восстановления доступа"
        ],
        correctAnswerIndex: 0,
        explanation: "mTLS (Mutual TLS): обычный TLS — сервер доказывает identity клиенту. mTLS — оба предъявляют сертификаты. Use cases: microservices, IoT, enterprise B2B APIs, high-security environments. Сложнее deployment, но намного безопаснее паролей!",
        link: {
            label: "Cloud flare: mTLS",
            url: "https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/"
        }
    },
    {
        question: "Зачем нужен Security Header X-Frame-Options в контексте аутентификации?",
        answers: [
            "Предотвращает Clickjacking: встраивание страницы входа в iframe на злонамеренном сайте для кражи credentials через UI overlay",
            "Ускоряет загрузку формы входа",
            "Шифрует пароль перед отправкой",
            "Автоматически включает двухфакторную аутентификацию",
            "Блокирует SQL injection в форме входа",
            "Проверяет сложность введённого пароля",
            "Устанавливает срок жизни cookies"
        ],
        correctAnswerIndex: 0,
        explanation: "X-Frame-Options: DENY или SAMEORIGIN. Clickjacking attack: evil.com встраивает <iframe src='bank.com/login'>, накладывает прозрачный слой. User думает заполняет форм у на evil → на самом деле bank → credentials украдены. Header блокирует iframe!",
        link: {
            label: "MDN: X-Frame-Options",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
        }
    },
    {
        question: "Почему важно логировать события аутентификации?",
        answers: [
            "Для обнаружения атак (unusual login patterns, brute-force), forensics после взлома, compliance (SOC 2, PCI DSS), alerts на аномалии",
            "Только для статистики посещаемости сайта",
            "Логи не нужны если используется HTTPS",
            "Это требуется только для open-source проектов",
            "Логирование замедляет процесс аутентификации",
            "Нужно только для мобильных приложений",
            "Это legacy требование из прошлого века"
        ],
        correctAnswerIndex: 0,
        explanation: "Auth Logging must include: timestamp, user_id/email, IP, user-agent, success/fail, failure reason, location (GeoIP). Alerts: 5 failed logins → notify user, 100 fails from IP → block, login from new country → verify. Retention: logs = evidence для incident response.",
        link: {
            label: "OWASP: Logging Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        }
    },
    {
        question: "Что НЕ должно попадать в authentication логи?",
        answers: [
            "Пароли (даже failed attempts) и полные токены — только hash/prefix для security, GDPR compliance, insider threat prevention",
            "IP-адрес пользователя",
            "Timestamp события",
            "User-Agent строка",
            "Результат аутентификации (success/fail)",
            "Идентификатор пользователя",
            "Географическое местоположение"
        ],
        correctAnswerIndex: 0,
        explanation: "НИКОГДА не логировать: passwords, full API keys/tokens, PII without reason, credit cards. OK логировать: token prefix (first 6 chars), password hash для failed attempts (для check против breach DBs), but not plaintext. Logs = potential leak target!",
        link: {
            label: "CWE-532: Information Exposure Through Log Files",
            url: "https://cwe.mitre.org/data/definitions/532.html"
        }
    },
    {
        question: "Что такое Zero Trust Security Model в контексте аутентификации?",
        answers: [
            "Никогда не доверяй, всегда проверяй: аутентификация и авторизация при каждом запросе, даже внутри сети — нет trusted zones",
            "Полное отсутствие аутентификации в системе",
            "Доверие только пользователям с нулевым опытом",
            "Блокировка всех пользователей по умолчанию",
            "Система без паролей и токенов",
            "Trust только для zero-day уязвимостей",
            "Аутентификация только на периметре сети"
        ],
        correctAnswerIndex: 0,
        explanation: "Zero Trust: устаревшая модель — 'внутри сети = trusted'. Новая — verify everything: device health, user identity, context (IP/location), every request auth. Принципы: least privilege, microsegmentation, MFA everywhere, assume breach.",
        link: {
            label: "NIST: Zero Trust Architecture",
            url: "https://www.nist.gov/publications/zero-trust-architecture"
        }
    },
    {
        question: "Зачем проверять Have I Been Pwned (HIBP) API при регистрации/смене пароля?",
        answers: [
            "Проверка пароля против 12+ млрд украденных credentials из реальных утечек — блокировка уже скомпрометированных паролей",
            "Для подсчёта количества регистраций",
            "HIBP автоматически взламывает слабые пароли",
            "Это маркетинговый инструмент для конверсии",
            "Проверка нужна только для .gov доменов",
            "HIBP улучшает SEO рейтинг сайта",
            "Это требование только для EU стран"
        ],
        correctAnswerIndex: 0,
        explanation: "HIBP check: k-Anonymity protocol — отправляете first 5 chars SHA1 hash, получаете список. Если пароль в breach → reject: 'This password appeared in  data breach'. Troy Hunt DB: Collection #1-5, LinkedIn, Adobe, etc. Free API!",
        link: {
            label: "Have I Been Pwned API",
            url: "https://haveibeenpwned.com/API/v3"
        }
    },
    {
        question: "Что такое Passwordless Authentication?",
        answers: [
            "Аутентификация без пароля: magic links, TOTP, WebAuthn/FIDO2, biometrics — устраняет weak/reused passwords и phishing",
            "Вход без ввода любых данных вообще",
            "Автоматический вход для всех пользователей",
            "Система без регистрации аккаунтов",
            "Анонимный доступ ко всем ресурсам",
            "Гостевой режим без ограничений",
            "Социальная сеть без профилей"
        ],
        correctAnswerIndex: 0,
        explanation: "Passwordless: 1) Magic Links (email OTP link) 2) SMS/Email OTP 3) Push notifications 4) FIDO2/WebAuthn (hardware keys, TouchID) 5) Passkeys (Apple/Google). Advantages: no passwords to steal/phish, better UX. Challenges: email security dependency, adoption.",
        link: {
            label: "Microsoft: Passwordless Strategy",
            url: "https://www.microsoft.com/security/business/solutions/passwordless-authentication"
        }
    },
    {
        question: "Как защитить Backup Codes (коды восстановления) для 2FA?",
        answers: [
            "Генерировать one-time use криптостойкие коды, хранить хеши (не plaintext), требовать их безопасное сохранение (password manager, печать)",
            "Коды восстановления не нужны вообще",
            "Отправить их пользователю в открытом email",
            "Публиковать на главной странице профиля",
            "Хранить в plaintext в базе для удобства",
            "Делать backup codes одинаковыми для всех",
            "Установить пожизненный срок действия"
        ],
        correctAnswerIndex: 0,
        explanation: "Backup Codes best practices: 1) генерировать 8-10 random codes 2) one-time use (mark as used) 3) хранить bcrypt hashes 4) regenerate option 5) пользователь должен сохранить offline (password manager/бумага) 6) warning: последний код использован.",
        link: {
            label: "Google: Backup Codes",
            url: "https://support.google.com/accounts/answer/1187538"
        }
    }
];
