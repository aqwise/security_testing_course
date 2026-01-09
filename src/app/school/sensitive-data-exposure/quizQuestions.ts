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
        question: "Что такое Sensitive Data Exposure?",
        answers: [
            "Ненамеренное раскрытие конфиденциальной информации (PII, пароли, ключи, медицинские/финансовые данные) из-за отсутствия защиты",
            "Раскрытие публичных алгоритмов работы сервера",
            "Отказ в обслуживании (Denial of Service attack)",
            "Внедрение вредоносного SQL кода в базу данных",
            "Атака Cross-Site Scripting (XSS)",
            "Подделка межсайтовых запросов (CSRF)",
            "Манипуляция параметрами массового назначения"
        ],
        correctAnswerIndex: 0,
        explanation: "Sensitive Data Exposure (A02:2021) - когда приложение не защищает PII, credentials, финансовые данные. Атакующие перехватывают данные (MitM), крадут ключи, находят .git/.env файлы, читают неза шифрованные backups. Отличается от Broken Access Control (неправильные права доступа).",
        link: {
            label: "OWASP: Cryptographic Failures",
            url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        }
    },
    {
        question: "Какая информация считается PII (Personally Identifiable Information)?",
        answers: [
            "ФИО, паспортные данные, номер телефона, email, адрес проживания, дата рождения, биометрические данные - любая информация идентифицирующая личность",
            "IP-адрес сервера и версия операционной системы",
            "Название фреймворка и версия используемого PHP",
            "Публичный ключ SSL/TLS сертификата сайта",
            "User-Agent строка браузера пользователя",
            "Часовой пояс сервера и locale",
            "Доменное имя и DNS записи сайта"
        ],
        correctAnswerIndex: 0,
        explanation: "PII = Personal Identifiable Information. Примеры: Full  Name, SSN/ИНН, паспорт, номер карты, email, phone, адрес, IP (может быть), биометрия, медицинская история. GDPR и CCPA требуют защиты PII: шифрование, минимизация, право на удаление.",
        link: {
            label: "NIST: PII Guide",
            url: "https://csrc.nist.gov/publications/detail/sp/800-122/final"
        }
    },
    {
        question: "Какой основной метод защиты данных при передаче (Data in Transit)?",
        answers: [
            "TLS/SSL шифрование (HTTPS) с modern cipher suites (TLS 1.3, AES-GCM) — предотвращает перехват Man-in-the-Middle",
            "Сжатие данных через gzip или Brotli",
            "Кодирование данных через Base64 encoding",
            "Использование только HTTP POST запросов",
            "Добавление CORS заголовков на сервере",
            "Минификация JavaScript и CSS файлов",
            "Включение CDN для ускорения доставки"
        ],
        correctAnswerIndex: 0,
        explanation: "Data in Transit защищается TLS 1.2+ (лучше 1.3). Base64 = encoding (НЕ шифрование!). Требования: HTTPS для всего сайта, HSTS header, valid certificates, no mixed content, secure ciphers (disable RC4, 3DES). Внутренние сервисы также  должны использовать TLS (zero-trust).",
        link: {
            label: "OWASP: Transport Layer Protection",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        }
    },
    {
        question: "Какой основной метод защиты данных в покое (Data at Rest)?",
        answers: [
            "Шифрование базы данных и полей с sensitive data (AES-256-GCM, column-level encryption), secure key management через HSM/KMS",
            "Просто скрытие папки с базой данных",
            "Регулярное удаление старых записей из БД",
            "Использование RAID массивов для надёжности",
            "Установка файрволла перед сервером БД",
            "Создание резервных копий каждый час",
            "Переименование таблиц БД случайными именами"
        ],
        correctAnswerIndex: 0,
        explanation: "Data at Rest: шифрование дисков (Full Disk Encryption), БД (Transparent Data Encryption), отдельных полей (credit cards, SSN). AES-256 для симметричного шифрования. Ключи хранить отдельно в Key Management System (AWS KMS, Azure Key Vault, HashiCorp Vault). НЕ hardcode keys!",
        link: {
            label: "OWASP: Cryptographic Storage",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Является ли Base64 шифрованием?",
        answers: [
            "Нет, Base64 - это обратимая кодировка (encoding), а не шифрование. Любой может декодировать данные без ключа одной командой",
            "Да, Base64 это надёжный метод шифрования",
            "Да, но только для изображений и файлов",
            "Нет, Base64 это криптографический хеш-алгоритм",
            "Да, если добавить соль (salt) к данным",
            "Нет, но он используется только для обфускации",
            "Да, современные браузеры усиливают Base64"
        ],
        correctAnswerIndex: 0,
        explanation: "Base64 = encoding (НЕ encryption!). Используется для представления binary data в text format (например, email attachments, data URLs). Обратное преобразование тривиально: `atob('aGVsbG8=')` → 'hello'. Для шифрования используйте AES, ChaCha20. Никогда не храните sensitive data в Base64!",
        link: {
            label: "RFC 4648: Base64 Encoding",
            url: "https://datatracker.ietf.org/doc/html/rfc4648"
        }
    },
    {
        question: "Что такое PCI DSS?",
        answers: [
            "Payment Card Industry Data Security Standard - требования к организациям, обрабатывающим платёжные карты (Visa, MasterCard, Amex)",
            "Протокол передачи зашифрованных данных через интернет",
            "Программа для automated password cracking",
            "Тип реляционной базы данных для финансов",
            "Стандарт для шифрования жёстких дисков",
            "Формат хранения сертификатов SSL/TLS",
            "Алгоритм хеширования паролей пользователей"
        ],
        correctAnswerIndex: 0,
        explanation: "PCI DSS v4.0 (2022): 12 требований включая: не храните CVV/CVV2, шифруйте PANом (карт), strong access control, регулярные тесты безопасности, мониторинг сетей. Нарушение → штрафы $5K-$100K/месяц + loss of ability to process cards.",
        link: {
            label: "PCI Security Standards Council",
            url: "https://www.pcisecuritystandards.org/"
        }
    },
    {
        question: "Что такое GDPR?",
        answers: [
            "General Data Protection Regulation - закон ЕС об обработке персональных данных граждан ЕС (2018) с штрафами до €20M или 4% годового оборота",
            "Глобальная сеть защиты маршрутизаторов",
            "Графический интерфейс для администрирования БД",
            "Протокол маршрутизации для VPN соединений",
            "Стандарт шифрования государственных тайн",
            "Генератор детерминированных псевдослучайных чисел",
            "Германский протокол передачи речевых данных"
        ],
        correctAnswerIndex: 0,
        explanation: "GDPR (EU 2018): право на забвение, data portability, breach notification (72h), consent, privacy by design. Applies to any org processing EU citizens' data. Max fine: €20M или 4% global revenue. Требует encryption at rest/transit, минимизацию данных, DPO (Data Protection Officer).",
        link: {
            label: "GDPR Official Text",
            url: "https://gdpr-info.eu/"
        }
    },
    {
        question: "Чем опасно хранение секретов в репозитории кода (например, .env в git)  ?",
        answers: [
            "Публичные сканеры (GitHub, GitLab) автоматически ищут committed credentials — мгновенный production access для атакующих через git history",
            "Репозиторий станет занимать слишком много места",
            "Git начнёт работать медленнее со временем",
            "Это нарушает code style guidelines проекта",
            "Pull requests будут конфликтовать чаще",
            "CI/CD pipeline перестанет работать",
            "IDE будет показывать больше предупреждений"
        ],
        correctAnswerIndex: 0,
        explanation: "GitHub secrets scanning находит AWS keys, private keys, tokens в commits. Злоумышленники мониторят публичные repos (automated scraping). Даже после удаления файла — он в git history! Tools: TruffleHog, GitLeaks, git-secrets. Best practice: .gitignore для .env, использовать secrets managers (AWS Secrets Manager, HashiCorp Vault).",
        link: {
            label: "GitHub: Security Best Practices",
            url: "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning"
        }
    },
    {
        question: "Что делает заголовок HSTS (HTTP Strict Transport Security)?",
        answers: [
            "Заставляет браузер использовать только HTTPS для домена на заданный период (max-age), предотвращает SSL stripping и downgrade attacks",
            "Скрывает HTML исходный код страницы от просмотра",
            "Автоматически ускоряет загрузку CSS стилей",
            "Полностью блокирует XSS атаки на сайте",
            "Шифрует Cookie файлы в браузере",
            "Включает автоматическое обновление сертификата",
            "Защищает от SQL injection в формах"
        ],
        correctAnswerIndex: 0,
        explanation: "HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Браузер запоминает — всегда HTTPS для домена. Защи та: SSL stripping (MitM переводит на HTTP), certificate warnings bypass. Preload list (hstspreload.org) — hardcoded в браузеры. Раз включил preload — сложно убрать!",
        link: {
            label: "MDN: HSTS",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        }
    },
    {
        question: "Почему нельзя использовать устаревшие алгоритмы шифрования (DES, RC4, MD5 для паролей)?",
        answers: [
            "Их вычислительная сложность взлома слишком низка для современных GPU/ASIC — brute-force за минуты/часы вместо столетий",
            "Они работают слишком медленно на серверах",
            "Современные браузеры их не поддерживают",
            "Они требуют платную коммерческую лицензию",
            "Занимают слишком много оперативной памяти",
            "Не совместимы с облачными провайдерами",
            "Нарушают стандарты HTML5 и CSS3"
        ],
        correctAnswerIndex: 0,
        explanation: "DES: 56-bit key → brute-forced в 1998. RC4: biases в keystream. 3DES: deprecated (64-bit blocks → birthday attack). MD5: collision attacks. SHA-1: deprecated (Google SHAttered 2017). Используйте: AES-256-GCM, ChaCha20, Argon2/bcrypt для паролей, SHA-256/SHA-3 для хешей.",
        link: {
            label: "NIST: Deprecated Algorithms",
            url: "https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program"
        }
    },
    {
        question: "Можно ли хранить пароли пользователей в открытом виде (plaintext)?",
        answers: [
            "Нет, никогда и ни при каких условиях! Обязательно хешировать с уникальной солью через Argon2id/bcrypt/scrypt с high work factor",
            "Да, если база данных защищена фаерволом",
            "Да, для удобства восстановления доступа",
            "Только пароли администраторов можно plaintext",
            "Да, если использовать Base64 encoding",
            "Да, при условии шифрования диска сервера",
            "Да, для temporary тестовых аккаунтов"
        ],
        correctAnswerIndex: 0,
        explanation: "Plaintext passwords = катастрофа! При breach все accounts compromised. Требование: Argon2id (winner PHC 2015), bcrypt (cost 12+), scrypt. Никогда: MD5, SHA-1, SHA-256 without salt. Каждому паролю — уникальная salt (generated cryptographically secure random). Проверка: `hash(input+salt)==stored_hash`.",
        link: {
            label: "OWASP: Password Storage",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое 'Man-in-the-Middle' (MitM) атака?",
        answers: [
            "Перехват и потенциальная модификация сообщений между двумя сторонами без их ведома — атакующий видит/изменяет весь трафик",
            "Атака на physical сервер в дата-центре",
            "Целевая атака на системного администратора",
            "Вид email spamming кампании",
            "DDoS атака с использованием ботнета",
            "SQL injection через proxy сервер",
            "Фишинговая атака через SMS сообщения"
        ],
        correctAnswerIndex: 0,
        explanation: "MitM: атакующий между client-server (WiFi intercept, ARP spoofing, DNS hijacking, rogue proxy). Может читать/модифицировать трафик. Защита: TLS/SSL (HTTPS), certificate pinning, HSTS, VPN, two-factor auth. Tools: Ettercap, mitmproxy, Burp Suite. Public WiFi особенно уязвим!",
        link: {
            label: "OWASP: Man-in-the-Middle",
            url: "https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack"
        }
    },
    {
        question: "Как помогает 'Certificate Pinning'?",
        answers: [
            "Привязывает мобильное приложение к конкретному SSL/TLS сертификату или public key, блокируя MitM даже с поддельным trusted CA certificate",
            "Автоматически ускоряет проверку сертификата",
            "Позволяет безопасно использовать самоподписанные сертификаты",
            "Это устаревший метод без практической пользы",
            "Увеличивает срок действия SSL сертификата",
            "Шифрует приватный ключ на сервере",
            "Автоматически обновляет сертификаты Let's Encrypt"
        ],
        correctAnswerIndex: 0,
        explanation: "Certificate Pinning: app хранит hash публичного ключа сервера. При соединении проверяет certificate chain. Если не совпадает (даже valid CA) → reject. Защита от: compromised CA, government MitM, corporate proxies. Минус: нужно updatingродить app при смене cert. Alternatives: Public Key Pinning (deprecated), DANE/TLSA.",
        link: {
            label: "OWASP: Certificate Pinning",
            url: "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"
        }
    },
    {
        question: "Что делать с метаданными файлов (EXIF в изображениях, author в документах)?",
        answers: [
            "Удалять перед публикацией через специальные инструменты — EXIF содержит GPS координаты, модель камеры, автора, timestamp и другие PII",
            "Оставлять как есть для аутентичности",
            "Просто зашифровать данные AES-256",
            "Использовать для улучшения SEO сайта",
            "Конвертировать в Base64 encoding",
            "Сохранять только для внутреннего использования",
            "Автоматически публиковать в социальных сетях"
        ],
        correctAnswerIndex: 0,
        explanation: "EXIF (Exchangeable Image File Format): GPS (широта/долгота), device (iPhone 14 Pro), datetime, camera settings, иногда thumbnail. Реальные cases: whistleblowers deanonymized, journalists tracked. Tools для очистки: exiftool, mat2, ImageOptim. Office docs: author, company, edit history, hidden text. Всегда strip metadata!",
        link: {
            label: "EFF: Metadata",
            url: "https://ssd.eff.org/module/why-metadata-matters"
        }
    },
    {
        question: "Почему подробные сообщения об ошибках опасны на production?",
        answers: [
            "Раскрывают внутреннюю структуру: пути к файлам, версии библиотек, SQL queries, stack traces — roadmap для атакующего",
            "Они визуально пугают конечных пользователей",
            "Создают дополнительную нагрузку на сервер",
            "Портят дизайн и UX сайта",
            "Замедляют время ответа на 10-15%",
            "Нарушают стандарты accessibility (WCAG)",
            "Занимают место в логах сервера"
        ],
        correctAnswerIndex: 0,
        explanation: "Stack Trace Exposure: показывает framework (Laravel 9.x), DB structure (table 'users' column 'api_key'), file paths (/var/www/app/Models/User.php:42), библиотеки. Атакующий: ищёт CVE для версии, планирует SQL injection. Production: generic 'Internal Server Error'. Подробные errors → logs (не user).",
        link: {
            label: "CWE-209: Information Exposure Through Error",
            url: "https://cwe.mitre.org/data/definitions/209.html"
        }
    },
    {
        question: "Какой инструмент помогает искать забытые файлы на сервере (.git, .env, .swp)?",
        answers: [
            "ffuf, gobuster, dirsearch — brute-force directory/file enumeration с wordlists для обнаружения скрытых ресурсов",
            "Adobe Photoshop для анализа изображений",
            "Calculator для вычисления хешей",
            "Notepad для редактирования конфигов",
            "Microsoft Excel для анализа данных",
            "Google Chrome DevTools",
            "Windows Task Manager"
        ],
        correctAnswerIndex: 0,
        explanation: "File Enumeration tools: ffuf (fast), gobuster (Go-based), dirsearch (Python). Wordlists: SecLists, common.txt. Ищут: .git/config, .env, backup.sql, .DS_Store, web.config.bak, .svn, .idea. Defense: веб-сервер config (Nginx: `location ~ /\\.` { deny all; }), не деплоить dev files, regular scans.",
        link: {
            label: "ffuf: Fast Web Fuzzer",
            url: "https://github.com/ffuf/ffuf"
        }
    },
    {
        question: "Что такое 'Google Dorks' (Google Hacking Database)?",
        answers: [
            "Специальные операторы поиска Google для обнаружения уязвимых сайтов, exposed файлов, публичной конфиденциальной информации в индексе",
            "Новые сотрудники команды Google",
            "Браузерная игра от компании Google",
            "Новый облачный сервис Google Cloud",
            "Программа багбаунти от Google",
            "Алгоритм ранжирования поисковой выдачи",
            "Виртуальный ассистент для Android"
        ],
        correctAnswerIndex: 0,
        explanation: "Google Dorking: `site:example.com filetype:pdf confidential`, `intitle:\"index of\" \"parent directory\"`, `inurl:admin filetype:db`. GHDB (Google Hacking Database): thousands of dorks. Находит: passwords in files, vulnerable servers, webcams, sensitive documents. Defense: robots.txt (слабо), authentication, не индексировать sensitive, monitoring Google searches.",
        link: {
            label: "Google Hacking Database",
            url: "https://www.exploit-db.com/google-hacking-database"
        }
    },
    {
        question: "Опасно ли включение автозаполнения (Autocomplete) для полей с чувствительными данными?",
        answers: [
            "Да! На публичных/shared компьютерах данные (пароли, карты) кешируются браузером и доступны следующему пользователю",
            "Нет, это удобная функция безопасности",
            "Опасно только для input type='date'",
            "Нет, браузер автоматически управляет безопасностью",
            "Да, но только на устройствах Windows",
            "Нет, HTTPS полностью защищает autocomplete",
            "Опасно только для текстовых полей на русском"
        ],
        correctAnswerIndex: 0,
        explanation: "Autocomplete risk: shared computers (library, cafe), browser сохраняет values. Исправление: `<input autocomplete=\"off\">` or `autocomplete=\"new-password\"` для паролей. HTML5 autocomplete types: 'cc-number', 'cc-exp', 'cc-csc'. Defense in depth: также educate users о private browsing mode.",
        link: {
            label: "MDN: autocomplete attribute",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete"
        }
    },
    {
        question: "Что проверять в Amazon S3 Bucket security?",
        answers: [
            "Permissions (ACL): часто buckets публичные (Public Read/Write) по ошибке — любой может скачать/загрузить файлы, включая sensitive data",
            "Только скорость загрузки файлов из bucket",
            "Общее количество файлов в хранилище",
            "Эстетичные имена файлов и folders",
            "Версию AWS SDK используемую приложением",
            "Географическую близость к пользователям",
            "Формат метаданных объектов (JSON vs XML)"
        ],
        correctAnswerIndex: 0,
        explanation: "S3 Security: 1) Block Public Access (recommended default) 2) Bucket policies (deny по умолчанию) 3) Encryption at rest (SSE-S3/SSE-KMS) 4) Versioning (защита от accidental deletion) 5) Access logging 6) MFA Delete. Common mistake: PublicRead ACL. Tools для scan: S3Scanner, bucket-stream. Real breaches: Capital One (2019), misconfigured S3.",
        link: {
            label: "AWS: S3 Security Best Practices",
            url: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
        }
    },
    {
        question: "Нужно ли использовать Cache-Control headers для страниц с чувствительными данными?",
        answers: [
            "Да! `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` предотвращают кеширование sensitive data на диске/in-memory",
            "Да, для максимальной скорости загрузки",
            "Нет, но max-age=300 допустимо",
            "Да, если файлы в формате PDF",
            "Нет, современные браузеры автоматически управляют",
            "Да, но только для мобильных устройств",
            "Нет, HTTPS certificate достаточно"
        ],
        correctAnswerIndex: 0,
        explanation: "Caching sensitive pages: Back button → browser восстанавливает из cache (personal data visible). Public computers: logged out, но data на диске. Headers: `Cache-Control: no-store, no-cache, must-revalidate, private`. `Pragma: no-cache` (HTTP/1.0 compat). Apply к: /profile, /settings, /admin, forms с PII.",
        link: {
            label: "MDN: Cache-Control",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
        }
    },
    {
        question: "Как инструмент 'TruffleHog' или 'GitLeaks' помогает в безопасности?",
        answers: [
            "Сканируют всю Git history на наличие секретов (API keys, passwords, private keys) через regex и entropy analysis — находят забытые credentials",
            "Они ищут трюфели в кулинарных рецептах",
            "Защищают от DDoS атак на уровне сети",
            "Оптимизируют и минифицируют JavaScript код",
            "Автоматически обновляют npm dependencies",
            "Проверяют code style и форматирование",
            "Генерируют documentation из комментариев"
        ],
        correctAnswerIndex: 0,
        explanation: "Secret Scanning: TruffleHog (entropy-based), GitLeaks (regex rules), git-secrets (AWS pre-commit hook). Сканируют: весь git history, commits, branches, даже deleted files. Находят: AWS keys, GCP credentials, private SSH keys, JWT secrets, database passwords. CI/CD integration: fail build если secret detected. Post-breach: rotate all secrets!",
        link: {
            label: "TruffleHog GitHub",
            url: "https://github.com/trufflesecurity/trufflehog"
        }
    },
    {
        question: "Что такое 'Hardcoded Credentials'?",
        answers: [
            "Логины/пароли/API keys, прописанные непосредственно в исходном коде (string literals) — видны в decompiled apps и git history",
            "Особенно сложные устойчивые пароли",
            "Физические аппаратные ключи безопасности (YubiKey)",
            "SSL/TLS сертификаты с длительным сроком",
            "Биометрические данные пользователей",
            "Токены с очень длинным временем жизни",
            "Encrypted database connection strings"
        ],
        correctAnswerIndex: 0,
        explanation: "Hardcoded Credentials: `const API_KEY = 'sk-abc123...'` в коде. Risks: в Git history навсегда, reverse engineering (mobile apps), anyone с доступом к code → full access. Solution: environment variables, secret managers (AWS Secrets Manager, Azure Key Vault), config servers (Spring Cloud Config). Never commit secrets!",
        link: {
            label: "CWE-798: Hardcoded Credentials",
            url: "https://cwe.mitre.org/data/definitions/798.html"
        }
    },
    {
        question: "Почему нельзя использовать HTTP (без S) для передачи credentials?",
        answers: [
            "Все данные (включая пароли, токены, session cookies) передаются открытым текстом — любой в сети может перехватить через packet sniffing",
            "Это выглядит не современно и не модно",
            "Google понизит сайт в поисковой выдаче",
            "Браузеры не сохранят пароль пользователя",
            "HTTP работает медленнее чем HTTPS",
            "Это нарушает стандарты HTML5",
            "Cookie будут автоматически удалены"
        ],
        correctAnswerIndex: 0,
        explanation: "HTTP = plaintext! Network sniffing (Wireshark): видны все headers, cookies, POST body. Public WiFi особенно опасен. Browser warnings: 'Not Secure' в адресной строке. HTTPS обязателен для: login forms, any sensitive data, cookies (Secure flag). Modern browsers: blocks mixed content (HTTPS page loading HTTP resources).",
        link: {
            label: "Let's Encrypt: Free HTTPS",
            url: "https://letsencrypt.org/getting-started/"
        }
    },
    {
        question: "Что делать с дефолтными страницами сервера (Apache, Nginx, Tomcat default pages)?",
        answers: [
            "Удалить или заменить custom error pages — дефолтные страницы раскрывают версию веб-сервера и ОС, помогая в reconnaissance",
            "Оставить для визуальной привлекательности",
            "Использовать как главную страницу сайта",
            "Добавить приветственное сообщение для хакеров",
            "Модифицировать для SEO оптимизации",
            "Конвертировать в API endpoint",
            "Использовать для тестирования производительности"
        ],
        correctAnswerIndex: 0,
        explanation: "Default Pages Disclosure: 'Apache/2.4.41 (Ubuntu) Server at example.com Port 80'. Атакующий: ищет CVE для версии, targeted exploits. Solution: custom error pages (404, 403, 500), remove sample apps (Tomcat /examples), hide server header (`Server: nginx` → remove version). Security by obscurity — не основная защита, но part of defense in depth.",
        link: {
            label: "OWASP: Information Disclosure",
            url: "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"
        }
    },
    {
        question: "Какую роль играет файл robots.txt в безопасности?",
        answers: [
            "Никакой защиты! Это публичный файл с рекомендациями для поисковых ботов — атакующие используют его как карту скрытых директорий",
            "Он полностью защищает admin панель от доступа",
            "Автоматически шифрует весь сайт",
            "Блокирует всех хакеров на DNS уровне",
            "Включает двухфакторную аутентификацию",
            "Удаляет sensitive данные из индекса Google",
            "Создаёт firewall для веб-приложения"
        ],
        correctAnswerIndex: 0,
        explanation: "robots.txt: `Disallow: /admin`, `Disallow: /api/internal/` — directory enumeration cheat sheet для attackers! Search engines могут игнорировать. Best practice: не полагаться на robots.txt для security, использовать authentication. Если секретный path — не указывать в robots.txt! Sensitive directories → .htaccess deny, authentication.",
        link: {
            label: "robots.txt Specification",
            url: "https://www.robotstxt.org/"
        }
    },
    {
        question: "Что такое 'Salt' (соль) в контексте хеширования паролей?",
        answers: [
            "Криптографически случайные уникальные данные, добавляемые к каждому паролю перед хешированием — защищает от Rainbow Tables и parallel cracking",
            "Просто секретный ключ шифрования AES",
            "Вектор инициализации для блочного шифра",
            "Конфигурационный параметр сетевого firewall",
            "Алгоритм генерации случайных чисел",
            "Дополнительный уровень Base64 encoding",
            "Специальный формат storage для паролей"
        ],
        correctAnswerIndex: 0,
        explanation: "Password Salt: каждому паролю — unique random salt (128+ bits). Хранится plaintext рядом с hash. hash = Argon2(password + salt). Rainbow Tables бесполезны (precomputed для no-salt). Parallel cracking сложнее (каждый password = разный salt). Format: bcrypt: `$2b$12$[salt][hash]`. Never reuse salt !",
        link: {
            label: "OWASP: Password Storage Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
        }
    },
    {
        question: "Почему важно отключать Directory Listing на веб-сервере?",
        answers: [
            "Предотвращает автоматическое отображение содержимого папок — атакующие не смогут увидеть структуру файлов, скачать backups, source code",
            "Потому что это визуально некрасиво выглядит",
            "Это создаёт избыточную нагрузку на диск",
            "Это обязательное требование стандарта HTML5",
            "Listing замедляет работу сервера в 2 раза",
            "Современные браузеры не поддерживают listing",
            "Это нарушает правила GDPR compliance"
        ],
        correctAnswerIndex: 0,
        explanation: "Directory Listing: если index.html отсутствует, сервер показывает список файлов. Риск: скачать backup.sql, .git folder, source code, .env файлы. Apache: `Options -Indexes`. Nginx: `autoindex off;`. Defense in depth: также убедиться что sensitive файлы не деплоятся на production.",
        link: {
            label: "Apache: Disable Directory Listing",
            url: "https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html"
        }
    },
    {
        question: "Как злоумышленники используют Shodan?",
        answers: [
            "Поисковая система для IoT устройств, индустриальных систем, открытых портов — находят камеры, SCADA, databases с дефолтными паролями",
            "Для майнинга криптовалюты на GPU",
            "Как мессенджер для коммуникации",
            "Для стриминга видео контента",
            "В качестве VPN сервиса",
            "Как облачное хранилище файлов",
            "Для создания презентаций и документов"
        ],
        correctAnswerIndex: 0,
        explanation: "Shodan ('Dark Google'): индексирует internet-facing devices. Search: `port:3389 country:US` (RDP), `product:MySQL`, `http.title:\"Dashboard\" port:80`. Находит: webcams (default admin/admin), industrial control systems, MongoDB без auth. Defense: не expose services to internet, firewall rules, change default credentials, monitor Shodan for your IPs.",
        link: {
            label: "Shodan Search Engine",
            url: "https://www.shodan.io/"
        }
    },
    {
        question: "Чем опасен публичный доступ к логам (access.log, error.log)?",
        answers: [
            "Логи содержат токены в URL параметрах, PII users (emails, IPs), пути к файлам, версии софта, SQL errors — полная reconnaissance информация",
            "Логи занимают слишком много дискового пространства",
            "Они только текстовые файлы без ценности",
            "Логи нужны исключительно администраторам",
            "Это замедляет работу веб-сервера",
            "Логи автоматически шифруются браузером",
            "Публичный доступ улучшает отладку production"
        ],
        correctAnswerIndex: 0,
        explanation: "Log Exposure: access.log показывает `/reset?token=abc123&email=user@example.com`, User-Agents, Referers. error.log: stack traces, SQL queries, file paths. Атакующий: valid tokens, user enumeration, version info. Defense: restrict access (.htaccess), не логировать sensitive params, log rotation+encryption, centralized logging (ELK).",
        link: {
            label: "OWASP: Logging Cheat Sheet",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое 'Masking' (маскирование) данных?",
        answers: [
            "Замена части символов на placeholder (звёздочки, X) при отображении — показывать '4111 **** **** 1234' вместо полного номера карты",
            "Полное удаление данных из базы",
            "Шифрование AES-256 всех полей",
            "Сжатие данных через gzip compression",
            "Конвертация в Base64 encoding",
            "Архивирование старых записей в ZIP",
            "Перемещение данных в другую таблицу"
        ],
        correctAnswerIndex: 0,
        explanation: "Data Masking: отображение partial data. Credit card: показать last 4 digits. Email: `u***r@example.com`. SSN: `***-**-1234`. НЕ шифрование! Просто UI hiding. Backend всё равно хранит full data (encrypted). Use cases: customer service screens, receipts, logs. Real storage требует encryption!",
        link: {
            label: "NIST: Data Masking",
            url: "https://csrc.nist.gov/glossary/term/data_masking"
        }
    },
    {
        question: "Нужно ли шифровать резервные копии (Backups)?",
        answers: [
            "Обязательно! Backup = полная копия БД often stored offsite — stolen backup tape/disk = полная компрометация всех данных",
            "Нет, backups хранятся в secure location",
            "Только праздничные backups требуют шифрования",
            "Нет, достаточно password-protected ZIP архива",
            "Да, но только для финансовых компаний",
            "Нет, это замедлит процесс восстановления",
            "Backups автоматически защищены RAID"
        ],
        correctAnswerIndex: 0,
        explanation: "Backup Encryption обязателен! Real cases: stolen tapes from vans, cloud bucket misconfiguration. Требования: AES-256 encryption, separate key management, test restoration regularly. Tools: gpg for files, LUKS for disks, cloud-native (AWS EBS encryption). Off-site backups особенно critical (physical theft risk).",
        link: {
            label: "NIST: Backup Security",
            url: "https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final"
        }
    },
    {
        question: "Что проверяет инструмент 'Nuclei' или Burp 'Software Version Reporter'?",
        answers: [
            "Раскрытие версий софта в HTTP headers (Server, X-Powered-By), HTML comments, JS files — mapping для CVE database",
            "Лицензионный статус программного обеспечения",
            "Цветовую схему дизайна сайта",
            "Скорость интернет-соединения пользователя",
            "Географическое местоположение сервера",
            "Контрактные обязательства с вендорами",
            "Статистику посещаемости веб-сайта"
        ],
        correctAnswerIndex: 0,
        explanation: "Version Disclosure: `Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`, HTML comments `<!-- WordPress 5.8 -->`. Атакующий → CVE database → targeted exploit. Nuclei templates: thousands of checks. Defense: remove version headers (Apache: ServerTokens Prod), minimize disclosure, regular патчи важнее obscurity.",
        link: {
            label: "Nuclei Templates",
            url: "https://github.com/projectdiscovery/nuclei-templates"
        }
    },
    {
        question: "Является ли скрытие полей через CSS 'display: none' или 'visibility: hidden' защитой данных?",
        answers: [
            "Абсолютно нет! Данные присутствуют в HTML source code и DOM — любой может прочитать через View Source или DevTools",
            "Да, это надёжный метод защиты",
            "Да, если приложение на React framework",
            "Да, в современных браузерах это работает",
            "Нет, но только для старых версий IE",
            "Да, при использовании HTTPS соединения",
            "Да, если добавить JavaScript obfuscation"
        ],
        correctAnswerIndex: 0,
        explanation: "CSS hiding ≠ security! `<div style='display:none'>Secret: API_KEY_123</div>` — видно в HTML source. Правильный подход: не отправлять sensitive data на client вообще! Server-side filtering. Client = untrusted environment. Real protection: proper authorization на backend API.",
        link: {
            label: "CWE-602: Client-Side Security",
            url: "https://cwe.mitre.org/data/definitions/602.html"
        }
    },
    {
        question: "Как защитить API ключи в мобильных приложениях?",
        answers: [
            "Не хранить sensitive keys в app! Proxy критичные requests через backend BFF. Для unavoidable keys: certificate pinning + code obfuscation + runtime detection",
            "Просто поместить ключи в strings.xml файл",
            "Спрятать как watermark в изображениях",
            "Это невозможно технически защитить",
            "Использовать Base64 encoding ключей",
            "Хранить в SharedPreferences Android",
            "Добавить в Info.plist для iOS"
        ],
        correctAnswerIndex: 0,
        explanation: "Mobile API Keys: app легко decompile (APK → Java). Best: Backend-For-Frontend pattern (BFF) — mobile → your server → 3rd party API. Unavoidable keys (map APIs): obfuscation (ProGuard/R8), runtime integrity checks, certificate pinning, rate limiting на backend. Accept: motivated attacker может извлечь. Minimize blast radius!",
        link: {
            label: "OWASP: Mobile Security",
            url: "https://owasp.org/www-project-mobile-top-10/"
        }
    },
    {
        question: "Что такое 'Tokenization' в контексте платёжных систем?",
        answers: [
            "Замена реального номера карты (PAN) на случайный токен — токен бесполезен за пределами системы, даже при утечке данные карты в безопасности",
            "Выпуск собственной криптовалюты компанией",
            "Использование JWT для аутентификации API",
            "Процесс входа через OAuth токены",
            "Создание session токенов для пользователей",
            "Blockchain технология для транзакций",
            "Генерация QR кодов для платежей"
        ],
        correctAnswerIndex: 0,
        explanation: "Payment Tokenization: PAN 4111111111111111 → Token T9876543210. Token stored в your DB, PAN в tokenization vault (PCI compliant). Breach твоей DB → токены бесполезны without vault access. Apple Pay, Google Pay используют tokenization. PCI DSS: reduces scope. Network tokens vs merchant tokens.",
        link: {
            label: "PCI Tokenization Guidelines",
            url: "https://www.pcisecuritystandards.org/documents/Tokenization_Guidelines_Info_Supplement.pdf"
        }
    },
    {
        question: "Опасно ли использовать GET параметры для передачи чувствительных данных?",
        answers: [
            "Очень опасно! GET params логируются на всех proxy servers, в browser history, Referer headers, SSL не защищает — используйте POST + request body",
            "Нет проблем если используется HTTPS",
            "Опасно только если параметры длиннее 255 символов",
            "Нет проблем для параметров на кириллице",
            "Безопасно для мобильных приложений",
            "Опасно только на HTTP/1.1, безопасно на HTTP/2",
            "GET защищён если добавить CORS headers"
        ],
        correctAnswerIndex: 0,
        explanation: "GET Parameters Exposure: `/api/user?ssn=123-45-6789` → server logs, proxy logs, browser history, analytics. Referer header leak (click link on your site → external site sees full URL). HTTPS шифрует только transport, не URLs! Best: POST с body для sensitive data. Query params → только public/non-sensitive (pagination, filters).",
        link: {
            label: "CWE-598: GET Request with Sensitive Data",
            url: "https://cwe.mitre.org/data/definitions/598.html"
        }
    },
    {
        question: "Как Postman коллекции могут привести к утечке данных?",
        answers: [
            "Public sharing коллекций с hardcoded environment variables (API tokens, passwords) в JSON — instant credential exposure",
            "Postman collections не могут вызвать утечки",
            "Postman это платный инструмент с защитой",
            "Утечка возможна только через API Postman",
            "Проблемы только при использовании на Windows",
            "Через SSL handshake в Postman requests",
            "При экспорте в формат cURL команд"
        ],
        correctAnswerIndex: 0,
        explanation: "Postman Collection Leaks: `environment.json` с variables `{{API_KEY}}=prod_secret_xyz`. User shares collection publicly → credentials exposed. Real cases: GitHub/GitLab search reveals thousands. Best practices: use env variables locally only, never commit, Postman Vault для team sharing, rotate если exposed.",
        link: {
            label: "Postman: Security Best Practices",
            url: "https://learning.postman.com/docs/sending-requests/variables/"
        }
    },
    {
        question: "Что делать при обнаружении утечки credentials/PII?",
        answers: [
            "Немедленно: rotate всех credentials, сброс паролей affected users, breach notification (GDPR 72h), forensic investigation, public disclosure если требуется",
            "Просто молчать и надеяться что никто не заметит",
            "Полностью удалить базу данных",
            "Сменить только UI design сайта",
            "Отключить сервер на неделю",
            "Создать новый домен и переехать",
            "Обвинить хакеров в социальных сетях"
        ],
        correctAnswerIndex: 0,
        explanation: "Breach Response: 1) Containment: rotate keys/passwords, revoke tokens 2) Investigation: scope, what leaked, how 3) Notification: users (email), регуляторы (GDPR 72h), public if major 4) Remediation: fix vulnerability, improve monitoring 5) Prevention: lessons learned. Examples: Equifax (2017), Marriott (2018) — delayed response made worse.",
        link: {
            label: "GDPR: Breach Notification",
            url: "https://gdpr-info.eu/art-33-gdpr/"
        }
    },
    {
        question: "Зачем нужна ротация криптографических ключей (Key Rotation)?",
        answers: [
            "Периодическая смена ключей уменьшает impact при компрометации — старые encrypted data становятся нечитаемыми с украденным старым ключом",
            "Чтобы ключи не заржавели физически",
            "Для визуальной привлекательности dashboard",
            "Чтобы запутать системных администраторов",
            "Ротация требуется только раз в 10 лет",
            "Это маркетинговый трюк вендоров security",
            "Для совместимости с legacy системами"
        ],
        correctAnswerIndex: 0,
        explanation: "Key Rotation: регулярная смена encryption keys (ежегодно или при подозрении). При компрометации: ущерб ограничен периодом использования ключа. Best practices: automated rotation (AWS KMS auto-rotate), versioned keys, re-encrypt data with new key (or dual-layer encryption), audit trail. NIST: rotate при suspicion, периодически, при employee departure.",
        link: {
            label: "AWS: KMS Key Rotation",
            url: "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
        }
    },
    {
        question: "Что такое 'Perfect Forward Secrecy' (PFS) в TLS?",
        answers: [
            "Свойство протокола: компрометация long-term private key не позволяет расшифровать прошлые перехваченные сессии — unique session keys",
            "Идеальный пароль пользователя длиной 128 символов",
            "Секретный режим чата в мессенджерах",
            "Browser incognito mode с VPN",
            "Тип SSL сертификата с вечным сроком",
            "Алгоритм шифрования будущего поколения",
            "Feature только Enterprise версий HTTPS"
        ],
        correctAnswerIndex: 0,
        explanation: "Perfect Forward Secrecy (PFS): каждая TLS session использует ephemeral (temporary) Diffie-Hellman keys (DHE/ECDHE). Даже если server RSA private key украден в будущем → прошлые перехваченные sessions остаются зашифрованными. Cipher suites: ECDHE-RSA-AES256-GCM-SHA384. Modern browsers требуют PFS. NSA monitoring defense!",
        link: {
            label: "EFF: Perfect Forward Secrecy",
            url: "https://www.eff.org/deeplinks/2013/08/pushing-perfect-forward-secrecy-important-web-privacy-protection"
        }
    },
    {
        question: "Почему комментарии в production HTML/JavaScript коде могут быть опасны?",
        answers: [
            "Разработчики случайно оставляют TODO с паролями, описания уязвимостей, internal API endpoints, tech stack details — reconnaissance goldmine",
            "Комментарии увеличивают размер файла на 2-3%",
            "Браузеры могут случайно выполнить их как код",
            "Это визуально портит исходный код",
            "Поисковые системы индексируют комментарии",
            "Comments нарушают W3C HTML стандарты",
            "Увеличивается время парсинга на 15ms"
        ],
        correctAnswerIndex: 0,
        explanation: "HTML/JS Comments: `<!-- TODO: remove hardcoded admin password 'temp123' -->`, `// API endpoint: /api/internal/debug?key=xyz`. Атакующий: View Source → finds secrets, internal URLs, logic flaws. Minification удаляет комментарии. Best practice: strip comments в production build, no sensitive info в comments вообще!",
        link: {
            label: "CWE-615: Information Exposure Through Comments",
            url: "https://cwe.mitre.org/data/definitions/615.html"
        }
    },
    {
        question: "Как работает разведка через Wappalyzer?",
        answers: [
            "Browser extension анализирует HTTP headers, HTML patterns, JS libraries для определения tech stack — атакующий узнаёт versions → ищет CVE",
            "Это вирус крадущий пароли пользователя",
            "SQL injection автоматический инструмент",
            "Password brute-force утилита",
            "Инструмент для DDoS атак",
            "malware для кражи  cookies",
            "Phishing framework для email campaigns"
        ],
        correctAnswerIndex: 0,
        explanation: "Wappalyzer: определяет WordPress 6.1, jQuery 3.6, Cloudflare, Google Analytics. Атакующий: WordPress 6.1 → search CVE-2023-xxxx → targeted exploit. Defense: version hiding помогает минимально, главное — regular updates & patches. BuiltWith, WhatRuns — аналогичные tools.",
        link: {
            label: "Wappalyzer Technology Lookup",
            url: "https://www.wappalyzer.com/"
        }
    },
    {
        question: "Что такое 'File Enumeration' или 'Forced Browsing'?",
        answers: [
            "Перебор распространённых имён файлов/директорий (backup.sql, /admin, .git) для обнаружения незащищённых ресурсов на сервере",
            "Alphabetical сортировка файлов в проводнике",
            "Автоматическое удаление старых файлов",
            "Процесс архивирования данных в ZIP",
            "Создание thumbnail preview для изображений",
            "Индексация файлов для desktop search",
            "Defragmentation жёсткого диска"
        ],
        correctAnswerIndex: 0,
        explanation: "Forced Browsing: tools (ffuf, dirb) пробуют `/admin.php`, `/backup/`, `/.git/`, `/config.bak`. Wordlists: SecLists/Discovery/Web-Content. Находят: exposed backups, admin panels, debug pages. Defense: authentication на sensitive paths, disable directory listing, remove debug files, web application firewall (WAF).",
        link: {
            label: "OWASP: Forced Browsing",
            url: "https://owasp.org/www-community/attacks/Forced_browsing"
        }
    },
    {
        question: "Опасен ли `.DS_Store` файл macOS на веб-сервере?",
        answers: [
            "Да! `.DS_Store` содержит имена всех файлов в директории, включая скрытые — раскрывает структуру, помогает enumeration attack",
            "Нет, это просто системный файл macOS безвредный",
            "Опасен только на Windows серверах",
            "Нет, он автоматически удаляется",
            "Опасность только для Linux серверов",
            "`.DS_Store` полезен для SEO",
            "Это защитный механизм macOS"
        ],
        correctAnswerIndex: 0,
        explanation: ".DS_Store Disclosure: macOS создаёт в каждой папке. Содержит: list of files (даже hidden), folder structure. Атакующий: скачивает `/.DS_Store` → получает map всех файлов. Tools: ds_store_exp. Defense: .htaccess `<Files .DS_Store> Deny </Files>`, git clean, deployment script exclusion.",
        link: {
            label: "DS_Store Exposure",
            url: "https://github.com/anantshri/DS_Store_crawler_parser"
        }
    },
    {
        question: "Как защитить `.git` папку на production сервере?",
        answers: [
            "Best: не деплоить .git вообще! Alternative: Nginx/Apache deny access к скрытым папкам `location ~ /\\.git { deny all; }`",
            "Переименовать папку в  `_git` для скрытности",
            "Установить password через .htpasswd  файл",
            "Сделать read-only permissions chmod 444",
            "Использовать git-crypt для шифрования",
            "Добавить в robots.txt Disallow правило",
            "Переместить .git в subdomain"
        ],
        correctAnswerIndex: 0,
        explanation: ".git Exposure: `/.git/config` содержит repo URL, potential credentials. Злоумышленник: скачивает .git → восстанавливает весь source code, history, secrets. Tools: git-dumper, GitHack. Defense: 1) exclude from deployment 2) web server config deny (Nginx: `location ~ /\\.` { deny all; }) 3) regular security scans.",
        link: {
            label: "GitHack Tool",
            url: "https://github.com/lijiejie/GitHack"
        }
    },
    {
        question: "Что такое 'Padding Oracle Attack'?",
        answers: [
            "Криптографическая атака на CBC mode: по error messages о padding злоумышленник постепенно расшифровывает ciphertext без ключа",
            "Атака на Oracle Database через SQL injection",
            "Брутфорс CSS padding values для UI bugs",
            "Exploit уязвимости в Java Virtual Machine",
            "Переполнение буфера в network packets",
            "DDoS через UDP packet flooding",
            "XSS через манипуляцию DOM padding"
        ],
        correctAnswerIndex: 0,
        explanation: "Padding Oracle: CBC mode с PKCS#7 padding. Server returns different errors: 'invalid padding' vs 'invalid MAC'. Атакующий: manipulates ciphertext blocks, queries server → decrypts byte-by-byte. Famous: ASP.NET (2010). Defense: use authenticated encryption (AES-GCM), generic error messages, constant-time validation.",
        link: {
            label: "Padding Oracle Attack Explained",
            url: "https://robertheaton.com/2013/07/29/padding-oracle-attack/"
        }
    },
    {
        question: "Безопасно ли использовать `Math.random()` для генерации токенов безопасности?",
        answers: [
            "Категорически нет! `Math.random()` предсказуем (pseudo-random) — используйте `crypto.getRandomValues()` или `crypto.randomBytes()` для CSPRNG",
            "Да, Math.random() идеален для всех целей",
            "Да, но только в новых браузерах Chrome/Firefox",
            "Безопасно только для temporary tokens",
            "Нет, но подходит для production games",
            "Да, если умножить на большое число",
            "Безопасно только на HTTPS сайтах"
        ],
        correctAnswerIndex: 0,
        explanation: "Math.random() = NOT cryptographically secure! Predictable seed, deterministic algorithm. Атакующий может predict future values. CSPRNG (Cryptographically Secure): `Web Crypto API: crypto.getRandomValues()`, Node.js: `crypto.randomBytes()`, Python: `secrets` module. Use for: session IDs, CSRF tokens, password reset codes, encryption keys.",
        link: {
            label: "MDN: Crypto.getRandomValues",
            url: "https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues"
        }
    },
    {
        question: "Что такое 'Side-Channel Attack' (атака по побочным каналам)?",
        answers: [
            "Извлечение информации из физической реализации: timing analysis, power consumption, electromagnetic radiation, acoustic analysis — обходит криптографию",
            "Атака через соседний WiFi канал (channel 6 vs 11)",
            "Social engineering через второстепенных сотрудников",
            "Email phishing campaign с attachments",
            "Man-in-the-middle через rogue proxy",
            "SQL injection через alternative input fields",
            "XSS через third-party widgets"
        ],
        correctAnswerIndex: 0,
        explanation: "Side-Channel Attacks: Timing (разное время для correct/incorrect password char), Power Analysis (DPA на smartcards), Acoustic (keyboard sounds → keystrokes), EM radiation (TEMPEST). Famous: Spectre/Meltdown (CPU cache timing). Defense: constant-time algorithms, hardware isolation, signal shielding, noise injection.",
        link: {
            label: "Side-Channel Attacks Overview",
            url: "https://en.wikipedia.org/wiki/Side-channel_attack"
        }
    },
    {
        question: "Какой подход безопаснее: Blacklist или Whitelist для валидации input?",
        answers: [
            "Whitelist (allow only known good) — blacklist всегда можно обойти новыми вариациями, whitelist blocks everything кроме явно разрешённого",
            "Blacklist более гибкий и безопасный",
            "Оба подхода абсолютно одинаковы",
            "Ni один не работает на практике",
            "Blacklist лучше для production",
            "Whitelist только для development",
            "Зависит от фазы луны"
        ],
        correctAnswerIndex: 0,
        explanation: "Whitelist vs Blacklist: Blacklist блокирует `<script>`, но атакующий использует `<ScRiPt>`, `<img onerror=...>`, `<svg onload=...>`. Whitelist: allow только [a-zA-Z0-9], block всё остальное. Применение: file uploads (whitelist: .jpg,.png), input validation (allow only expected chars), CSP (whitelist domains). Blacklist полезен как дополнительный слой, не единственная защита.",
        link: {
            label: "OWASP: Input Validation",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        }
    },
    {
        question: "Какой режим блочного шифрования (Block Cipher Mode) небезопасен и визуально сохраняет паттерны?",
        answers: [
            "ECB (Electronic Codebook) — каждый block шифруется независимо, одинаковые plaintext blocks → одинаковые ciphertext blocks (виден контур пингвина)",
            "CBC (Cipher Block Chaining) mode",
            "GCM (Galois/Counter Mode)",
            "CTR (Counter) mode",
            "CFB (Cipher Feedback) mode",
            "OFB (Output Feedback) mode",
            "XTS (XEX Tweaked CodeBook) mode"
        ],
        correctAnswerIndex: 0,
        explanation: "ECB Mode Problem: шифрует каждый 16-byte block independently. Одинаковые blocks plaintext → одинаковые blocks ciphertext. Famous: ECB penguin image — outline виден после шифрования! Never использовать ECB. Best: AES-GCM (authenticated encryption), CBC с уникальным IV, CTR mode.",
        link: {
            label: "ECB Penguin Visualization",
            url: "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)"
        }
    },
    {
        question: "Что такое 'IV Reuse' (повторное использование вектора инициализации)?",
        answers: [
            "Критическая ошибка в stream ciphers и CTR mode — один IV с одним ключом для разных сообщений позволяет XOR attack и восстановление plaintext",
            "Экономия memory через переиспользование",
            "Улучшение производительности шифрования на 30%",
            "Смена сетевого протокола на более быстрый",
            "Техника сжатия encrypted данных",
            "Автоматическая ротация ключей системой",
            "Backward compatibility механизм"
        ],
        correctAnswerIndex: 0,
        explanation: "IV Reuse Attack: CTR/Stream cipher: C1 = P1 ⊕ Keystream, C2 = P2 ⊕ Keystream (same IV+key). Атакующий: C1 ⊕ C2 = P1 ⊕ P2. Known plaintext → остальное восстановимо. WEP WiFi  был взломан из-за IV reuse! Defense: уникальный IV для каждого сообщения (random или counter-based).",
        link: {
            label: "IV Attacks Explained",
            url: "https://crypto.stackexchange.com/questions/2991/why-must-iv-key-pairs-not-be-reused-in-ctr-mode"
        }
    },
    {
        question: "В чем опасность использования алгоритма 'none' в JWT?",
        answers: [
            "Позволяет подделать токен — атакующий меняет alg на 'none', удаляет signature, server принимает если не validates algorithm properly",
            "Никакой опасности, это стандартный алгоритм",
            "Токен становится слишком длинным для передачи",
            "JWT перестаёт работать в old browsers",
            "Это улучшает производительность сервера",
            "none algorithm требуется для refresh tokens",
            "Используется только для development окружения"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT 'none' Algorithm Attack: header `{\"alg\":\"none\"}`. Library bug: если не проверяет algorithm → accepts unsigned token. Атакующий: modify payload (role: admin), remove signature. CVE-2015-9235 (many libs). Defense: whitelist allowed algorithms (HS256, RS256), reject 'none', library updates.",
        link: {
            label: "Auth0: JWT None Algorithm",
            url: "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
        }
    },
    {
        question: "Безопасно ли хранить секретные данные в JWT payload?",
        answers: [
            "Абсолютно нет! JWT payload это Base64 (НЕ encryption) — любой может декодировать и прочитать содержимое, signature только проверяет подлинность",
            "Да, JWT полностью зашифрован",
            "Да, если используется HTTPS",
            "Безопасно при наличии RSA256 signature",
            "Да, только для email адресов пользователей",
            "Безопасно если токен в httpOnly cookie",
            "Да, современные browsers шифруют JWT"
        ],
        correctAnswerIndex: 0,
        explanation: "JWT Payload = Base64 encoded JSON (NOT encrypted!). Любой: `atob(payloadPart)` → reads all claims. Signature проверяет integrity, не confidentiality. Never store: passwords, credit cards, SSN в payload. Store: user ID, roles, expiration. Для sensitive data: encrypted tokens (JWE) или reference tokens.",
        link: {
            label: "JWT.io: Introduction",
            url: "https://jwt.io/introduction"
        }
    },
    {
        question: "Что такое 'SSL Stripping' атака?",
        answers: [
            "MitM атака: злоумышленник перехватывает HTTPS→HTTP downgrade, жертва общается с сервером через HTTP thinking it's secure — credentials visible",
            "Удаление SSL сертификата с сервера",
            "Striptease performance для хакеров",
            "Автоматическое обновление SSL на новую версию",
            "Процесс удаления padding из encrypted data",
            "Compression алгоритм для HTTPS трафика",
            "Техника минификации JavaScript через SSL"
        ],
        correctAnswerIndex: 0,
        explanation: "SSL Stripping (sslstrip tool): User → http://bank.com (redirects to https). MitM: intercepts, keeps HTTPS to server, serves HTTP to user. User sees HTTP (no lock icon), но многие не замечают. Data plaintext к attacker. Defense: HSTS header, user awareness, HTTPS Everywhere browser extension.",
        link: {
            label: "SSL Strip Attack Explained",
            url: "https://www.venafi.com/blog/what-are-ssl-stripping-attacks"
        }
    },
    {
        question: "Как HSTS помогает против SSL Stripping?",
        answers: [
            "Strict-Transport-Security header заставляет browser ВСЕГДА использовать HTTPS для домена (даже при HTTP link) — prevents downgrade attacks",
            "Блокирует все HTTP соединения globally",
            "Автоматически шифрует весь network traffic",
            "Проверяет валидность SSL сертификатов",
            "Увеличивает скорость HTTPS handshake",
            "Удаляет mixed content автоматически",
            "Генерирует новые SSL certificates"
        ],
        correctAnswerIndex: 0,
        explanation: "HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. Browser remembers: блокирует HTTP requests, auto-upgrades links, ignores user bypass. Preload list (hardcoded в Chrome/Firefox): protection с first visit. Downside: трудно отменить (especially preload). Max-age = seconds.",
        link: {
            label: "HSTS Preload List",
            url: "https://hstspreload.org/"
        }
    },
    {
        question: "Что такое 'Mixed Content' warning в браузерах?",
        answers: [
            "HTTPS страница загружает ресурсы (images, scripts, CSS) по HTTP — потенциальная Man-in-the-Middle injection, browsers block или warn",
            "Смешивание текста разных языков (EN/RU)",
            "Inclusion различных типов файлов (JPG+PNG)",
            "Ошибка в HTML markup структуре",
            "Конфликт между CSS frameworks",
            "Multiple JavaScript versions на странице",
            "Использование inline и external стилей"
        ],
        correctAnswerIndex: 0,
        explanation: "Mixed Content: `<script src='http://cdn.example.com/app.js'>` на HTTPS page. Риск: MitM modifies script → XSS. Types: Active (scripts, iframes - blocked), Passive (images, audio - warning). Modern browsers: auto-upgrade или block. Fix: use HTTPS для всех ресурсов, Content-Security-Policy upgrade-insecure-requests.",
        link: {
            label: "MDN: Mixed Content",
            url: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
        }
    },
    {
        question: "Зачем нужен 'Hardware Security Module' (HSM)?",
        answers: [
            "Физическое tamper-resistant устройство для secure хранения криптографических ключей и выполнения crypto операций — ключи never leave HSM",
            "Для ускорения graphics rendering в играх",
            "Майнинг криптовалюты более эффективно",
            "Хранение резервных копий файлов",
            "Увеличение RAM capacity сервера",
            "Network routing и firewall функции",
            "Автоматическая очистка вирусов"
        ],
        correctAnswerIndex: 0,
        explanation: "HSM (Hardware Security Module): специализированное устройство (FIPS 140-2 Level 3/4). Private keys stored в tamper-proof hardware. Crypto operations внутри HSM. Applications: payment processing (PIN encryption), SSL/TLS private keys, code signing, blockchain. Cloud HSMs: AWS CloudHSM, Azure Dedicated HSM. Physical security + cryptographic isolation.",
        link: {
            label: "NIST: HSM Information",
            url: "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/validated-modules"
        }
    },
    {
        question: "Что такое 'Timing Attack' на сравнение строк/хешей?",
        answers: [
            "Если функция сравнения возвращается раньше при первом несовпадающем символе — атакующий измеряет время response, посимвольно брутфорсит secret (token, HMAC)",
            "Атака в определённое время суток (night)",
            "DDoS flooding с временными метками",
            "Race condition в multithreading",
            "Измерение network latency для геолокации",
            "Синхронизация часов между серверами",
            "Timeout errors в API requests"
        ],
        correctAnswerIndex: 0,
        explanation: "Timing Attack Example: `if (hash[0] != input[0]) return false; ...` — быстрее fails на 1st char. Атакующий: пробует 'a'-'z' для 1st char, измеряет time → longest time = correct char. Repeats для каждого char. Defense: constant-time comparison (`hash_equals` PHP, `timingSafeEqual` Node.js, `hmac.compare_digest` Python).",
        link: {
            label: "Timing Attack Explanation",
            url: "https://codahale.com/a-lesson-in-timing-attacks/"
        }
    },
    {
        question: "Как правильно сравнивать токены/хеши для защиты от Timing Attacks?",
        answers: [
            "Использовать constant-time comparison functions: `hash_equals()` (PHP), `crypto.timingSafeEqual()` (Node.js), `hmac.compare_digest()` (Python)",
            "Простое сравнение через оператор ==",
            "String comparison через strcmp() function",
            "Оператор !== для проверки неравенства",
            "Сравнение длин строк через .length",
            "Regular expression matching /^token$/",
            "Loop через каждый символ с if statements"
        ],
        correctAnswerIndex: 0,
        explanation: "Constant-Time Comparison: сравнивает ВСЕ bytes независимо от результата. Время одинаково для correct/incorrect input. PHP: `hash_equals($known, $user)`. Node: `crypto.timingSafeEqual(buf1, buf2)`. Python: `hmac.compare_digest(a, b)`. Never: ==, strcmp для security-critical comparisons!",
        link: {
            label: "PHP: hash_equals",
            url: "https://www.php.net/manual/en/function.hash-equals.php"
        }
    },
    {
        question: "Можно ли использовать устаревшие cipher suites (RC4, 3DES) в TLS?",
        answers: [
            "Категорически нет! RC4 имеет biases, 3DES уязвим к SWEET32 (birthday attack на 64-bit blocks) — используйте AES-GCM, ChaCha20-Poly1305",
            "Да, они очень быстрые и эффективные",
            "Только для banking applications требуется",
            "Да, если это VPN соединение",
            "Безопасно только для internal networks",
            "Используются только в legacy IoT devices",
            "Обязательны для PCI DSS compliance"
        ],
        correctAnswerIndex: 0,
        explanation: "Deprecated Ciphers: RC4 (biases → key recovery), 3DES (SWEET32 attack на 64-bit blocks), CBC mode ciphers (BEAST, Lucky13). Modern: TLS 1.3 (только AEAD cipher suites), TLS 1.2 с AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. Check: SSL Labs, testssl.sh. Disable weak ciphers in web server config.",
        link: {
            label: "Mozilla SSL Configuration Generator",
            url: "https://ssl-config.mozilla.org/"
        }
    },
    {
        question: "Что такое уязвимости 'BEAST', 'CRIME', 'POODLE' в TLS/SSL?",
        answers: [
            "Атаки на старые версии SSL/TLS и CBC cipher mode — позволяют расшифровать session cookies через chosen-plaintext attack",
            "Названия вирусов для Windows системы",
            "Типы животных в зоопарке безопасности",
            "Имена хакерских группировок APT",
            "Алгоритмы машинного обучения",
            "Versions of malware trojans",
            "Кодовые названия NSA operations"
        ],
        correctAnswerIndex: 0,
        explanation: "SSL/TLS Attacks: BEAST (TLS 1.0 CBC), CRIME (TLS compression), POODLE (SSLv3 CBC padding oracle). Все exploited CBC mode weaknesses. Defense: disable SSLv3/TLS 1.0, disable TLS compression, use TLS 1.2+ with AEAD ciphers (GCM), server-side mitigation patches. Check vulnerability: testssl.sh tool.",
        link: {
            label: "SSL/TLS Attacks Overview",
            url: "https://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS/SSL"
        }
    },
    {
        question: "Опасно ли включать HTTP compression  (gzip) для HTTPS (BREACH attack)?",
        answers: [
            "Да, если на странице есть user input reflection и secrets (CSRF token, session ID) — атакующий угадывает secret по размеру compressed response",
            "Нет, compression всегда безопасен",
            "Опасно только для image файлов",
            "gzip полностью несовместим с HTTPS",
            "Безопасно если используется HTTP/2",
            "Compression увеличивает безопасность",
            "Риск только для PDF documents"
        ],
        correctAnswerIndex: 0,
        explanation: "BREACH Attack (2013): если page показывает user input (`?search=test`) + содержит secret (CSRF token), compression reveals secret length. Атакующий: пробует prefixes, shortest response = correct. Mitigation: disable compression для sensitive pages, randomize secrets, CSRF token per-request, separate secrets from user input.",
        link: {
            label: "BREACH Attack Paper",
            url: "http://breachattack.com/"
        }
    },
    {
        question: "Что такое 'Clipboard Sniffing' или 'Clipboard Hijacking'?",
        answers: [
            "Malware мониторит clipboard — крадёт скопированные passwords/credit cards или подменяет crypto wallet addresses перед вставкой",
            "Нюхание клея в офисных принадлежностях",
            "Автоматическая очистка буфера обмена",
            "Copy-paste функция в текстовых редакторах",
            "Синхронизация clipboard между devices",
            "Ускорение копирования больших файлов",
            "Форматирование текста при вставке"
        ],
        correctAnswerIndex: 0,
        explanation: "Clipboard Attacks: Malware hooks clipboard API. Scenarios: 1) User copies password → malware exfiltrates 2) User copies Bitcoin address → malware replaces с attacker's address (typosquatting). Real malware: ComboJack, Evrial. Defense: paste verification для crypto addresses, password managers (auto-fill without clipboard), clipboard isolation в browsers.",
        link: {
            label: "Clipboard Hijacking Malware",
            url: "https://www.malwarebytes.com/blog/news/2018/06/clipboardhijacker-malware-targets-us-bank-customers"
        }
    },
    {
        question: "Помогает ли экранная клавиатура (On-Screen Keyboard) от keyloggers?",
        answers: [
            "Только от hardware keyloggers — software keyloggers делают screenshots при mouse clicks, videos screen recording или tracking cursor position",
            "Да, полная защита от всех keyloggers",
            "Нет, абсолютно бесполезна всегда",
            "Помогает только на Windows 7",
            "Защищает только mobile устройства",
            "Эффективна только с touchscreen",
            "Работает только если нет мыши"
        ],
        correctAnswerIndex: 0,
        explanation: "On-Screen Keyboard Limitations: защита от physical keyloggers (USB/PS2 interceptors). Software keyloggers: screenshot on click, video recording, mouse tracking, OCR. Modern malware often includes screen capture. Best defense: anti-malware software, 2FA (keylogger steals password, но не 2FA code), virtual machines для sensitive tasks.",
        link: {
            label: "Keylogger Types",
            url: "https://www.kaspersky.com/resource-center/definitions/keylogger"
        }
    },
    {
        question: "Что такое 'Heap Dump' и чем он опасен?",
        answers: [
            "Snapshot оперативной памяти Java/Node процесса для debugging — содержит пароли, API keys, session tokens, PII в plaintext в переменных",
            "Garbage collection процесс в Java",
            "Выброс ошибок в консоль DevTools",
            "Копия файла подкачки Windows (pagefile)",
            "Процесс очистки кеша браузера",
            "Архивирование heap allocations в ZIP",
            "Удаление unused objects из памяти"
        ],
        correctAnswerIndex: 0,
        explanation: "Heap Dump Risk: `jmap -dump` (Java), Chrome DevTools Memory snapshot. Variables в dump: plaintext passwords (`String password = 'admin123'`), decrypted data, session keys. Accessible если: server compromise, insider threat, misconfigured monitoring. Defense: minimize sensitive data lifetime, overwrite/zero memory after use, encrypt dumps, restrict access.",
        link: {
            label: "Java Heap Dump Security",
            url: "https://www.oracle.com/java/technologies/javase/seccodeguide.html"
        }
    },
    {
        question: "Как защитить sensitive данные в оперативной памяти (RAM)?",
        answers: [
            "Use SecureString (C#), mlock() для prevent swapping to disk, zero/overwrite buffers сразу после использования, minimal lifetime для secrets in memory",
            "Невозможно защитить данные в RAM",
            "Выключать компьютер после каждого использования",
            "Использовать только SSD вместо HDD",
            "Увеличить объём оперативной памяти",
            "Установить DDR5 вместо DDR4",
            "Включить Windows Defender Firewall"
        ],
        correctAnswerIndex: 0,
        explanation: "Memory Protection: 1) SecureString (C#/.NET): encrypted in memory 2) mlock()/VirtualLock(): prevent пароли в swap file 3) Zeroization: `memset(buffer, 0, size)` после use 4) Stack allocation для secrets (auto-cleared), не heap 5) Minimal lifetime. Languages: Rust (Drop trait), Go (defer zeroing). Physical: cold boot attacks (RAM remanence) → full disk encryption.",
        link: {
            label: "Secure Memory Handling",
            url: "https://github.com/veorq/cryptocoding#clean-memory-of-secret-data"
        }
    },
    {
        question: "В чем риск использования vim/nano на production server без настройки?",
        answers: [
            "Editors создают swap/backup файлы (.swp, .config.php~, .save) — если crash, файлы остаются и могут быть downloadable с secrets",
            "vim очень сложный для использования",
            "Нет мышки для редактирования",
            "Черный экран пугает пользователей",
            "Отсутствует syntax highlighting",
            "Невозможно копировать текст",
            "Нет visual интерфейса для навигации"
        ],
        correctAnswerIndex: 0,
        explanation: "Editor Temp Files: vim создаёт `.config.php.swp`, nano → `.config.php.save`, emacs → `config.php~`. Если editor crashes → файлы остаются. Атакующий: enumeration attack обнаруживает - скачивает с credentials. Defense: .vimrc `set nobackup noswapfile`, disable recovery files, gitignore .swp, regular cleanup scripts.",
        link: {
            label: "Vim Swap Files Security",
            url: "https://vim.fandom.com/wiki/Remove_swap_and_backup_files_from_your_working_directory"
        }
    },
    {
        question: "Что такое 'Data Loss Prevention' (DLP) системы?",
        answers: [
            "Мониторинг и блокировка передачи конфиденциальных данных (PII, credit cards, IP) за периметр через email, USB, cloud uploads — pattern recognition",
            "Просто потеря всех данных компании",
            "Протокол для загрузки файлов с сервера",
            "Система автоматического backup важных данных",
            "Tools для восстановления deleted files",
            "Антивирус для защиты от ransomware",
            "Firewall для блокировки DDoS атак"
        ],
        correctAnswerIndex: 0,
        explanation: "DLP Systems: сканируют данные in-motion (email, web uploads), at-rest (file servers), in-use (endpoint). Pattern matching: regex для credit cards (`\\d{4}-\\d{4}-\\d{4}-\\d{4}`), keywords ('confidential'), ML classification. Actions: block, quarantine, alert. Vendors: Symantec, McAfee, Forcepoint. Cloud DLP: Google Workspace, Microsoft 365.",
        link: {
            label: "NIST: DLP Guide",
            url: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
        }
    },
    {
        question: "Опасно ли логировать полные URLs в access logs?",
        answers: [
            "Очень опасно! GET parameters остаются в logs: `/reset?token=secret123&email=user@example.com` — logs читают многие employees, backups unencrypted",
            "Нет, это стандартная практика logging",
            "Опасно только если URL длиннее 1024 bytes",
            "Безопасно при ротации логов daily",
            "Логи автоматически шифруются сервером",
            "Риск только для Apache, nginx безопасен",
            "URLs в логах всегда sanitized автоматически"
        ],
        correctAnswerIndex: 0,
        explanation: "URL Logging Risk: `GET /api/reset?token=a1b2c3...` → access.log. Token valid возможно hours. Logs: доступны sysadmins, SOC team, backed up to S3, aggregated в SIEM. Best: 1) POST для sensitive data (не URLs) 2) sanitize URLs before logging 3) encrypt logs 4) restrict access 5) short token lifetime.",
        link: {
            label: "OWASP: Logging Guide",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое 'Keyboard Cache' на мобильных телефонах?",
        answers: [
            "Autocorrect dictionary сохраняет введённые слова включая passwords/PINs если input field не помечен как secure — доступен в settings ещё долго",
            "Просто кеш клавиатур для быстрой загрузки",
            "Залипание физических клавиш devices",
            "Подсветка клавиатуры в темноте",
            "Vibration feedback при нажатии",
            "Раскладка клавиатуры QWERTY vs AZERTY",
            "Swipe gesture recording для touch typing"
        ],
        correctAnswerIndex: 0,
        explanation: "Mobile Keyboard Cache: iOS/Android keyboards запоминают typed words для autocomplete. Если `<input type='text'>` для password/credit card → keyboard cache learns. Attack: physical access→ Settings → Keyboard → learned words. Defense: `autocomplete='off'`, `type='password'`, custom keyboards для sensitive input, educate users clear keyboard dictionary.",
        link: {
            label: "iOS Keyboard Security",
            url: "https://support.apple.com/guide/security/secure-keyboard-entry-sec70bc6f1b5/web"
        }
    },
    {
        question: "Нужно ли отключать browser caching для страниц с sensitive данными (личный кабинет)?",
        answers: [
            "Обязательно! `Cache-Control: no-store` предотвращает сохранение на disk — иначе Back button или shared computer показывает personal data после logout",
            "Нет, кеш ускоряет загрузку страниц",
            "Только для admin панелей требуется",
            "Browser сам решает что кешировать",
            "Безопасно если используется HTTPS",
            "Нужно только на мобильных устройствах",
            "Cache автоматически очищается при logout"
        ],
        correctAnswerIndex: 0,
        explanation: "Sensitive Page Caching: без headers browser кеширует на disk. Scenarios: 1) Back button after logout → cached page visible 2) shared computer → next user sees data 3) browser crash → recovery shows cached content. Headers: `Cache-Control: no-store, no-cache, must-revalidate, private`. Apply to: /profile, /settings, /dashboard.",
        link: {
            label: "HTTP Caching: Best Practices",
            url: "https://web.dev/http-cache/"
        }
    },
    {
        question: "Что такое 'Exposed .vscode folder' и какие риски?",
        answers: [
            "Папка `.vscode` содержит `launch.json`, `settings.json` с environment variables, API keys, database connection strings для debugging — exposed on web",
            "Просто визуальный редактор VSCode",
            "Вирус маскирующийся под VSCode",
            "Расширение для браузера Chrome",
            "Официальная папка Microsoft продуктов",
            "Системная папка Windows для кодеков",
            "IDE theme и color scheme конфигурация"
        ],
        correctAnswerIndex: 0,
        explanation: ".vscode Exposure: `launch.json` содержит `\"env\": {\"API_KEY\": \"prod_123\", \"DATABASE_URL\": \"...\"}` для debugging. Если деплоится on web server → `example.com/.vscode/launch.json` downloadable. Also: `.idea` (IntelliJ), `.vs` (Visual Studio). Defense: .gitignore IDE folders, exclude from deployment, web server deny rules.",
        link: {
            label: "VSCode Security",
            url: "https://code.visualstudio.com/docs/editor/workspace-trust"
        }
    },
    {
        question: "Безопасно ли передавать credentials в HTTP Basic Authentication?",
        answers: [
            "Только если HTTPS (TLS)! Basic Auth передаёт credentials в Base64 каждом request — без TLS это plaintext, но TLS шифрует весь HTTP including headers",
            "Никогда не безопасно использовать Basic Auth",
            "Безопасно только в private networks за firewall",
            "Base64 является достаточным шифрованием",
            "Безопасно если пароль длиннее 20 символов",
            "Только для admin users это допустимо",
            "Basic Auth deprecated в HTTP/2"
        ],
        correctAnswerIndex: 0,
        explanation: "HTTP Basic Auth: `Authorization: Basic base64(username:password)`. Base64 ≠ encryption! Anyone intercepts → instant credentials. HTTPS required: TLS encrypts entire HTTP (headers+body). Still issues: credentials sent every request (use token after initial auth), no logout mechanism, phishing риск. Modern alternative: OAuth 2.0, JWT bearer tokens.",
        link: {
            label: "MDN: Basic Authentication",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication"
        }
    },
    {
        question: "Как работает 'Memory Scraping' malware на POS terminals?",
        answers: [
            "Malware сканирует RAM платёжного терминала, ищет pattern Track 1/2 магнитной полосы (credit card data) до того как POS software её зашифрует",
            "Физическое соскабливание микросхем памяти",
            "Удаление истории транзакций из памяти",
            "Stealing оперативной памяти devices",
            "Очистка cache для ускорения POS",
            "Compression данных в RAM для экономии",
            "Defragmentation памяти терминала"
        ],
        correctAnswerIndex: 0,
        explanation: "POS RAM Scraping: Track 2 format: `1234567890123456=25121011234567890123` (PAN=expiry=service code). Malware: memory dump → regex search patterns → exfiltrate. Famous: Target breach (2013), Home Depot (2014). Defense: Point-to-Point Encryption (P2PE) — card data encrypted at mag stripe reader, RAM never sees plaintext, memory protection, POS hardening.",
        link: {
            label: "PCI: POS Security",
            url: "https://www.pcisecuritystandards.org/document_library?category=pcissc"
        }
    },
    {
        question: "Что такое 'Credential Stuffing' атака?",
        answers: [
            "Автоматизированный массовый login attempt с использованием баз утекших паролей с других сайтов — exploits password reuse пользователей",
            "Наполнение баз данных фальшивыми credentials",
            "Процесс сброса всех паролей в системе",
            "Создание множества test аккаунтов",
            "Hashing паролей с additional salt",
            "Конфигурирование credential manager в OS",
            "Backup всех user accounts в облако"
        ],
        correctAnswerIndex: 0,
        explanation: "Credential Stuffing: атакующий использует combo lists (email:password pairs) из breaches (Collection #1-5, RockYou). Automated tools: Sentry MBA, SNIPR. Users reuse passwords → success rate 0.1-2%. Defense: rate limiting, CAPTCHA, device fingerprinting, breach detection services (HaveIBeenPwned API), enforce unique passwords, monitor for anomalous login patterns.",
        link: {
            label: "OWASP: Credential Stuffing",
            url: "https://owasp.org/www-community/attacks/Credential_stuffing"
        }
    },
    {
        question: "Помогает ли 'Rate Limiting' от утечки данных?",
        answers: [
            "Да! Замедляет brute-force, credential stuffing, data scraping APIs, user enumeration — ограничивает скорость exfiltration даже при найденной уязвимости",
            "Нет, это только для защиты от DDoS",
            "Rate limiting влияет только на bandwidth",
            "Напрямую нет никакой выгоды",
            "Применимо только к GraphQL APIs",
            "Блокирует только IPv6 трафик",
            "Работает только на уровне CDN"
        ],
        correctAnswerIndex: 0,
        explanation: "Rate Limiting для Data Protection: 1) Login attempts: блокирует brute-force/stuffing (max 5/min per IP) 2) API calls: предотвращает scraping всей БД (1000 req/hour per user) 3) Password reset: блокирует user enumeration 4) Download: ограничивает mass exfiltration. Implementations: Token Bucket, Leaky Bucket, Fixed/Sliding Window.Tools: nginx limit_req, API Gateway.",
        link: {
            label: "OWASP: Rate Limiting",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое архитектура 'Zero Trust' Security Model?",
        answers: [
            "'Never trust, always verify' — каждый request (даже internal) требует authentication/authorization, нет implicit trust based на network location",
            "Нулевое доверие между разработчиками команды",
            "Отсутствие SSL/TLS сертификатов",
            "Zero-day уязвимости в системе",
            "Запрет использования любых паролей",
            "Отключение всех security механизмов",
            "Блокировка всех администраторов"
        ],
        correctAnswerIndex: 0,
        explanation: "Zero Trust Principles: 1) Verify explicitly (auth на every request) 2) Least privilege access 3) Assume breach (segment network, limit lateral movement) 4) Inspect/log all traffic 5) Device compliance check. Implementations: Google BeyondCorp, Microsoft Zero Trust, NIST SP 800-207. No VPN trust, service-to-service mTLS, continuous verification.",
        link: {
            label: "NIST: Zero Trust Archi tecture",
            url: "https://www.nist.gov/publications/zero-trust-architecture"
        }
    },
    {
        question: "Опасно ли отправлять PII или sensitive data по email?",
        answers: [
            "Очень опасно! Email часто unencrypted in transit (SMTP), хранится на multiple servers, accessible to admins — используйте PGP/S/MIME или secure file sharing",
            "Нет проблем если тема письма пустая",
            "Gmail автоматически шифрует всё",
            "Безопасно при BCC вместо TO",
            "Email защищён если сервер HTTPS",
            "Нет риска для PDF attachments",
            "Корпоративный email server всегда безопасен"
        ],
        correctAnswerIndex: 0,
        explanation: "Email Security Issues: 1) SMTP often plaintext 2) Stored на sender/recipient/relay servers 3) Admin access 4) Backup tapes 5) Subpoenas/law enforcement. Solutions: PGP (end-to-end), S/MIME (certificates), secure portals (expire links), password-protected encrypted ZIPs (separate password channel). Never: SSN, credit cards, passwords в email body.",
        link: {
            label: "EFF: Email Self-Defense",
            url: "https://emailselfdefense.fsf.org/"
        }
    },
    {
        question: "Что такое правильная 'Redaction' (редактирование) в PDF файлах?",
        answers: [
            "Полное удаление sensitive содержимого из файла структуры — НЕ просто чёрный прямоугольник сверху (text остаётся underneath)",
            "Рисование черных квадратов поверх текста",
            "Смена шрифта на белый цвет",
            "Выделение текста жёлтым маркером",
            "Blur эффект через Photoshop",
            "Копирование без форматирования",
            "Конвертация  страниц в изображения"
        ],
        correctAnswerIndex: 0,
        explanation: "PDF Redaction Mistakes: просто overlaying black rectangles → original text в metadata/structure. Real cases: DOJ, CIA documents unredacted. Adobe Acrobat Pro: Redaction Tools (actually removes content). After redaction: 'Remove Hidden Information', PDF/A format. Alternative: screenshot → to image (loses text layer). Government: NARA guidelines для proper redaction.",
        link: {
            label: "Adobe: PDF Redaction",
            url: "https://helpx.adobe.com/acrobat/using/removing-sensitive-content-pdfs.html"
        }
    },
    {
        question: "Почему важна 'Data Classification' (классификация данных)?",
        answers: [
            "Определяет appropriate security controls (encryption, access, retention) based на sensitivity level — Public, Internal, Confidential, Restricted",
            "Алфавитная сортировка файлов в базе",
            "Категоризация по размеру файлов",
            "Группировка данных по дате создания",
            "Тегирование для поиска в системе",
            "Архивирование старых документов",
            "Colour coding папок в file explorer"
        ],
        correctAnswerIndex: 0,
        explanation: "Data Classification Levels: 1) **Public**: marketing materials (no controls) 2) **Internal**: employee directory (basic access control) 3) **Confidential**: financial reports (encryption, limited access) 4) **Restricted/Secret**: PII, trade secrets, PHI (strong encryption, audit logging, DLP, need-to-know). Apply appropriate controls per level, DLP policies enforce, training users.",
        link: {
            label: "NIST: Data Classification",
            url: "https://csrc.nist.gov/glossary/term/data_classification"
        }
    },
    {
        question: "Что раскрывает SNI (Server Name Indication) в TLS handshake?",
        answers: [
            "Hostname клиента в plaintext до шифрования connection — ISP/observer видит какой сайт посещается даже при HTTPS (example.com)",
            "Серийный номер SSL сертификата",
            "IP адрес DNS сервера пользователя",
            "Версию операционной системы клиента",
            "Список установленных browser extensions",
            "Cookie значения перед шифрованием",
            "Email адрес владельца домена"
        ],
        correctAnswerIndex: 0,
        explanation: "SNI Disclosure: TLS Client Hello содержит SNI extension в plaintext: `server_name: www.example.com`. Нужно для shared hosting (multiple SSL certs на 1 IP). Но: ISP/firewalls видят destination. ESNI (Encrypted SNI)/ECH (Encrypted Client Hello) в TLS 1.3: шифрует SNI. Privacy: SNI → DNS queries correlation → browsing history.",
        link: {
            label: "Cloudflare: Encrypted SNI",
            url: "https://blog.cloudflare.com/encrypted-sni/"
        }
    },
    {
        question: "Безопасно ли хранить API keys в client-side JavaScript code?",
        answers: [
            "Категорически нет! JS код виден всем через devtools/view-source — keys instantly compromised. Use backend proxy для API calls",
            "Да, если файл минифицирован и obfuscated",
            "Безопасно в production webpack builds",
            "Да, для public readonly API keys",
            "OK если код в IIFE wrapper",
            "Безопасно при использовании HTTPS",
            "Допустимо для React/Vue apps"
        ],
        correctAnswerIndex: 0,
        explanation: "Client-Side API Keys Risk: даже obfuscated/minified → reverse engineering trivial. View Source или Network tab → key visible. **Exceptions**: genuinely public read-only keys (Google Maps API key с domain restrictions). **Solution**: Backend-For-Frontend (BFF) pattern — client → your server → 3rd party API. Server validates user, makes API call, returns filtered data.",
        link: {
            label: "OWASP: API Security",
            url: "https://owasp.org/www-project-api-security/"
        }
    },
    {
        question: "Что такое 'Secrets Management' системы и зачем нужны?",
        answers: [
            "Централизованное secure хранение и access control для credentials/API keys/certificates с encryption, audit logs, rotation, versioning — HashiCorp Vault, AWS Secrets Manager",
            "Просто password manager типа LastPass",
            "Backup система для важных файлов",
            "Менеджер задач для команды разработки",
            "Version control system  для документов",
            "Encryption tool для жёстких дисков",
            "Monitor логов безопасности"
        ],
        correctAnswerIndex: 0,
        explanation: "Secrets Management: централизует secrets вместо scattered .env files. Features: 1) Encryption at rest/transit 2) Access control (who can read which secret) 3) Audit logging 4) Auto-rotation 5) Dynamic secrets (short-lived DB creds) 6) Versioning. Tools: HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager, CyberArk. Integration: apps pull secrets at runtime.",
        link: {
            label: "HashiCorp Vault",
            url: "https://www.vaultproject.io/"
        }
    },
    {
        question: "Опасно ли использовать outdated TLS versions (TLS 1.0, TLS 1.1)?",
        answers: [
            "Да! TLS 1.0/1.1 уязвимы к BEAST, POODLE, weak ciphers — PCI DSS禁止с 2018. Use TLS 1.2+ (preferably 1.3)",
            "Нет, все TLS версии одинаково безопасны",
            "Опасно только для финансовых сайтов",
            "TLS 1.0 быстрее и эффективнее",
            "Legacy browsers требуют старые версии",
            "Это только рекомендация, не требование",
            "TLS 1.1 is the sweet spot balance"
        ],
        correctAnswerIndex: 0,
        explanation: "TLS Version Security: TLS 1.0/1.1 deprecated (RFC 8996, 2021). Vulnerabilities: BEAST, weak MD5/SHA-1 support. TLS 1.2: minimum (AES-GCM required). TLS 1.3: best (faster handshake, only AEAD ciphers, perfect forward secrecy mandatory). Browser support: Chrome/Firefox dropped TLS 1.0/1.1 (2020). Check: SSL Labs, enforce server-side.",
        link: {
            label: "RFC 8996: TLS 1.0/1.1 Deprecation",
            url: "https://datatracker.ietf.org/doc/html/rfc8996"
        }
    },
    {
        question: "Что такое 'API Versioning' в контексте раскрытия информации?",
        answers: [
            "Exposed версия API в URL/headers (`/api/v1/`, `X-API-Version: 2.3.1`) — атакующий тестирует старые versions для known vulnerabilities, bypasses",
            "Простая нумерация релизов API",
            "Процесс обновления API endpoints",
            "Changelog documentation для разработчиков",
            "Контрактная версионность с clients",
            "Git tagging для API codebase",
            "Semantic versioning scheme (SemVer)"
        ],
        correctAnswerIndex: 0,
        explanation: "API Versioning Security: `/api/v1/users`, `/api/v2/users` — старые versions часто: unmaintained, missing security patches, easier to exploit. Атакующий: tries v1 когда v2 patched. Best practices: deprecate old versions promptly, redirect to latest, authentication на all versions, monitor usage, sunset policy. Don't: expose internal version numbers в errors.",
        link: {
            label: "OWASP: API Versioning",
            url: "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
        }
    },
    {
        question: "Чем опасна 'Subdomain Enumeration' для безопасности?",
        answers: [
            "Обнаруживает forgotten/dev/staging subdomains с weak security (dev.example.com, backup.example.com) — часто содержат sensitive data или vulnerabilities",
            "Простое перечисление всех поддоменов",
            "Это улучшает SEO ranking сайта",
            "Помогает в DNS  load balancing",
            "Ускоряет CDN content delivery",
            "Организует структуру веб-приложения",
            "Необходимо для SSL wildcard certificates"
        ],
        correctAnswerIndex: 0,
        explanation: "Subdomain Enum Attack: tools (Sublist3r, Amass, DNS brute-force) находят: staging.example.com (production data), admin-panel.example.com, dev-api.example.com, старые forgotten subdomains. Risks: unpatched software, exposed credentials, development debug modes, backups. Defense: proper DNS management, decommission unused subdomains, same security standards для all subdomains.",
        link: {
            label: "Subdomain Enumeration Tools",
            url: "https://github.com/projectdiscovery/subfinder"
        }
    },
    {
        question: "Что такое 'HTTP Security Headers' и как они защищают данные?",
        answers: [
            "Response headers инструктируют browser behavior: HSTS (force HTTPS), CSP (block XSS), X-Frame-Options (clickjacking), etc. — prevent data leakage/injection",
            "Headers для ускорения HTTP requests",
            "Информация о версии web server",
            "Cookies и session management data",
            "Compression settings для content",
            "Cache control instructions only",
            "SEO metadata для поисковиков"
        ],
        correctAnswerIndex: 0,
        explanation: "Security Headers: 1) HSTS (force HTTPS) 2) CSP (Content-Security-Policy): blocks inline scripts/XSS 3) X-Frame-Options: prevents clickjacking 4) X-Content-Type-Options: nosniff (MIME sniffing attacks) 5) Referrer-Policy: controls Referer header 6) Permissions-Policy: limits browser features. Check: securityheaders.com. Configure web server (nginx, Apache) или app framework.",
        link: {
            label: "Security Headers",
            url: "https://securityheaders.com/"
        }
    },
    {
        question: "Почему важно sanitize filenames при file uploads?",
        answers: [
            "Malicious filenames могут content path traversal (`../../etc/passwd`), command injection (`; rm -rf /`), XSS в file listings — validate/whitelist characters",
            "Для правильной alphabetical сортировки",
            "Чтобы файлы помещались на диск",
            "Для совместимости с Windows/Linux",
            "Улучшения скорости поиска файлов",
            "Экономии места в базе данных",
            "Красивого отображения в UI"
        ],
        correctAnswerIndex: 0,
        explanation: "Filename Attacks: 1) Path Traversal: upload `../../etc/passwd` или `..\\..\\windows\\system32\\config\\sam` 2) Command Injection: `file; whoami.jpg` 3) XSS: `<img src=x onerror=alert(1)>.jpg` в directory listing. Defense: rename uploaded files (UUID), whitelist chars ([a-zA-Z0-9_.-]), validate extension, store outside webroot, serve через controlled endpoint.",
        link: {
            label: "OWASP: File Upload",
            url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        }
    },
    {
        question: "Что такое 'Information Disclosure via Error Messages' в APIs?",
        answers: [
            "Detailed error responses раскрывают DB schema, internal paths, library versions, business logic — generic errors для production, details только в logs",
            "Ошибки которые помогают debugging",
            "User-friendly сообщения об ошибках",
            "HTTP status codes 4xx и 5xx",
            "Exception stack traces для разработчиков",
            "Валидация сообщения для forms",
            "Локализованные тексты ошибок"
        ],
        correctAnswerIndex: 0,
        explanation: "API Error Disclosure: Bad: `{\"error\": \"Column 'api_key' doesn't exist in table 'users'\"}`, `ValueError at /app/models/user.py line 42`. Good: `{\"error\": \"Invalid request\", \"code\": \"ERR_001\"}`. Logs: full details server-side. Avoid: SQL errors, file paths, framework versions, internal IP addresses в responses. Use generic messages + unique error codes для support.",
        link: {
            label: "CWE-209: Error Message Disclosure",
            url: "https://cwe.mitre.org/data/definitions/209.html"
        }
    },
    {
        question: "Безопасно ли использовать HTTP Referer header для security decisions?",
        answers: [
            "Нет! Referer spoofable, browser extensions могут remove, users за proxy/VPN могут strip — never trust для authorization, only advisory analytics",
            "Да, Referer полностью надёжен",
            "Безопасно только для HTTPS сайтов",
            "Referer является криптографической защитой",
            "Да, если combined с CORS headers",
            "Идеален для CSRF protection",
            "Browser всегда отправляет correct Referer"
        ],
        correctAnswerIndex: 0,
        explanation: "Referer Header Risks: 1) User spoofing (Burp, curl) 2) Privacy extensions remove 3) HTTPS→HTTP transition strips 4) `Referrer-Policy: no-referrer`. Never use для: authentication, CSRF protection (use CSRF tokens), access control. OK for: analytics, logging referral source. Leaks URL params: решение `Referrer-Policy: strict-origin`.",
        link: {
            label: "MDN: Referer Header",
            url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer"
        }
    },
    {
        question: "Что такое 'Secrets Scanning' in CI/CD pipelines?",
        answers: [
            "Automated analysis кода/commits на наличие credentials perед deployment — fails build если secrets detected, prevents accidental exposure",
            "Поиск bugs в production коде",
            "Testing API endpoints автоматически",
            "Code coverage analysis для тестов",
            "Lint checking для code style",
            "Performance profiling applications",
            "Dependency vulnerability scanning"
        ],
        correctAnswerIndex: 0,
        explanation: "Secrets Scanning Tools: Trufflehog, GitLeaks, git-secrets, GitHub Advanced Security. CI/CD Integration: pre-commit hooks, pipeline step (fail on match). Regex patterns: AWS keys, GCP keys, private SSH keys, generic passwords. False positives: test fixtures → .secretsignore. Post-detection: rotate secrets immediately, investigate exposure scope.",
        link: {
            label: "GitHub: Secret Scanning",
            url: "https://docs.github.com/en/code-security/secret-scanning"
        }
    },
    {
        question: "Чем опасен 'Improper Certificate Validation' в mobile apps?",
        answers: [
            "App принимает invalid/self-signed/any certificates — позволяет Man-in-the-Middle перехватить HTTPS трафик, читать sensitive data/inject responses",
            "Замедляет SSL handshake process",
            "Увеличивает размер app bundle",
            "Сертификаты занимают много памяти",
            "Визуальное предупреждение в UI",
            "Блокирует работу на старых Android",
            "Несовместимость с iOS certificates"
        ],
        correctAnswerIndex: 0,
        explanation: "Certificate Validation Bypass: apps игнорируют certificate errors для \"convenience\" (dev testing). Real attack: corporate MitM proxy, coffee shop WiFi с fake certificate. Malicious devs: TrustManager accepts all. Defense: certificate pinning, proper validation, test with Charles Proxy/mitmproxy, Android Network Security Config, iOS App Transport Security.",
        link: {
            label: "OWASP: Certificate Pinning",
            url: "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"
        }
    },
    {
        question: "Что такое 'Data Retention Policy' и почему важна?",
        answers: [
            "Определяет как долго хранить данные и когда удалять — minimizes exposure window, GDPR compliance, reduces breach impact, legal/business requirements",
            "Backup стратегия для disaster recovery",
            "Performance optimization через archiving",
            "Compression алгоритм для старых data",
            "Migration plan к новой БД",
            "Репликация данных между серверами",
            "Changelog истории для аудита"
        ],
        correctAnswerIndex: 0,
        explanation: "Data Retention: 1) Legal requirements (tax records 7 years) 2) GDPR: delete when no longer needed, right to erasure 3) Security: less data = less breach exposure. Policy: classify data types, define retention periods, automated deletion, secure disposal (crypto erasure), logs retention (~90 days analytics, 1 year security). Document policy, train staff, regular audits.",
        link: {
            label: "GDPR: Data Retention",
            url: "https://gdpr-info.eu/issues/data-retention/"
        }
    },
    {
        question: "Опасно ли использовать 'Public Wi-Fi' без VPN для work tasks?",
        answers: [
            "Очень опасно! Public WiFi часто unencrypted или fake Evil Twin APs — MitM может intercept traffic, even HTTPS vulnerable до certain attacks (SSL strip, SNI)",
            "Безопасно если сайты используют HTTPS",
            "Нет риска в кафе Starbucks",
            "Public WiFi faster чем mobile data",
            "Airport WiFi полностью защищён",
            "WPA2 encryption достаточна",
            "HTTPS certificate автоматически защищает"
        ],
        correctAnswerIndex: 0,
        explanation: "Public WiFi Risks: 1) Packet sniffing (Wireshark, tcpdump) 2) Evil Twin AP (same SSID) 3) SSL stripping 4) Session hijacking 5) Malware injection. HTTPS helps but: SNI plaintext, metadata visible, possible SSL stripping. Defense: VPN (encrypts everything), avoid sensitive tasks, verify AP legitimacy, use mobile hotspot, HTTPS Everywhere extension.",
        link: {
            label: "EFF: Public WiFi Security",
            url: "https://ssd.eff.org/module/how-use-public-wi-fi-safely"
        }
    },
    {
        question: "Что такое 'Shadow IT' и какие риски для data security?",
        answers: [
            "IT systems/services используемые без approval IT department (личный Dropbox, Gmail для work, unapproved SaaS) — data leakage, no monitoring, compliance violations",
            "Тёмный режим интерфейса приложений",
            "Backup IT infrastructure для failover",
            "Второй комплект серверов для testing",
            "Скрытые функции в программах",
            "Black hat hackers в организации",
            "Unapproved overtime работа IT staff"
        ],
        correctAnswerIndex: 0,
        explanation: "Shadow IT Examples: employees use personal Dropbox, WhatsApp для work files, unapproved cloud apps. Risks: 1) Data outside corporate security 2) No DLP monitoring 3) Compliance violations (GDPR, HIPAA) 4) Lost visibility 5) Credential sharing. Solution: approved alternatives (corporate G Suite, Teams), education, CASB (Cloud Access Security Broker), monitoring network traffic.",
        link: {
            label: "Gartner: Shadow IT",
            url: "https://www.gartner.com/en/information-technology/glossary/shadow-it"
        }
    },
    {
        question: "Почему важна 'Secure  Software Development Lifecycle' (SSDLC)?",
        answers: [
            "Интегрирует security на каждом этапе разработки (threat modeling, secure coding, testing, deployment) — cheaper fix early, prevents vulnerabilities в production",
            "Процесс создания красивого UI design",
            "Agile/Scrum методология разработки",
            "Система контроля версий для кода",
            "Автоматизация deployment pipeline",
            "Performance optimization techniques",
            "Documentation generation workflow"
        ],
        correctAnswerIndex: 0,
        explanation: "SSDLC Phases: 1) **Requirements**: threat modeling, security requirements 2) **Design**: secure architecture, attack surface analysis 3) **Implementation**: secure coding standards, code review 4) **Testing**: SAST, DAST, penetration testing 5) **Deployment**: hardening, monitoring 6) **Maintenance**: patching, incident response. Frameworks: Microsoft SDL, OWASP SAMM, BSIMM. DevSecOps integrates security автоматически.",
        link: {
            label: "OWASP: SAMM",
            url: "https://owaspsamm.org/"
        }
    },
    {
        question: "Что делать при обнаружении exposed database backup в интернете?",
        answers: [
            "Немедленно: 1) Remove accessibility 2) Assess scope (what data, how long exposed) 3) Breach notification process 4) Rotate credentials 5) Forensics 6) Prevent recurrence",
            "Просто удалить файл и забыть",
            "Скачать копию для анализа home",
            "Отправить email всем users",
            "Выключить весь production",
            "Blame responsible employee publicly",
            "Wait and see если кто-то найдёт"
        ],
        correctAnswerIndex: 0,
        explanation: "Exposed Backup Response: 1) **Immediate**: block access (S3 policy, firewall) 2) **Assess**: what data, PII count, duration exposed, who accessed (logs) 3) **Notify** : GDPR 72h, affected users, management 4) **Remediate**: rotate DB creds, API keys, investigate how it happened 5) **Prevent**: automated scanning (S3Scanner), bucket policies, principle of least privilege, security training.",
        link: {
            label: "GDPR: Breach Response",
            url: "https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/personal-data-breaches/"
        }
    },
    {
        question: "Что такое 'Container Security Scanning' и зачем нужен?",
        answers: [
            "Анализ Docker images на vulnerabilities в base OS/packages, secrets в layers, misconfigurations — prevents deploying insecure containers to production",
            "Физическая проверка shipping containers",
            "Testing производительности контейнеров",
            "Мониторинг использования ресурсов",
            "Optimization размера Docker images",
            "Network connectivity testing",
            "Load balancing между контейнерами"
        ],
        correctAnswerIndex: 0,
        explanation: "Container Scanning: tools (Trivy, Clair, Snyk, Anchore) находят: 1) OS vulnerabilities (outdated packages) 2) Application dependencies CVEs 3) Secrets в layers (passwords, keys) 4) Misconfigurations (running as root). CI/CD integration: scan на build, fail при high severity. Best: minimal base images (Alpine, distroless), regular updates, multi-stage builds, .dockerignore secrets.",
        link: {
            label: "Trivy Security Scanner",
            url: "https://github.com/aquasecurity/trivy"
        }
    },
    {
        question: "Каковы риски использования 'Third-Party Libraries' с vulnerabilities?",
        answers: [
            "Known CVEs в dependencies дают attackers easy entry point — Log4Shell (2021), Heartbleed (2014) affects millions. Regular updates + SCA tools essential",
            "Библиотеки just замедляют приложение",
            "Лицензионные проблемы с open source",
            "Увеличение размера bundle application",
            "Конфликты между versions dependencies",
            "Сложность в maintenance codebase",
            "Документация often outdated"
        ],
        correctAnswerIndex: 0,
        explanation: "Supply Chain Attacks: Equifax breach (Apache Struts CVE-2017-5638), Log4Shell (log4j CVE-2021-44228) affected millions globally. SCA (Software Composition Analysis): Snyk, Dependabot, OWASP Dependency-Check. Automated alerts for CVEs. Best practices: minimize dependencies, pin versions, private registry, verify checksums, rapid patching process, SBOM (Software Bill of Materials).",
        link: {
            label: "OWASP: Dependency Check",
            url: "https://owasp.org/www-project-dependency-check/"
        }
    }
];
