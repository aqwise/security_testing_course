export const quizQuestions = [
    {
        question: "1. Что такое SSRF?",
        answers: [
            "Server-Side Request Forgery — подделка запроса со стороны сервера",
            "Client-Side Request Forgery — подделка запроса со стороны клиента",
            "Secure Socket Request Framework",
            "Simple Server Request Format"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "2. В чем основное отличие SSRF от CSRF?",
        answers: [
            "В SSRF жертвой является сервер, который заставляют делать запросы. В CSRF жертва — клиент (браузер)",
            "SSRF это атака на базу данных",
            "CSRF это атака на сервер",
            "Ничем, это одно и то же"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "3. Какой IP адрес в AWS (и других облаках) часто является целью SSRF атак для получения метаданных?",
        answers: [
            "127.0.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "8.8.8.8"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "4. Что такое Blind SSRF?",
        answers: [
            "Когда сервер возвращает содержимое запрошенного ресурса пользователю",
            "Когда сервер выполняет запрос, но не возвращает тело ответа. Атакующий может судить об успехе только по косвенным признакам (время ответа, DNS запрос)",
            "Когда сервер не имеет доступа в интернет",
            "Это атака на слепых пользователей"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "5. Какой из этих протоколов (кроме HTTP) часто используется в SSRF для чтения локальных файлов?",
        answers: [
            "ftp://",
            "file://",
            "mailto:",
            "tel:"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "6. Какой протокол позволяет отправлять произвольные байты (например, для взаимодействия с Redis/Memcached) при SSRF?",
        answers: [
            "http://",
            "gopher://",
            "https://",
            "file://"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "7. Чем SSRF отличается от RFI (Remote File Inclusion)?",
        answers: [
            "RFI внедряет и исполняет код (обычно PHP) с удаленного сервера. SSRF заставляет сервер сделать запрос (прочитать данные или дернуть API)",
            "Это одно и то же",
            "RFI работает только локально",
            "SSRF всегда приводит к RCE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "8. Как можно обойти фильтр, запрещающий `127.0.0.1`?",
        answers: [
            "Использовать `localhost`",
            "Использовать `2130706433` (Decimal IP) или `0x7f000001` (Hex IP)",
            "Использовать `google.com`",
            "Никак"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "9. Что такое DNS Rebinding в контексте SSRF?",
        answers: [
            "Перезагрузка DNS сервера",
            "Техника обхода проверки IP, когда домен атакующего сначала резолвится в разрешенный IP (для проверки), а при втором запросе (уже для подключения) быстро меняется на внутренний IP (например, 127.0.0.1)",
            "Настройка DNS записей",
            "Блокировка DNS"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "10. Какой параметр URL чаще всего указывает на потенциальную SSRF?",
        answers: [
            "id",
            "page",
            "url / webhook / proxy / callback",
            "sort"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "11. Можно ли использовать SSRF для сканирования портов внутренней сети?",
        answers: [
            "Нет, это невозможно",
            "Да, по скорости ответа или ошибкам сервера можно определить, открыт порт или закрыт",
            "Только порт 80",
            "Только если есть права админа"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "12. Как защититься от SSRF на сетевом уровне?",
        answers: [
            "Запретить серверу любые исходящие соединения во внутреннюю сеть (кроме необходимых) через Firewall",
            "Отключить интернет",
            "Использовать HTTPS",
            "Сменить IP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "13. Почему валидация ввода по черным спискам (blacklist) часто неэффективна против SSRF?",
        answers: [
            "Хакеры не знают IP адресов",
            "Существует слишком много способов записать один и тот же IP адрес (IPv6, Octal, Hex, Enclosed Alphanumerics), что делает черные списки неполными",
            "Она замедляет сайт",
            "Она работает идеально"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "14. Что такое 'OAST' (Out-of-band Application Security Testing)?",
        answers: [
            "Тестирование на проде",
            "Техника обнаружения (в т.ч. Blind SSRF), когда уязвимый сервер заставляют отправить запрос на внешний контролируемый сервер (Burp Collaborator, webhook.site)",
            "Сканирование кода",
            "Аудит безопасности"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "15. Какой IP адрес соответствует `0` в Linux системах (и часто работает как байпас для localhost)?",
        answers: [
            "0.0.0.0",
            "255.255.255.255",
            "192.168.1.1",
            "10.0.0.1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "16. Что может сделать атакующий, если получит доступ к 169.254.169.254 на AWS?",
        answers: [
            "Ничего",
            "Получить временные ключи доступа (Access Keys) IAM роли, привязанной к инстансу, и захватить облачную инфраструктуру",
            "Перезагрузить сервер",
            "Изменить дизайн сайта"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "17. Что такое 'IPv6 Loopback'?",
        answers: [
            "::1",
            "127.0.0.1",
            "FE80::1",
            "2001::1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "18. Может ли перенаправление (HTTP Redirect) использоваться для обхода фильтров SSRF?",
        answers: [
            "Нет, серверы не следуют редиректам",
            "Да, если приложение проверяет исходный URL, но затем следует по редиректу на запрещенный ресурс (например, с подконтрольного хакеру домена на 127.0.0.1)",
            "Только для картинок",
            "Редиректы безопасны"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "19. Какой заголовок может помочь защититься от SSRF при запросах метаданных в AWS (IMDSv2)?",
        answers: [
            "X-Aws-Ec2-Metadata-Token",
            "Authorization",
            "Cookie",
            "User-Agent"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "20. Что такое 'Whitelist' подход в защите от SSRF?",
        answers: [
            "Разрешать все, кроме плохого",
            "Разрешать запросы ТОЛЬКО к заранее определенному списку доменов или IP адресов",
            "Использовать белый фон",
            "Писать код чисто"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "21. Можно ли эксплуатировать SSRF через PDF генераторы?",
        answers: [
            "Нет",
            "Да, если генератор поддерживает HTML теги, можно вставить iframe или img pointing to internal resources (также XSS/LFI)",
            "Только в Word",
            "PDF безопасен"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "22. Какой символ 'Enclosed Alphanumeric' может интерпретироваться как 'a' и 't' для обхода фильтров?",
        answers: [
            "ⓐ и ⓣ",
            "@ и +",
            "1 и 7",
            "А и Т (кириллица)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "23. Что такое 'CRLF Injection' в контексте SSRF?",
        answers: [
            "Внедрение перевода строки в URL для манипуляции заголовками HTTP запроса (например, для инъекции команд в Redis через HTTP протокол)",
            "Удаление файлов",
            "Форматирование текста",
            "Ошибка компиляции"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "24. Опасен ли `dict://` протокол при SSRF?",
        answers: [
            "Нет, это словарь",
            "Да, он позволяет отправлять произвольные команды (аналогично gopher), часто используется для атак на Memcached/Redis",
            "Только для перевода слов",
            "Нет, он устарел"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "25. Как 'Octal IP' адрес выглядит для 127.0.0.1?",
        answers: [
            "0177.0.0.1",
            "127.1",
            "0x7f000001",
            "100.100.100"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "26. Является ли SSRF уязвимостью из OWASP Top 10?",
        answers: [
            "Да (A10:2021)",
            "Нет, это редкость",
            "Только в 2013 году",
            "Нет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "27. Почему библиотека `curl` иногда опасна в контексте SSRF?",
        answers: [
            "Она поддерживает множество протоколов (gopher, telnet, file, ldap) по умолчанию, если их явно не отключить",
            "Она медленная",
            "Она пишет логи",
            "Она с открытым кодом"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "28. Как можно предотвратить DNS Rebinding?",
        answers: [
            "Запретить DNS",
            "Кэшировать DNS ответ и использовать полученный IP для проверки и последующего подключения (не делать повторный резолв)",
            "Использовать быстрый DNS",
            "Менять IP каждую минуту"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "29. Можно ли прочитать `/etc/passwd` через SSRF?",
        answers: [
            "Да, используя схему file:// (если она поддерживается библиотекой)",
            "Нет, это только LFI",
            "Только в Windows",
            "Нет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "30. Что такое 'Shortened URL' в контексте обхода SSRF?",
        answers: [
            "Использование сервисов сокращения ссылок (bit.ly) для маскировки целевого адреса (редирект)",
            "Короткий IP",
            "Сжатие трафика",
            "Хеширование"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "31. Какой адрес в диапазоне `127.0.0.0/8` указывает на локалхост?",
        answers: [
            "Только 127.0.0.1",
            "Любой адрес, начинающийся на 127 (например, 127.1.2.3)",
            "127.255.255.255",
            "Только 127.0.0.0"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "32. Что будет, если смешать IPv4 и Octal запись (например `127.1`)?",
        answers: [
            "Ошибка синтаксиса",
            "Сработает как 127.0.0.1 (браузеры и многие библиотеки это понимают)",
            "Ничего",
            "Откроется Google"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "33. Зачем использовать свой DNS сервер при атаке Blind SSRF?",
        answers: [
            "Чтобы ускорить атаку",
            "Чтобы получить подтверждение, что уязвимый сервер попытался разрешить имя вашего домена (даже если HTTP запрос заблокирован)",
            "Чтобы скрыть свой IP",
            "Для майнинга"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "34. Влияет ли настройка `allow_url_fopen` в PHP на SSRF?",
        answers: [
            "Нет",
            "Да, она разрешает использование URL в функциях работы с файлами, что повышает риск SSRF/RFI",
            "Только на картинки",
            "Это настройка БД"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "35. Как защитить внутренние админки от SSRF?",
        answers: [
            "Сделать красивый дизайн",
            "Требовать аутентификацию (пароль), даже при доступе с localhost, и использовать сетевую сегментацию",
            "Назвать их 'secret'",
            "Скрыть ссылки"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "36. Может ли Webhook функционал быть уязвим к SSRF?",
        answers: [
            "Нет, это фича",
            "Да, так как пользователь задает URL, на который сервер должен отправить запрос. Нужно строго фильтровать назначение",
            "Только в Telegram",
            "Webhook безопасен"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "37. Что такое 'Time-of-Check to Time-of-Use' (TOCTOU) в SSRF?",
        answers: [
            "Ошибка времени",
            "Состояние гонки, похожее на DNS Rebinding: проверка IP проходит, но в момент использования IP меняется",
            "Время проверки пароля",
            "Таймаут запроса"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "38. Какой инструмент в Burp Suite помогает генерировать пейлоады для обхода фильтров SSRF?",
        answers: [
            "Intruder + BChecks/Extensions",
            "Repeater",
            "Decoder",
            "Scanner"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "39. Нужно ли отключать неиспользуемые URL схемы (file, ftp, gopher) в библиотеках запросов?",
        answers: [
            "Нет, пусть будут",
            "Да, это важная часть Hardening для уменьшения импакта от SSRF",
            "Только FTP",
            "Это невозможно"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "40. Что такое 'Openstack Metadata' URL?",
        answers: [
            "169.254.169.254",
            "http://169.254.169.254/openstack",
            "localhost",
            "google.com"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "41. Может ли XML парсер привести к SSRF?",
        answers: [
            "Нет, это XXE",
            "Да, XXE часто используется как вектор для проведения SSRF атак (через внешние сущности http://...)",
            "Только для чтения файлов",
            "XML безопасен"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "42. Что делать, если приложению реально нужно скачивать картинки по URL пользователя?",
        answers: [
            "Разрешить все",
            "Использовать строгий парсинг URL, резолвить IP, сверять с whitelist/blacklist приватных диапазонов, и затем скачивать",
            "Использовать прокси",
            "Запретить картинки"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "43. Какие диапазоны IP считаются частными (Private) и должны быть заблокированы?",
        answers: [
            "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8",
            "8.8.8.8, 1.1.1.1",
            "Все IP",
            "Только 192.168.1.1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "44. Что такое 'Response Splitting' в SSRF?",
        answers: [
            "Разделение ответов для атаки через манипуляцию заголовками (связано с CRLF)",
            "Разрезание JSON",
            "Двойной ответ",
            "Ошибка сети"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "45. Опасен ли схематический URL `//google.com` (без протокола)?",
        answers: [
            "Нет",
            "Зависит от библиотеки, часто он наследует протокол текущего запроса или дефолтный",
            "Да, в некоторых случаях это может обойти простые регекспы, ожидающие `http` в начале",
            "Оба ответа 2 и 3 верны"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "46. Как атакующий может использовать SSRF против Redis?",
        answers: [
            "Чтобы украсть ключи",
            "Чтобы выполнить произвольные команды (RCE), например записать свою SSH public key в authorized_keys или создать cron job (через gopher или CRLF)",
            "Чтобы очистить кэш",
            "Чтобы ускорить базу"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "47. Поможет ли running app in container (Docker) защититься от SSRF impact?",
        answers: [
            "Полностью защитит",
            "Ограничит доступ к хостовой сети (если сеть изолирована), но атакующий все еще может атаковать другие контейнеры в той же сети",
            "Не поможет",
            "Docker уязвим сам по себе"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "48. Что такое 'Port Scanning' через SSRF?",
        answers: [
            "Поиск открытых портов путем перебора номеров портов в URL (http://localhost:1, :2...) и анализа ответов",
            "Сканирование принтером",
            "Проверка USB портов",
            "Анализ графиков"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "49. В каком месте HTTP запроса чаще всего встречается SSRF?",
        answers: [
            "Заголовки",
            "Тело (в полях, принимающих URL) или Query параметры",
            "Cookie",
            "User-Agent"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "50. Какой самый надежный способ полностью исключить SSRF?",
        answers: [
            "Не делать исходящих HTTP запросов от сервера на основе пользовательских данных (архитектурное решение)",
            "WAF",
            "RegExp",
            "Молитва"
        ],
        correctAnswerIndex: 0
    }
    ,
    {
        question: "51. Какой IP адрес используется для получения метаданных в Google Cloud Platform (GCP)?",
        answers: [
            "169.254.169.254",
            "127.0.0.1",
            "Metadata.google.internal",
            "Все перечисленное (IP и DNS имя)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "52. Какой заголовок обязателен для запросов к метаданным GCP (для защиты от SSRF)?",
        answers: [
            "Metadata-Flavor: Google",
            "X-Google-Metadata: True",
            "Authorization: Bearer",
            "Cookie: admin"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "53. Как атакующий может использовать FFmpeg для SSRF?",
        answers: [
            "Через HLS плейлисты (#EXTM3U), указывающие на внутренние ресурсы, или через поддельные AVI файлы",
            "Через переполнение буфера",
            "Только для видео карт",
            "FFmpeg безопасен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "54. Что такое 'Oracle Cloud Metadata' путь?",
        answers: [
            "/opc/v1/instance/",
            "/meta-data/",
            "/latest/meta-data/",
            "/oracle/metadata"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "55. Как защититься от атаки через DNS Pinning (Rebinding)?",
        answers: [
            "Использовать TLL 0",
            "Проверять IP адрес после резолва и использовать этот же IP для соединения (а не доменное имя)",
            "Запретить UDP",
            "Использовать hosts файл"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "56. Можно ли атаковать Memcached через SSRF?",
        answers: [
            "Да, используя gopher или CRLF инъекции через HTTP (Memcached текстовый протокол)",
            "Нет, это бинарный протокол",
            "Только через HTTPS",
            "Только если он на порту 80"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "57. Какой символ можно использовать в конце домена `google.com.`, чтобы обойти некоторые фильтры?",
        answers: [
            "Точка (.)",
            "Запятая (,)",
            "Слэш (/)",
            "Пробел"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "58. Что такое 'Kubernetes SSRF'?",
        answers: [
            "Доступ к Kubelet API (обычно порт 10250) или серверу метрик пода для захвата токенов или RCE в кластере",
            "Атака на докер файл",
            "Удаление подов",
            "Смена неймспейса"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "59. Как работает 'Mixed Case' bypass?",
        answers: [
            "Запись `LocalHost` вместо `localhost` (если фильтр регистрозависимый, а резолвер нет)",
            "Смешивание языков",
            "Смешивание цифр и букв",
            "Это не работает"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "60. Что такое 'Unicode Transformation' bypass?",
        answers: [
            "Использование символов, похожих на IP или домен (например, ⑯⑨.②⑤④...), которые нормализуются сервером в ASCII перед запросом",
            "Смена кодировки страницы",
            "Шифрование URL",
            "Сжатие Unicode"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "61. Можно ли использовать SSRF для доступа к локальному SMTP серверу?",
        answers: [
            "Да, для отправки спама или фишинга от имени доверенного сервера (через gopher или HTTPS CRLF)",
            "Нет, SMTP требует авторизацию",
            "Только для чтения писем",
            "SMTP закрыт фаерволом"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "62. Какой из этих URI является примером использования альтернативной схемы для bypass?",
        answers: [
            "attachment://",
            "myscheme://",
            "ldap://localhost:1337",
            "Всё вышеперечисленное (зависит от библиотек языка)"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "63. Чем опасен доступ к `http://localhost:9200` (Elasticsearch)?",
        answers: [
            "Утечка данных, удаление индексов, иногда RCE (через скриптинг)",
            "Ничем",
            "Только DoS",
            "Elasticsearch требует пароль всегда"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "64. Как 'Egress Filtering' помогает против SSRF?",
        answers: [
            "Блокирует исходящие соединения от сервера к интернету или во внутреннюю сеть, ограничивая возможности атакующего",
            "Фильтрует входящий трафик",
            "Очищает логи",
            "Ускоряет запросы"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "65. Можно ли использовать `0` вместо `127.0.0.1` в Windows?",
        answers: [
            "Нет, в Windows `0` или `0.0.0.0` обычно не работает как localhost в контексте connect()",
            "Да, всегда",
            "Только в PowerShell",
            "Зависит от версии"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "66. Что такое 'URL Parser Confusion'?",
        answers: [
            "Когда библиотека парсинга URL (используемая для валидации) и библиотека http-клиента (используемая для запроса) по-разному интерпретируют один и тот же URL",
            "Ошибка в браузере",
            "Путаница в DNS",
            "Сбой сервера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "67. Как использовать '@' для обхода валидации?",
        answers: [
            "http://evil.com@safe.com (сервер пойдет на safe.com) - НЕВЕРНО, на самом деле наоборот: http://safe.com@evil.com пойдет на evil.com (как user:password@host)",
            "Использовать как разделитель",
            "Это email адрес",
            "Это не работает"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "68. Что такое 'DigitalOcean Metadata' URL?",
        answers: [
            "http://169.254.169.254/metadata/v1/",
            "http://digitalocean.com/meta",
            "http://localhost/do",
            "http://10.10.0.1"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "69. Опасен ли `jar://` протокол в Java?",
        answers: [
            "Да, позволяет открывать файлы внутри архивов, может использоваться для обхода ограничений и SSRF/LFI",
            "Нет",
            "Только для Android",
            "Только для .exe"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "70. Как защитить Azure VM от SSRF?",
        answers: [
            "Требовать заголовок `Metadata: true`",
            "Отключить сеть",
            "Использовать Linux",
            "Удалить VM"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "71. Что такое 'Blind SSRF with Shellshock'?",
        answers: [
            "Использование SSRF для доставки Shellshock пейлоада (через User-Agent или другие заголовки) во внутренний уязвимый сервис",
            "Атака на командную строку",
            "Шоковая терапия",
            "Взрыв сервера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "72. В чем разница между `http://1.1.1.1` и `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`?",
        answers: [
            "Многочисленные символы могут запутать парсер (Orange Tsai's presentation), заставляя валидатор видеть один хост, а клиент запрашивать другой",
            "Никакой",
            "Это просто длинная ссылка",
            "Это CSS селектор"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "73. Можно ли получить RCE через SSRF в Adminer (DB management)?",
        answers: [
            "Да, подключаясь к 'Rogue MySQL Server', который через LOAD DATA LOCAL INFILE читает файлы клиента (сервера Adminer)",
            "Нет, это SQLi",
            "Только если пароль слабый",
            "Adminer безопасен"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "74. Что такое 'Cidr block 100.64.0.0/10'?",
        answers: [
            "Carrier Grade NAT, часто используется во внутренних сетях провайдеров и облаков, может содержать интересные сервисы",
            "Публичные IP",
            "Это localhost",
            "Это мусорный диапазон"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "75. Как обнаружить SSRF через PDF Generation?",
        answers: [
            "Вставить `<iframe src='http://burpcollaborator'>` в HTML, который конвертируется в PDF",
            "По размеру файла",
            "По цвету текста",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "76. Какой порт обычно слушает Docker API (уязвимый для SSRF)?",
        answers: [
            "2375 (unencrypted) / 2376",
            "8080",
            "22",
            "3306"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "77. Можно ли использовать SSRF для DoS атаки?",
        answers: [
            "Да, заставляя сервер скачивать огромные файлы или делать бесконечные запросы (loop)",
            "Нет",
            "Только на клиенте",
            "Только в играх"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "78. Что такое 'Ffmpeg HLS' SSRF?",
        answers: [
            "Создание .m3u8 плейлиста, где сегменты - это локальные файлы или URL внутренних ресурсов",
            "Стриминг видео",
            "Кодирование звука",
            "Ошибка плеера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "79. Как использовать Wildcard DNS (xip.io, nip.io) для SSRF?",
        answers: [
            "Домены типа `127.0.0.1.nip.io` резолвятся в 127.0.0.1, обходя простые проверки на 'IP адрес'",
            "Для ускорения интернета",
            "Для шифрования",
            "Для красоты"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "80. Что такое 'Protocol Smuggling'?",
        answers: [
            "Передача команд одного протокола (Redis) внутри другого (HTTP) через уязвимости парсинга или инъекции",
            "Контрабанда протоколов",
            "Скрытие трафика",
            "Туннелирование VPN"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "81. Поможет ли `dns_get_record()` перед запросом?",
        answers: [
            "Да, чтобы проверить, куда указывает домен, но нужно помнить про TOCTOU (Race Condition)",
            "Нет",
            "Только для MX записей",
            "Это для почты"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "82. Можно ли атаковать локальный интерфейс MongoDB через SSRF?",
        answers: [
            "Да, через HTTP интерфейс (если включен, порт 28017) или бинарный протокол (сложнее)",
            "Нет, MongoDB это NoSQL",
            "Только если нет пароля",
            "MongoDB не имеет сети"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "83. Что такое 'Gopher' протокол простыми словами?",
        answers: [
            "Старый протокол, позволяющий отправлять сырые байты TCP, что идеально для эмуляции протоколов типа Redis/SMTP при SSRF",
            "Животное",
            "Протокол Google",
            "Шифрованный канал"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "84. Как отключить libcurl protocols?",
        answers: [
            "Использовать опцию `CURLOPT_PROTOCOLS` и оставить только HTTP/HTTPS",
            "Удалить curl",
            "Запретить интернет",
            "Оно само отключится"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "85. В чем риск использования 'Headless Browser' (Puppeteer/Selenium) на сервере?",
        answers: [
            "Если он открывает URL пользователя, это полноценный браузер во внутренней сети (XSS=SSRF, file:// доступ, доступ к Intranet)",
            "Он ест много памяти",
            "Он медленный",
            "Он без дисплея"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "86. Как обнаружить SSRF если нет OAST и нет вывода?",
        answers: [
            "По таймингам (Time-based): запрос к закрытому порту может отвалиться мгновенно (RST) или висеть (DROP), к открытому - среднее время",
            "Никак",
            "По звуку кулера",
            "Гаданием"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "87. Что такое 'Alibaba Cloud Metadata'?",
        answers: [
            "http://100.100.100.200/latest/meta-data/",
            "169.254.169.254",
            "alibaba.metadata",
            "aliyun.com"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "88. Можно ли через SSRF прочитать исходный код?",
        answers: [
            "Да, например, через `file:///var/www/html/index.php`",
            "Нет, PHP исполняется",
            "Только HTML",
            "Только CSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "89. Какой HTTP метод часто используется при SSRF?",
        answers: [
            "GET (наиболее часто), но POST/PUT тоже возможны (особенно в Webhooks)",
            "Только OPTIONS",
            "Только DELETE",
            "TRACE"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "90. Что делать с редиректами в HTTP клиенте?",
        answers: [
            "Отключать или строго контролировать (проверять каждый новый URL перед переходом)",
            "Разрешать всегда",
            "Использовать 301",
            "Использовать 302"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "91. Что такое 'XXE OOB' (Out of Band)?",
        answers: [
            "Вид XXE, использующий SSRF канал для вывода данных на сервер атакующего (когда нет прямого вывода в ответе)",
            "Обычная XML",
            "Локальная атака",
            "Ошибка парсера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "92. Как работает техника 'DNS Rebinding' с TTL?",
        answers: [
            "Атакующий ставит очень короткий TTL (0 или 1), чтобы заставить сервер снова запросить DNS при следующем обращении",
            "Ставит длинный TTL",
            "Удаляет TTL",
            "Шифрует TTL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "93. Можно ли защититься, проверяя только начало URL (`startsWith('http://site.com')`)?",
        answers: [
            "Нет, это обходится: `http://site.com.evil.com` или `http://site.com@evil.com`",
            "Да, это надежно",
            "Только в Java",
            "Только в Python"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "94. Что такое 'SNI Proxy'?",
        answers: [
            "Прокси, использующий Server Name Indication. Может скрыть реальный IP назначения.",
            "Прокси для игр",
            "Сетевой интерфейс",
            "Система навигации"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "95. Влияет ли IPv6 на фильтры SSRF?",
        answers: [
            "Да, многие фильтры забывают про IPv6 (`[::1]`), что позволяет обойти blacklist IPv4",
            "Нет, IPv6 не используется",
            "Только в 5G",
            "IPv6 безопаснее"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "96. Можно ли использовать SSRF для атаки на Active Directory?",
        answers: [
            "Да, если сервер Windows и поддерживает NTLM auth, можно релеить креды или атаковать внутренние сервисы",
            "Нет",
            "Только на Linux",
            "Только через принтер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "97. Что такое 'URL Encoding' bypass?",
        answers: [
            "Использование %2e вместо точки, %2f вместо слэша, или двойное кодирование для обхода WAF/Filter",
            "Кодирование видео",
            "Сжатие текста",
            "Шифр Цезаря"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "98. Как работает защита 'Network Segmentation'?",
        answers: [
            "DMZ (Demilitarized Zone) - веб-сервер находится в изолированной сети и физически не может подключиться к базе данных или внутренней админке напрямую",
            "Разделение кабелей",
            "Виртуальная реальность",
            "Разные Wi-Fi"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "99. Какой риск использования `file_get_contents($url)` в PHP?",
        answers: [
            "Полный SSRF (если $url контролируется), поддержка data://, php://, file://, http://",
            "Нет риска",
            "Только XSS",
            "Только SQLi"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "100. Можно ли использовать SSRF для майнинга криптовалют?",
        answers: [
            "Напрямую нет, но через RCE (полученный через SSRF) можно установить майнер",
            "Да, SSRF майнит сам",
            "Только биткоин",
            "Нет"
        ],
        correctAnswerIndex: 0
    }
];
