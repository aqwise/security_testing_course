export const quizQuestions = [
    {
        question: "Что такое XXE?",
        answers: [
            "XML External Entity — уязвимость атаки на XML парсеры",
            "XSS Cross Element",
            "Extreme XML Encoding",
            "XML Extension Engine"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой компонент отвечает за обработку внешних сущностей в XML?",
        answers: [
            "HTML парсер",
            "XML процессор/парсер",
            "JavaScript движок",
            "CSS рендерер"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Что позволяет сделать успешная XXE атака?",
        answers: [
            "Только изменить цвет фона",
            "Читать локальные файлы сервера, выполнять SSRF, DoS",
            "Внедрять SQL запросы напрямую",
            "Взламывать WiFi"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Как выглядит определение сущности (Entity) в DTD?",
        answers: [
            "<!ENTITY name 'value'>",
            "<DEFINE name='value'>",
            "{ entity: name, value: value }",
            "@entity name = value"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой URI схема часто используется для чтения файлов при XXE?",
        answers: [
            "file://",
            "read://",
            "local://",
            "fs://"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Billion Laughs' атака?",
        answers: [
            "DoS атака через рекурсивное расширение XML сущностей",
            "Атака смехом",
            "XSS атака с эмодзи",
            "Атака на логин"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Blind XXE?",
        answers: [
            "XXE, где вывод данных не возвращается в ответе приложения",
            "XXE, которое не видно в логах",
            "XXE, использующее невидимые символы",
            "XXE для слепых пользователей"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как можно извлечь данные при Blind XXE?",
        answers: [
            "Никак",
            "Через OOB (Out-of-Band) канал, например, DNS или HTTP запрос на сервер атакующего",
            "Только угадыванием",
            "Через SQL Injection"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Какой протокол в Java может использоваться для листинга директорий при XXE (в старых версиях)?",
        answers: [
            "netdoc://",
            "dir://",
            "ls://",
            "list://"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое DTD?",
        answers: [
            "Document Type Definition — определение структуры XML",
            "Data Transfer Definition",
            "Direct Text Display",
            "Document Text Description"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли выполнить XXE через SVG файл?",
        answers: [
            "Нет, SVG это картинка",
            "Да, SVG основан на XML и может содержать сущности",
            "Только если SVG анимированный",
            "Только в браузере IE"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Как называется внешняя сущность, которая ссылается на другой файл?",
        answers: [
            "External Entity",
            "Outer Entity",
            "File Entity",
            "Import Entity"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какое ключевое слово используется для объявления внешней сущности?",
        answers: [
            "SYSTEM",
            "EXTERNAL",
            "FILE",
            "IMPORT"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое Parameter Entities в DTD?",
        answers: [
            "Сущности, используемые только внутри DTD (начинаются с %)",
            "Сущности для передачи параметров URL",
            "Сущности для SQL запросов",
            "Сущности для CSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой формат данных безопаснее XML в плане XXE?",
        answers: [
            "JSON",
            "HTML4",
            "SGML",
            "Никакой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как отключить XXE в большинстве парсеров?",
        answers: [
            "Запретить обработку DTD и внешних сущностей (disallow-doctype-decl)",
            "Включить фаервол",
            "Использовать HTTPS",
            "Перезагрузить сервер"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли XXE привести к RCE (Remote Code Execution)?",
        answers: [
            "Никогда",
            "Да, в редких случаях (например, через php://expect в PHP модуле expect)",
            "Всегда",
            "Только на Windows"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Какой Content-Type обычно указывает на XML?",
        answers: [
            "application/xml или text/xml",
            "application/json",
            "text/plain",
            "image/jpeg"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли сменить Content-Type на application/xml и попытаться атаковать JSON эндпоинт?",
        answers: [
            "Нет",
            "Да, некоторые фреймворки могут переключить парсер на XML, если поддерживают его",
            "Всегда сработает",
            "Это сломает интернет"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Что такое XInclude?",
        answers: [
            "Механизм включения одного XML в другой, может использоваться для XXE",
            "Включение JavaScript",
            "Включение CSS",
            "Функция PHP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как выглядит атака через XInclude?",
        answers: [
            "<xi:include href='file:///etc/passwd'/>",
            "<include src='/etc/passwd'/>",
            "<import file='/etc/passwd'/>",
            "<require path='/etc/passwd'/>"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая утилита помогает эксплуатировать XXE OOB?",
        answers: [
            "Burp Collaborator",
            "Notepad",
            "Calculator",
            "Paint"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает CDATA в XML?",
        answers: [
            "Позволяет использовать символы, которые иначе интерпретировались бы как разметка",
            "Шифрует данные",
            "Сжимает данные",
            "Удаляет данные"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Зачем использовать CDATA при эксфильтрации файлов через XXE?",
        answers: [
            "Чтобы спецсимволы в файле (например <, >) не ломали XML структуру",
            "Для красоты",
            "Для скорости",
            "Это обязательно"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой протокол (wrapper) в PHP позволяет кодировать данные в Base64?",
        answers: [
            "php://filter/read=convert.base64-encode/resource=",
            "base64://",
            "encode://",
            "crypt://"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли XXE использоваться для SSRF?",
        answers: [
            "Да, заставляя сервер делать HTTP запросы к внутренним ресурсам",
            "Нет",
            "Только для внешних ресурсов",
            "Только для HTTPS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой риск несет SOAP сервис?",
        answers: [
            "SOAP основан на XML, поэтому потенциально уязвим к XXE",
            "Никакого",
            "SOAP устарел и безопасен",
            "SOAP это мыло"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Classic XXE'?",
        answers: [
            "Когда результат внедрения сущности виден в ответе сервера",
            "XXE через музыку",
            "XXE 90-х годов",
            "XXE без XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как определить, что сервер уязвим к Blind XXE?",
        answers: [
            "По DNS/HTTP запросу на ваш сервер-логгер (OOB)",
            "По ошибке 500",
            "По долгой загрузке",
            "По изменению цвета"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент автоматизации поиска уязвимостей ищет XXE?",
        answers: [
            "Burp Suite Scanner / OWASP ZAP",
            "Photoshop",
            "Excel",
            "Word"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли функция `libxml_disable_entity_loader(true)` в PHP защитой?",
        answers: [
            "Да, она отключает загрузку внешних сущностей (для старых версий PHP)",
            "Нет, она включает их",
            "Она удаляет PHP",
            "Она только для HTML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать XXE для сканирования портов внутренней сети?",
        answers: [
            "Да, через SSRF (меняя порт в URL)",
            "Нет",
            "Только 80 порт",
            "Только 443 порт"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'External DTD'?",
        answers: [
            "DTD схема, загружаемая из внешнего файла",
            "DTD для внешних пользователей",
            "DTD вне компьютера",
            "Не существует"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как атаковать, если внутренние сущности запрещены, но внешние DTD разрешены?",
        answers: [
            "Использовать OOB XXE через параметр entities в внешнем DTD",
            "Сдаться",
            "Использовать SQLi",
            "Использовать XSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой протокол позволяет листить файлы в Java приложениях (Oracle JDK)?",
        answers: [
            "gopher://",
            "netdoc:// (в старых версиях) или file:// (если директория)",
            "java://",
            "jar://"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Что делать, если WAF блокирует слово SYSTEM?",
        answers: [
            "Использовать PUBLIC идентификатор",
            "Использовать PRIVATE",
            "Использовать HIDDEN",
            "Использовать SECRET"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли XXE возникнуть при парсинге Excel файлов (.xlsx)?",
        answers: [
            "Да, так как .xlsx это ZIP архив с XML файлами внутри",
            "Нет, это бинарный формат",
            "Только в CSV",
            "Только в PDF"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как защитить .NET приложение от XXE?",
        answers: [
            "Установить XmlResolver в null или ProhibitDtd = true",
            "Удалить .NET",
            "Использовать C++",
            "Ничего не делать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `DocumentBuilderFactory.setExpandEntityReferences(false)` защитой в Java?",
        answers: [
            "Да, это одна из настроек для предотвращения XXE",
            "Нет",
            "Это для JSON",
            "Это для картинок"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Entity Expansion'?",
        answers: [
            "Процесс замены ссылки на сущность её значением",
            "Расширение файлов",
            "Увеличение сущности",
            "Добавление новых полей"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какая ошибка часто выдается при Billion Laughs атаке?",
        answers: [
            "Out of Memory / Stack Overflow",
            "404 Not Found",
            "403 Forbidden",
            "200 OK"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли эксплуатировать XXE через JSON API?",
        answers: [
            "Обычно нет, если только API не конвертирует JSON в XML внутри или не поддерживает XML content-type параллельно",
            "Да, всегда",
            "Нет, никогда",
            "JSON это XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Где находится файл `hosts` в Linux?",
        answers: [
            "/etc/hosts",
            "/var/hosts",
            "/bin/hosts",
            "/tmp/hosts"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Где находится файл `win.ini` в Windows?",
        answers: [
            "C:/windows/win.ini",
            "/etc/win.ini",
            "D:/win.ini",
            "/bin/win.ini"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'error-based XXE'?",
        answers: [
            "Получение содержимого файла через текст ошибки парсера (например, 'file not found: [содержимое]')",
            "XXE, которое всегда выдает ошибку",
            "Ошибочное XXE",
            "XXE без ошибок"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой символ используется для разыменования сущности?",
        answers: [
            "& (амперсанд)",
            "$ (доллар)",
            "# (решетка)",
            "@ (собака)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как завершается ссылка на сущность?",
        answers: [
            "; (точка с запятой)",
            ". (точка)",
            ": (двоеточие)",
            ", (запятая)"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое SAX парсер?",
        answers: [
            "Simple API for XML — событийный парсер",
            "Super Awesome XML",
            "Simple Ajax XML",
            "Standard API XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое DOM парсер?",
        answers: [
            "Document Object Model — загружает весь XML в память",
            "Direct Object Model",
            "Data Object Mode",
            "Disk Only Memory"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой парсер более уязвим к DoS (Billion Laughs)?",
        answers: [
            "DOM (так как строит дерево в памяти)",
            "SAX",
            "StAX",
            "Никакой"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли читать бинарные файлы через XXE?",
        answers: [
            "Сложно, они могут ломать парсер. Лучше использовать кодирование (base64) через PHP фильтры или CDATA",
            "Да, легко",
            "Нет, невозможно",
            "Только картинки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `expect://id` wrapper в PHP?",
        answers: [
            "Выполняет команду `id` в шелле (требует модуль expect)",
            "Ожидает ID",
            "Генерирует ID",
            "Проверяет ID"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли валидация по XSD схемой защитой от XXE?",
        answers: [
            "Нет, XSD проверяет структуру, но не обязательно отключает внешние сущности",
            "Да, полностью",
            "Только если XSD локальный",
            "XSD это вирус"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В каком разделе OWASP Top 10 (2017) находился XXE?",
        answers: [
            "A4:2017-XML External Entities (XXE)",
            "A1: Injection",
            "A7: XSS",
            "A10: Logging"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В каком разделе OWASP Top 10 (2021) находится XXE?",
        answers: [
            "A05:2021-Security Misconfiguration (включено туда)",
            "A03:2021-Injection",
            "Выделен отдельно",
            "Убран совсем"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое jar:// протокол?",
        answers: [
            "Java Archive — позволяет читать файлы из архивов, может использоваться в XXE",
            "Протокол для банок (jars)",
            "JavaScript Archive",
            "JSON Archive"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать XXE для атаки на NTLM (Windows)?",
        answers: [
            "Да, заставляя сервер обратиться к SMB шаре атакующего (через UNC путь)",
            "Нет",
            "Только на Linux",
            "Только через HTTP"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что вернет `<!ENTITY xxe SYSTEM 'file:///dev/random'>`?",
        answers: [
            "Бесконечный поток случайных данных (DoS атака)",
            "Ошибку",
            "Пустую строку",
            "IP адрес"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить слепой XXE, если исходящий трафик блокируется?",
        answers: [
            "По задержкам (Time-based), например, чтение большого файла или /dev/random",
            "Никак",
            "По ошибкам синтаксиса",
            "По цвету пикселей"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что безопаснее: `<!DOCTYPE html>` или `<!DOCTYPE foo>`?",
        answers: [
            "HTML5 doctype безопасен (не использует DTD). Пользовательские DOCTYPE потенциально опасны в XML",
            "Одинаково",
            "Foo безопаснее",
            "Ничего"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие библиотеки Python уязвимы к XXE (lxml vs defusedxml)?",
        answers: [
            "lxml уязвим по умолчанию. defusedxml — безопасная альтернатива",
            "Все безопасны",
            "Все уязвимы",
            "Python не работает с XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает `resolveEntity` в Java?",
        answers: [
            "Метод, который можно переопределить для безопасной обработки или блокировки сущностей",
            "Решает уравнения",
            "Удаляет сущности",
            "Создает сущности"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли получить RCE через XXE в PHP без `expect`?",
        answers: [
            "Возможно, при использовании wrapper'а `phar://` и наличии гаджетов десериализации",
            "Нет, никогда",
            "Всегда",
            "Только через `http://`"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Restricted Zones' в IE и как это связано с XXE?",
        answers: [
            "Настройки безопасности, влияющие на то, куда парсер может обращаться",
            "Зоны парковки",
            "Зоны DNS",
            "Никак"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой порт обычно сканируют при SSRF через XXE для доступа к метаданным облака?",
        answers: [
            "80 (http://169.254.169.254)",
            "21",
            "22",
            "445"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое RSS фид?",
        answers: [
            "Формат XML для новостей, часто вектор для XXE атак",
            "Скрипт",
            "Стиль",
            "База данных"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли внедрить XXE через PDF?",
        answers: [
            "Да, PDF может содержать XMP (XML Metadata Platform) или формы XFA",
            "Нет",
            "Только в Adobe Reader 5",
            "Только в Chrome"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как влияет `Content-Type: application/xml` на WAF?",
        answers: [
            "WAF может применять XML-специфичные сигнатуры. Если изменить на text/xml или другое, можно попробовать обойти WAF, если он смотрит только на заголовок",
            "WAF всегда блокирует XML",
            "WAF игнорирует XML",
            "WAF падает"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое XXE через локальный DTD?",
        answers: [
            "Техника использования существующего на сервере DTD файла для переопределения сущностей (полезно, если внешний доступ закрыт)",
            "Использование DTD с флешки",
            "Использование DTD из кэша",
            "Такого нет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Где часто лежат DTD файлы в Linux?",
        answers: [
            "/usr/share/yelp/dtd/docbookx.dtd (GNOME Yelp)",
            "/etc/dtd",
            "/var/dtd",
            "/home/dtd"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какие файлы конфигурации WEB-серверов используют XML?",
        answers: [
            "web.xml (Java), applicationContext.xml (Spring), web.config (.NET)",
            "httpd.conf",
            "nginx.conf",
            ".htaccess"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли редактировать XML файлы напрямую на сервере через XXE?",
        answers: [
            "Обычно нет, XXE это чтение/SSRF. Запись (в файл) невозможна без специфичных врапперов",
            "Да, всегда",
            "Да, через UPDATE",
            "Да, через INSERT"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Goldrake' в контексте XXE?",
        answers: [
            "Инструмент для эксплуатации XXE (или название техники)",
            "Вирус",
            "Золотой ключик",
            "Тип XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой тег в SVG позволяет выполнять скрипты (XSS)?",
        answers: [
            "<script>",
            "<execute>",
            "<run>",
            "<do>"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Влияет ли кодировка (UTF-16) на обнаружение XXE WAF-ом?",
        answers: [
            "Да, смена кодировки (например, на UTF-16BE) может скрыть пейлоад от простых WAF, но парсер его поймет",
            "Нет",
            "Только UTF-8 работает",
            "XML не поддерживает кодировки"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'OOB'?",
        answers: [
            "Out of Band",
            "Out of Box",
            "Object Oriented Basic",
            "Only One Byte"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой префикс протокола используется в XXE для доступа к данным SharePoint?",
        answers: [
            "sharepoint:// (если поддерживается кастомный хендлер)",
            "sp://",
            "ms-sp://",
            "Никакой"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "Можно ли использовать `gopher://` для отправки POST запроса через XXE SSRF?",
        answers: [
            "Да, gopher позволяет конструировать произвольные TCP пакеты, включая HTTP POST",
            "Нет",
            "Только GET",
            "Только HEAD"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить, поддерживает ли парсер внешние сущности, без DTD?",
        answers: [
            "Нельзя, внешние сущности объявляются в DTD (внутреннем или внешнем)",
            "Просто написать &test;",
            "Использовать магию",
            "Отправить пустой файл"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'Internal Entity'?",
        answers: [
            "Сущность, значение которой определено внутри самого DTD (строка)",
            "Сущность внутри сервера",
            "Локальная переменная",
            "Внутренний голос"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Безопасен ли `SimpleXML` в PHP по умолчанию (современные версии)?",
        answers: [
            "Да, начиная с libxml 2.9.0 загрузка внешних сущностей отключена по умолчанию",
            "Нет, всегда уязвим",
            "Зависит от погоды",
            "SimpleXML не парсит XML"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как включить внешние сущности в `DOMDocument` PHP?",
        answers: [
            "LIBXML_NOENT (парадокс, но эта константа ВКЛЮЧАЕТ замену сущностей)",
            "LIBXML_YESENT",
            "ENABLE_XXE",
            "XXE_ON"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что значит 'NOENT' в libxml?",
        answers: [
            "No Entity Nodes (заменить узлы сущностей их значениями)",
            "No Entities (запретить сущности)",
            "No Entry",
            "No Entertainment"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой стандарт определяет XML?",
        answers: [
            "W3C XML 1.0",
            "RFC 123",
            "ISO 9001",
            "ГОСТ"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Важен ли порядок атрибутов в XML?",
        answers: [
            "Нет, порядок атрибутов не имеет значения",
            "Да, строго важен",
            "Да, по алфавиту",
            "Да, по длине"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Важен ли порядок элементов в XML?",
        answers: [
            "Да, порядок элементов важен",
            "Нет",
            "Только для корневого",
            "Только для пустых"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое SOAP Action?",
        answers: [
            "HTTP заголовок, указывающий намерение SOAP запроса",
            "Действие с мылом",
            "Команда удаления",
            "URL"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли XXE быть в SAML токене?",
        answers: [
            "Да, SAML это XML (часто Base64 закодированный)",
            "Нет, SAML безопасен",
            "SAML это JSON",
            "SAML это бинарник"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как декодировать SAML токен для поиска XXE?",
        answers: [
            "Base64 Decode + Inflate (иногда)",
            "MD5",
            "SHA256",
            "Rot13"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое XML Bomb?",
        answers: [
            "То же, что и Billion Laughs Attack",
            "Вирус",
            "Взрывчатка",
            "Звуковой файл"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Сколько сущностей `lol` в классической `lol9` атаке?",
        answers: [
            "10 в степени 9 (теоретически при разворачивании)",
            "9",
            "100",
            "Миллион"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как предотвратить XML Bomb?",
        answers: [
            "Ограничить глубину парсинга и размер выделяемой памяти",
            "Использовать больше памяти",
            "Удалить XML",
            "Использовать быстрый процессор"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли `<!ENTITY % pay SYSTEM 'file:///etc/passwd'>` валидной атакой?",
        answers: [
            "Да (если разрешены внешние DTD), это Blind OOB пейлоад",
            "Нет, синтаксис неверен",
            "Только для Windows",
            "Это для XSS"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что возвращает `file:///` если указать директорию?",
        answers: [
            "Зависит от языка (Java может вернуть список файлов, другие ошибку Access Denied или Is a directory)",
            "Всегда список файлов",
            "Всегда ошибку",
            "Синий экран"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли с помощью XXE читать переменные окружения?",
        answers: [
            "Только если они доступны через файлы (например /proc/self/environ в Linux) или спец. протоколы",
            "Да, командой env",
            "Нет",
            "Только PATH"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой инструмент в Kali Linux специально для эксплуатации XXE?",
        answers: [
            "XXEinjector",
            "XMLmap (существует, но менее популярен sqlmap)",
            "Burp Suite (Pro)",
            "Все перечисленные"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "Что такое DTD Poisoning?",
        answers: [
            "Подмена DTD файла или использование кэш-отравления для внедрения зловредного DTD",
            "Отравление еды",
            "Вирус в DTD",
            "Удаление DTD"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Если сервер отвечает JSON, но принимает XML, это:",
        answers: [
            "Возможный вектор атаки (Content-Type spoofing)",
            "Ошибка сервера",
            "Нормально",
            "Нельзя атаковать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить валидность XML?",
        answers: [
            "С помощью валидатора (xmllint)",
            "Глазами",
            "В блокноте",
            "В Paint"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делает атрибут `standalone='yes'` в XML декларации?",
        answers: [
            "Указывает, что документ не зависит от внешних определений (DTD), но парсер может игнорировать это при атаке",
            "Запрещает сеть",
            "Включает режим одиночки",
            "Отключает интернет"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как можно использовать XXE для DoS?",
        answers: [
            "Billion Laughs или чтение /dev/random",
            "Удаление БД",
            "Форматирование диска",
            "Выключение сервера"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой код ответа HTTP обычно при DoS через XXE?",
        answers: [
            "500 Internal Server Error или Time Out",
            "200 OK",
            "404 Not Found",
            "302 Redirect"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Нужен ли `root` элемент в валидном XML?",
        answers: [
            "Да, обязательно один корневой элемент",
            "Нет",
            "Можно два",
            "Можно сколько угодно"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что значит 'Well-formed XML'?",
        answers: [
            "XML, соответствующий синтаксическим правилам (теги закрыты, вложенность соблюдена)",
            "XML с красивыми отступами",
            "XML без ошибок логики",
            "XML с DTD"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что значит 'Valid XML'?",
        answers: [
            "XML, который не только Well-formed, но и соответствует DTD/XSD схеме",
            "XML без вирусов",
            "XML с подписью",
            "XML на английском"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли использовать XXE, если сервер не возвращает ответ (Blind), но делает DNS запросы?",
        answers: [
            "Да, можно подтвердить уязвимость и эксфильтрировать данные через DNS поддомены",
            "Нет",
            "Только подтвердить",
            "Только эксфильтрировать"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой DNS тип запроса используется в DNS OOB?",
        answers: [
            "A или AAAA (при разрешении имени)",
            "TXT",
            "MX",
            "PTR"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что такое 'DTD Injections'?",
        answers: [
            "Внедрение в DTD структуру (манипуляция схемой)",
            "Вакцинация",
            "Лечение DTD",
            "Удаление DTD"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Является ли XXE вектором для атак на облачную инфраструктуру (AWS/GCP/Azure)?",
        answers: [
            "Да, очень критичным (доступ к Instance Metadata Service)",
            "Нет",
            "Только AWS",
            "Только Azure"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Какой URL для AWS метаданных?",
        answers: [
            "http://169.254.169.254/latest/meta-data/",
            "http://aws.meta",
            "http://metadata.aws",
            "http://127.0.0.1/aws"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Может ли XXE читать файлы, доступные только root пользователю?",
        answers: [
            "Да, если процесс веб-сервера запущен от root (что является плохой практикой)",
            "Нет, никогда",
            "Всегда",
            "Только в Windows"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Как проверить пользователя, от которого запущен XML парсер, через XXE?",
        answers: [
            "Прочитать /etc/passwd или /proc/self/status",
            "Командой whoami (если есть RCE)",
            "Спросить админа",
            "Посмотреть логи"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Что делать, если XML парсер экранирует `&`?",
        answers: [
            "Использовать кодирование (например, &#x26;), если контекст позволяет, или это значит защиты нет",
            "Сдаться",
            "Использовать %",
            "Использовать $"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "В каких файлах Office может быть XXE?",
        answers: [
            "docx, pptx, xlsx (в файлах [Content_Types].xml или workbook.xml внутри архива)",
            "doc (бинарный)",
            "txt",
            "rtf"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Можно ли XXE использовать для кражи NTLM хешей?",
        answers: [
            "Да, при запросе к SMB ресурсу",
            "Нет",
            "Только Kerberos",
            "Только пароли"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "XXE это серверная или клиентская уязвимость?",
        answers: [
            "Серверная (Server-Side), так как XML парсится на сервере (обычно)",
            "Клиентская",
            "Браузерная",
            "Сетевая"
        ],
        correctAnswerIndex: 0
    }
];
