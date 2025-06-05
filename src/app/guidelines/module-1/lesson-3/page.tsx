
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export default function Module1Lesson3Page() {
  return (
    <ContentPageLayout
      title="Урок 3: Расширение практики – OWASP Juice Shop"
      subtitle="Модуль I: Основы безопасности веб-приложений"
    >
      <P>
        После знакомства с классическими уязвимостями в DVWA, пришло время перейти к более современному и сложному приложению – OWASP Juice Shop. Этот урок посвящен развертыванию Juice Shop с помощью Docker, навигации по приложению, поиску его ключевого элемента – Score Board, и решению нескольких начальных заданий.
      </P>

      <H2>A. Знакомство с OWASP Juice Shop</H2>
      <P>
        OWASP Juice Shop – это современное, намеренно уязвимое веб-приложение, разработанное проектом OWASP (Open Worldwide Application Security Project). Оно написано с использованием JavaScript-стека технологий: Node.js на сервере, фреймворк Express, и Angular на клиенте.<sup>24</sup> Juice Shop идеально подходит для отработки навыков поиска и эксплуатации уязвимостей из списка OWASP Top 10, а также многих других, менее распространенных, но реальных проблем безопасности.<sup>24</sup>
      </P>
      
      <H3>Ключевые особенности OWASP Juice Shop:</H3>
      <Ul items={[
        <><strong>Современный стек технологий:</strong> В отличие от DVWA, Juice Shop имитирует архитектуру современных одностраничных приложений (SPA) с REST API, что делает его более реалистичной целью для тренировки.</>,
        <><strong>Геймификация:</strong> Процесс обучения построен в игровой форме. За успешное решение заданий (эксплуатацию уязвимостей) начисляются очки, прогресс отслеживается на специальной "Доске результатов" (Score Board). Приложение уведомляет пользователя о решенных задачах.<sup>24</sup></>,
        <><strong>Hacking Instructor:</strong> Для некоторых заданий доступен встроенный "Инструктор по взлому", который предоставляет пошаговые подсказки и руководства, что очень полезно для новичков.<sup>24</sup></>,
        <><strong>Разнообразие заданий:</strong> Juice Shop содержит большое количество заданий (более 100) с различными уровнями сложности, от очень простых (1 звезда) до экспертных (6 звезд).<sup>25</sup></>,
        <><strong>Открытый исходный код:</strong> Как и многие проекты OWASP, Juice Shop является опенсорсным, что позволяет изучать его код для лучшего понимания уязвимостей.</>,
      ]} />
      <P>Название "Juice Shop" (Магазин соков) имеет интересное происхождение. Немецкое слово "Saftladen", означающее "захудалое заведение" или "бесполезная контора", дословно переводится как "магазин соков".<sup>24</sup></P>
      <Card className="my-4 p-4 border-l-4 border-primary bg-primary/10">
        <P>
          Juice Shop представляет собой более реалистичную и сложную цель по сравнению с DVWA. Его современный технологический стек (JavaScript-фреймворки, REST API)<sup>24</sup> делает его отличным следующим шагом в обучении после освоения основ на DVWA. Элементы геймификации и наличие "Hacking Instructor"<sup>24</sup> значительно повышают вовлеченность и доступность для новичков, помогая преодолевать трудности при столкновении со сложными задачами и снижая фрустрацию.
        </P>
      </Card>

      <H2>B. Развертывание OWASP Juice Shop с использованием Docker</H2>
      <P>
        Как и DVWA, OWASP Juice Shop легко разворачивается с помощью Docker. Это самый простой и рекомендуемый способ начать работу с приложением.
      </P>
      <H3>Шаг 1: Установка Docker (если еще не установлен)</H3>
      <P>
        Если вы еще не установили Docker, вернитесь к Уроку 1 и следуйте инструкциям по установке Docker Desktop для вашей операционной системы.
      </P>
      <H3>Шаг 2: Загрузка официального образа OWASP Juice Shop</H3>
      <P>Откройте терминал (командную строку) и выполните следующую команду для загрузки последней версии образа Juice Shop из Docker Hub:</P>
      <CodeBlock language="bash" code="docker pull bkimminich/juice-shop" />
      <P>Эта команда загрузит официальный образ, поддерживаемый разработчиками Juice Shop.<sup>11</sup></P>

      <H3>Шаг 3: Запуск контейнера OWASP Juice Shop</H3>
      <P>После загрузки образа запустите контейнер следующей командой:</P>
      <CodeBlock language="bash" code="docker run --rm -d -p 3000:3000 bkimminich/juice-shop" />
      <P>Разберем команду:<sup>13</sup></P>
      <Ul items={[
        <><code>docker run</code>: команда для запуска нового контейнера.</>,
        <><code>--rm</code>: флаг, который указывает Docker автоматически удалить контейнер после его остановки.</>,
        <><code>-d</code>: запускает контейнер в фоновом (detached) режиме, то есть терминал не будет "занят" логами контейнера.</>,
        <><code>-p 3000:3000</code>: пробрасывает порт 3000 внутри контейнера (на этом порту работает Juice Shop) на порт 3000 вашей хост-машины.</>,
        <><code>bkimminich/juice-shop</code>: имя образа, из которого запускается контейнер.</>,
      ]} />

      <H3>Шаг 4: Доступ к OWASP Juice Shop</H3>
      <P>После успешного запуска контейнера:</P>
      <Ul items={[
        "Откройте ваш веб-браузер (рекомендуется использовать браузер, настроенный на работу с Burp Suite Proxy, как описано в Уроке 1).",
        <>В адресной строке введите: <Link href="http://localhost:3000" target="_blank" rel="noopener noreferrer" className={LinkStyle}>http://localhost:3000</Link></>
      ]} />
      <P>
        Вы должны увидеть главную страницу интернет-магазина соков. При первом запуске может появиться приветственный баннер или всплывающее окно с предложением помощи от Hacking Instructor.<sup>27</sup> Вы можете закрыть его или следовать его указаниям, если хотите.
      </P>
      <Card className="my-4 p-4 border-l-4 border-primary bg-primary/10">
        <P>
          Стандартизация развертывания через Docker<sup>11</sup> делает Juice Shop доступным на любой платформе с минимальными усилиями. Это полностью соответствует его цели быть широко используемым учебным инструментом, так как Docker устраняет проблемы совместимости и сложности ручной установки Node.js и всех зависимостей Juice Shop, особенно для пользователей, не знакомых с экосистемой Node.js.
        </P>
      </Card>

      <H2>C. Навигация по Juice Shop: Поиск Score Board</H2>
      <P>
        Одним из первых и самых важных заданий в Juice Shop является поиск Score Board (Доски результатов). Это не просто элемент интерфейса, а само по себе задание начального уровня сложности (обычно 1 звезда).<sup>25</sup> Score Board отслеживает ваш прогресс в решении заданий (взломе уязвимостей) и показывает полный список доступных челленджей с их сложностью и категориями.
      </P>
      <P><strong>Почему это важно?</strong> Без доступа к Score Board вы не сможете видеть, какие задания существуют, какие вы уже решили, и какие категории уязвимостей представлены в приложении.</P>
      
      <H3>Методы поиска Score Board (применяем навыки Разведки и Картирования из WAHH2):</H3>
      <P>Согласно официальному руководству "Pwning OWASP Juice Shop" и общему описанию проекта, Score Board "тщательно спрятан"<sup>28</sup> и на него нет прямой, очевидной ссылки в пользовательском интерфейсе приложения.<sup>28</sup> Это сделано намеренно, чтобы первое задание было связано с исследованием.</P>
      <P>Вот несколько подходов к поиску:</P>
      <Ul items={[
        <><strong>Угадывание URL (URL guessing):</strong>
          <P className="mb-1">Зная, что Score Board существует, можно попробовать угадать его URL-адрес. Распространенные пути для подобных страниц могут быть <code>/score-board</code>, <code>/scoreboard</code>, <code>/challenges</code>, <code>/results</code> и т.п..<sup>28</sup> Попробуйте ввести эти варианты в адресную строку после <code>http://localhost:3000</code>.</P>
        </>,
        <><strong>Анализ клиентского кода (HTML, JavaScript):</strong>
          <P className="mb-1">Современные веб-приложения, особенно SPA (Single Page Applications) как Juice Shop, активно используют JavaScript для навигации и отображения контента.</P>
          <Ul items={[
              "Откройте инструменты разработчика в вашем браузере (обычно клавиша F12).",
              "Исследуйте исходный HTML-код главной страницы.",
              "Просмотрите загруженные JavaScript-файлы (вкладка \"Sources\" или \"Debugger\" в инструментах разработчика). Ищите в коде ключевые слова, такие как \"score\", \"board\", \"challenge\", \"ctf\", \"route\", \"path\".",
              <>В одном из видео-разборов<sup>29</sup> упоминается, что ссылка на scoreboard может быть найдена в виде <code>routerLink</code> в коде Angular-компонентов.</>,
              <>В старом, но все еще релевантном по принципу, разборе<sup>30</sup> указывалось на поиск закомментированной ссылки в исходном коде главной страницы.</>
          ]} />
        </>,
        <><strong>Использование Hacking Instructor:</strong>
          <P className="mb-1">Если при первом запуске или в процессе навигации вы видите приветственный баннер или всплывающие подсказки с иконкой "🎓" (академическая шапочка), это Hacking Instructor. Он может предложить помощь в поиске Score Board.<sup>25</sup> Следуйте его инструкциям.</P>
        </>,
        <><strong>Просмотр HTTP-трафика в Burp Suite:</strong>
          <P className="mb-1">Хотя прямую ссылку может быть сложно найти, анализ HTTP-запросов и ответов в Burp Suite (вкладка Proxy -> HTTP history) при навигации по сайту может иногда выявить вызовы API или загрузку скриптов, которые содержат информацию о путях к различным компонентам приложения, включая Score Board.</P>
        </>
      ]} />

      <H3>Конкретный путь (наиболее вероятный):</H3>
      <P>Чаще всего Score Board в OWASP Juice Shop доступен по URL-адресу:</P>
      <CodeBlock code="http://localhost:3000/#/score-board" />
      <P>После того как вы успешно перейдете по правильному адресу, приложение поздравит вас с решением вашего первого задания – "Score Board".</P>
      <Card className="my-4 p-4 border-l-4 border-primary bg-primary/10">
        <P>
          Сам процесс поиска Score Board является отличным обучающим упражнением, знакомящим пользователя с методами начальной разведки и анализа клиентской части веб-приложения. Это не просто "найти страницу", а применить навыки анализа HTML/JS и угадывания URL, что является частью этапов "Картирование" и "Обнаружение" из методологии WAHH2. Наличие "Hacking Instructor"<sup>25</sup> для этого первого ключевого шага помогает предотвратить "застревание" новичка на самом старте и обеспечивает положительный первый опыт.
        </P>
      </Card>

      <H2>D. Практические упражнения: Решение 1-2 простых (1-звездочных) заданий из Juice Shop</H2>
      <P>
        После того как вы нашли Score Board, вы увидите список всех доступных заданий, отсортированных по сложности (количество звезд) и категориям. Давайте попробуем решить несколько заданий с рейтингом 1 звезда (⭐), чтобы освоиться.
      </P>

      <H3>Рекомендуемые 1-звездочные задания для начала (на основе<sup>25</sup>):</H3>
      <div className="space-y-6">
        <div>
          <H3>"Score Board" (Категория: Miscellaneous)</H3>
          <P><strong>Описание:</strong> Найти тщательно спрятанную страницу 'Score Board'.</P>
          <P>Это задание вы уже должны были решить, чтобы получить доступ к списку заданий.</P>
        </div>
        <div>
          <H3>"Bonus Payload" (Категория: XSS)</H3>
          <P><strong>Описание:</strong> Использовать специальную XSS-нагрузку (payload), чтобы отобразить встроенный контент. Точная нагрузка обычно указана в описании задания на Score Board или в подсказках Hacking Instructor. Согласно<sup>31</sup>, это:</P>
          <CodeBlock code='<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>' />
          <P><strong>Где пробовать:</strong> Поле поиска на главной странице Juice Shop – это классическое место для тестирования XSS-уязвимостей.<sup>30</sup></P>
          <P><strong>Действия:</strong></P>
          <Ul items={[
              "Скопируйте указанную выше XSS-нагрузку.",
              "Вставьте ее в поле поиска на главной странице Juice Shop.",
              "Нажмите Enter или кнопку поиска."
          ]} />
          <P><strong>Результат:</strong> Если уязвимость эксплуатируется, на странице должен появиться встроенный плеер SoundCloud. Juice Shop уведомит вас о решении задания.</P>
          <P><strong>Hacking Instructor:</strong> Для этого задания доступен Hacking Instructor (иконка "🎓" на Score Board рядом с названием задания).<sup>25</sup> Нажмите на нее для получения пошаговых инструкций.</P>
        </div>
        <div>
          <H3>"DOM XSS" (Категория: XSS)</H3>
          <P><strong>Описание:</strong> Выполнить атаку DOM-based Cross-Site Scripting, используя указанную нагрузку. Согласно<sup>31</sup> и<sup>32</sup>, это: <code>{'<iframe src="javascript:alert(\'xss\')">'}</code></P>
          <P><strong>Где пробовать:</strong> Снова поле поиска.</P>
          <P><strong>Действия:</strong></P>
          <Ul items={[
            <>Скопируйте нагрузку <code>{'<iframe src="javascript:alert(\'xss\')"></iframe>'}</code>.</>,
            "Вставьте ее в поле поиска на главной странице.",
            "Нажмите Enter или кнопку поиска."
          ]} />
          <P><strong>Результат:</strong> На странице должно появиться всплывающее окно JavaScript alert с текстом "xss". Задание будет отмечено как решенное.</P>
          <P><strong>Hacking Instructor:</strong> Для этого задания также доступен Hacking Instructor.<sup>25</sup></P>
        </div>
        <div>
          <H3>"Error Handling" (Категория: Error Handling)</H3>
          <P><strong>Описание:</strong> Спровоцировать ошибку в приложении, которая обрабатывается не очень корректно или неконсистентно.<sup>31</sup></P>
          <P><strong>Где пробовать:</strong> Различные поля ввода, параметры URL.</P>
          <P><strong>Действия (пример):</strong></P>
          <Ul items={[
            <>Попробуйте ввести специальные символы, такие как одинарная кавычка ('), двойная кавычка ("), или последовательности символов, характерные для SQL-инъекций (например, <code>' OR 1=1--</code>) в поле поиска или в других полях ввода на сайте.<sup>30</sup></>,
            "Манипулируйте параметрами в URL, добавляя некорректные значения."
          ]} />
          <P><strong>Результат:</strong> Появление нестандартной страницы ошибки, утечка информации о сервере или базе данных, или любое другое необычное поведение приложения, которое свидетельствует о плохой обработке ошибок.</P>
          <P><strong>Hacking Instructor:</strong> Проверьте наличие иконки "🎓".</P>
        </div>
      </div>
      <P className="mt-4">При выполнении этих заданий активно используйте Burp Suite (Proxy -> HTTP history) для наблюдения за тем, какие запросы отправляются на сервер и какие ответы приходят. Это поможет вам лучше понять, как ваши действия в браузере транслируются в HTTP-взаимодействия.</P>
      <Card className="my-4 p-4 border-l-4 border-primary bg-primary/10">
        <P>
          Решение даже самых простых задач в Juice Shop требует применения различных техник (XSS, анализ ошибок), что сразу погружает в практическую сторону веб-безопасности. Задания типа "Bonus Payload" и "DOM XSS"<sup>25</sup> требуют активного ввода вредоносных данных, а "Error Handling" – наблюдения за реакцией приложения на некорректный ввод, что соответствует этапам "Обнаружение" и "Эксплуатация" методологии WAHH2. Категории уязвимостей в Juice Shop<sup>25</sup> напрямую соотносятся с OWASP Top 10, что делает его идеальным инструментом для изучения наиболее распространенных и опасных веб-уязвимостей.
        </P>
      </Card>

      <H3>Таблица 4: OWASP Juice Shop – Примеры 1-звездочных заданий для новичков</H3>
      <div className="overflow-x-auto my-6">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Название задания</TableHead>
              <TableHead>Категория</TableHead>
              <TableHead>Краткое описание/Цель</TableHead>
              <TableHead>Основная подсказка/Место для атаки</TableHead>
              <TableHead>Наличие Hacking Instructor (🎓)</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell>"Score Board"</TableCell>
              <TableCell>Miscellaneous</TableCell>
              <TableCell>Найти скрытую страницу с результатами и списком заданий.</TableCell>
              <TableCell>Угадывание URL (<code>/#/score-board</code>), анализ клиентского кода, подсказки Hacking Instructor.</TableCell>
              <TableCell>Да<sup>25</sup></TableCell>
            </TableRow>
            <TableRow>
              <TableCell>"Bonus Payload"</TableCell>
              <TableCell>XSS</TableCell>
              <TableCell>Использовать специальную XSS-нагрузку (iframe SoundCloud) для отображения встроенного контента.</TableCell>
              <TableCell>Поле поиска. Нагрузка: <code>{'<iframe... src="https://w.soundcloud.com/...></iframe>'}</code>.<sup>31</sup></TableCell>
              <TableCell>Да<sup>25</sup></TableCell>
            </TableRow>
            <TableRow>
              <TableCell>"DOM XSS"</TableCell>
              <TableCell>XSS</TableCell>
              <TableCell>Выполнить атаку DOM XSS с использованием javascript:alert.</TableCell>
              <TableCell>Поле поиска. Нагрузка: <code>{'<iframe src="javascript:alert(\'xss\')">'}</code>.<sup>31</sup></TableCell>
              <TableCell>Да<sup>25</sup></TableCell>
            </TableRow>
            <TableRow>
              <TableCell>"Error Handling"</TableCell>
              <TableCell>Error Handling</TableCell>
              <TableCell>Спровоцировать ошибку в приложении, которая обрабатывается некорректно, возможно, с утечкой информации.</TableCell>
              <TableCell>Поля ввода (поиск, формы), параметры URL. Ввод специальных символов (например, ').</TableCell>
              <TableCell>Проверить на Score Board</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>

      <H2>E. Блок контроля знаний (Урок 3)</H2>
      <Card className="my-6">
        <CardContent className="p-6 space-y-4">
          <div>
            <P><strong>1. Какая основная технология используется в OWASP Juice Shop, отличающая его от DVWA?</strong></P>
            <Ul items={[
              "a) PHP и MySQL",
              "b) Node.js, Express и Angular (JavaScript-стек)",
              "c) ASP.NET и MSSQL",
              "d) Python и Django"
            ]} />
            <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: b) Node.js, Express и Angular (JavaScript-стек)</em></P>
          </div>
          <hr />
          <div>
            <P><strong>2. Что такое "Score Board" в OWASP Juice Shop?</strong></P>
            <Ul items={[
              "a) Форум для обсуждения уязвимостей.",
              "b) Страница, отслеживающая прогресс в решении заданий и перечисляющая их.",
              "c) Инструмент для автоматического сканирования Juice Shop.",
              "d) Список администраторов приложения."
            ]} />
            <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: b) Страница, отслеживающая прогресс в решении заданий и перечисляющая их.</em></P>
          </div>
          <hr />
          <div>
            <P><strong>3. Какая команда Docker используется для запуска OWASP Juice Shop с пробросом порта 3000 и удалением контейнера после остановки?</strong></P>
            <Ul items={[
              "a) docker run -p 80:3000 bkimminich/juice-shop",
              "b) docker start -d -port 3000 bkimminich/juice-shop",
              "c) docker run --rm -d -p 3000:3000 bkimminich/juice-shop",
              "d) docker pull bkimminich/juice-shop -p 3000"
            ]} />
            <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: c) docker run --rm -d -p 3000:3000 bkimminich/juice-shop</em></P>
          </div>
          <hr />
          <div>
            <P><strong>4. Какая из следующих XSS-нагрузок обычно используется для проверки DOM XSS в Juice Shop в одном из начальных заданий?</strong></P>
            <Ul items={[
              "a) <script>window.location='http://malicious.com'</script>",
              "b) <h1>XSS</h1>",
              <>c) <code>{'<iframe src="javascript:alert(\'xss\')"></iframe>'}</code></>,
              "d) '; alert('XSS'); //"
            ]} />
            <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: c) {'<iframe src="javascript:alert(\'xss\')"></iframe>'}</em></P>
          </div>
          <hr />
          <div>
            <P><strong>5. Что означает иконка "🎓" (дипломная шапочка) рядом с некоторыми заданиями на Score Board в Juice Shop?</strong></P>
            <Ul items={[
              "a) Задание очень сложное.",
              "b) Задание связано с академическими исследованиями.",
              "c) Для этого задания доступен Hacking Instructor (пошаговое руководство).",
              "d) Задание было добавлено недавно."
            ]} />
            <P className="mt-2 text-primary font-semibold"><em>Правильный ответ: c) Для этого задания доступен Hacking Instructor (пошаговое руководство).</em></P>
          </div>
        </CardContent>
      </Card>
    </ContentPageLayout>
  );
}
    
