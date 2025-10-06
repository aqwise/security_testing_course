'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import Link from 'next/link';
import { cn } from '@/lib/utils';
import { FlaskConical, CheckCircle2, XCircle, ScrollText, BookOpen, KeyRound, ShieldAlert, Fingerprint, Target, Lock, Unlock, Eye, EyeOff, AlertCircle, Bug, Shield } from 'lucide-react';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sourcesData = [
    { id: 1, text: "Access control vulnerabilities and privilege escalation - PortSwigger", url: "https://portswigger.net/web-security/access-control" },
    { id: 2, text: "How to use Autorize - Medium", url: "https://authorizedentry.medium.com/how-to-use-autorize-fcd099366239" },
    { id: 3, text: "GitHub - PortSwigger/autorize", url: "https://github.com/PortSwigger/autorize" },
    { id: 4, text: "GitHub - PortSwigger/turbo-intruder", url: "https://github.com/PortSwigger/turbo-intruder" },
    { id: 5, text: "Lab: Unprotected admin functionality", url: "https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality" },
    { id: 6, text: "Lab: Unprotected admin functionality with unpredictable URL", url: "https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url" },
    { id: 7, text: "Lab: User role controlled by request parameter", url: "https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter" },
    { id: 8, text: "Lab: User role can be modified in user profile", url: "https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile" },
    { id: 9, text: "Lab: User ID controlled by request parameter", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter" },
    { id: 10, text: "Lab: User ID controlled by request parameter, with unpredictable user IDs", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids" },
    { id: 11, text: "Lab: User ID controlled by request parameter with data leakage in redirect", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect" },
    { id: 12, text: "Lab: User ID controlled by request parameter with password disclosure", url: "https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure" },
    { id: 13, text: "Lab: Insecure direct object references", url: "https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references" },
    { id: 14, text: "Lab: Multi-step process with no access control on one step", url: "https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step" },
    { id: 15, text: "Lab: URL-based access control can be circumvented", url: "https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented" },
    { id: 16, text: "Lab: Method-based access control can be circumvented", url: "https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented" },
];

const quizQuestions = [
    { question: "Что является основной причиной уязвимостей контроля доступа?", answers: ["Слабые пароли", "Неправильная реализация проверок на сервере", "Отсутствие HTTPS", "Устаревшие библиотеки"], correctAnswerIndex: 1 },
    { question: "Какой принцип безопасности нарушается при хранении роли пользователя в cookie?", answers: ["Принцип минимальных привилегий", "Доверие клиентским данным", "Шифрование данных", "Аутентификация"], correctAnswerIndex: 1 },
    { question: "Что такое 'Forced Browsing'?", answers: ["Атака на пароли", "Обход проверок доступа путем прямого обращения к URL", "Межсайтовое выполнение скриптов", "Инъекция SQL-кода"], correctAnswerIndex: 1 },
    { question: "Какой инструмент Burp Suite наиболее эффективен для автоматизации поиска BAC/IDOR?", answers: ["Intruder", "Autorize", "Scanner", "Decoder"], correctAnswerIndex: 1 },
    { question: "Что означает принцип 'Deny by default'?", answers: ["Отказывать всем пользователям", "Запрещать доступ по умолчанию, разрешая только явно указанные действия", "Блокировать IP-адреса", "Требовать двухфакторную аутентификацию"], correctAnswerIndex: 1 },
    
    // Дополнительные вопросы для углубленной проверки знаний
    { question: "Что такое IDOR (Insecure Direct Object Reference)?", answers: ["Уязвимость в шифровании", "Уязвимость, при которой приложение использует идентификатор объекта от клиента без проверки прав", "Атака на сессии", "Проблема с CORS"], correctAnswerIndex: 1 },
    { question: "Какой из примеров НЕ является вектором атаки на контроль доступа?", answers: ["Изменение ID в URL", "Подделка JWT токена", "SQL-инъекция", "Обход многоэтапного процесса"], correctAnswerIndex: 2 },
    { question: "Что означает BAC в контексте веб-безопасности?", answers: ["Basic Access Control", "Broken Access Control", "Backend Access Control", "Blocked Access Control"], correctAnswerIndex: 1 },
    { question: "Какая из ситуаций описывает горизонтальное повышение привилегий?", answers: ["Обычный пользователь получает права админа", "Пользователь A видит данные пользователя B", "Неавторизованный доступ к админ-панели", "Обход двухфакторной аутентификации"], correctAnswerIndex: 1 },
    { question: "В каком случае возникает вертикальное повышение привилегий?", answers: ["Пользователь видит чужие данные", "Обычный пользователь получает доступ к админским функциям", "Изменение собственного профиля", "Просмотр публичной информации"], correctAnswerIndex: 1 },
    
    { question: "Что такое Path Traversal атака?", answers: ["Обход аутентификации", "Использование относительных путей для доступа к файлам вне разрешенных директорий", "Атака на базу данных", "Кража сессионных токенов"], correctAnswerIndex: 1 },
    { question: "Какой пример демонстрирует Path Traversal?", answers: ["/upload?file=document.pdf", "/upload?file=../../etc/passwd", "/admin/users", "/api/user/123"], correctAnswerIndex: 1 },
    { question: "Что означает Client Side Caching в контексте BAC?", answers: ["Кэширование на стороне сервера", "Кэширование конфиденциальных данных в браузере", "Кэширование API запросов", "Кэширование статических файлов"], correctAnswerIndex: 1 },
    { question: "Какие HTTP заголовки помогают предотвратить нежелательное кэширование?", answers: ["Authorization, Content-Type", "Cache-Control, X-Cache", "CORS, X-Frame-Options", "User-Agent, Accept"], correctAnswerIndex: 1 },
    { question: "Что может раскрыть файл robots.txt?", answers: ["Пароли пользователей", "Пути к скрытым админ-разделам", "API ключи", "Конфигурацию сервера"], correctAnswerIndex: 1 },
    
    { question: "Какой параметр может указывать на IDOR уязвимость?", answers: ["user_id=123", "username=admin", "password=123456", "session=active"], correctAnswerIndex: 0 },
    { question: "Что нужно сделать для эксплуатации IDOR?", answers: ["Подобрать пароль", "Изменить ID на ID другого пользователя", "Выполнить SQL-инъекцию", "Украсть сессионный токен"], correctAnswerIndex: 1 },
    { question: "В чем разница между user.example.com и admin.example.com, если они используют один API?", answers: ["Разные базы данных", "Разные интерфейсы, но возможно одинаковые права в API", "Разные серверы", "Разные протоколы"], correctAnswerIndex: 1 },
    { question: "Как можно создать пользователя с правами админа?", answers: ["Угадать пароль админа", "Добавить параметр user_role:admin при создании", "Использовать SQL-инъекцию", "Перехватить сессию админа"], correctAnswerIndex: 1 },
    { question: "Что означает статус ответа 200 OK при тестировании BAC?", answers: ["Доступ запрещен", "Запрос выполнен успешно", "Ошибка сервера", "Неавторизованный доступ"], correctAnswerIndex: 1 },
    
    { question: "Какие методы HTTP чаще всего не защищены контролем доступа?", answers: ["GET, HEAD", "POST, PUT, PATCH, DELETE", "OPTIONS, TRACE", "CONNECT, TRACK"], correctAnswerIndex: 1 },
    { question: "Что такое /actuator в Spring Boot?", answers: ["База данных", "Endpoint для мониторинга и управления", "Система авторизации", "Кэш приложения"], correctAnswerIndex: 1 },
    { question: "Какой тип файлов часто забывают защитить?", answers: ["HTML страницы", "Статические файлы и API документация", "CSS стили", "JavaScript файлы"], correctAnswerIndex: 1 },
    { question: "Что означает CORS в контексте BAC?", answers: ["Cross-Origin Resource Sharing", "Cross-Origin Request Security", "Cookie Origin Resource Sharing", "Client Origin Request Security"], correctAnswerIndex: 0 },
    { question: "Как неправильная настройка CORS влияет на безопасность?", answers: ["Замедляет работу сайта", "Позволяет несанкционированный доступ к API", "Блокирует легитимные запросы", "Не влияет на безопасность"], correctAnswerIndex: 1 },
    
    { question: "Что такое JWT токен?", answers: ["Java Web Token", "JSON Web Token", "JavaScript Web Token", "Joint Web Token"], correctAnswerIndex: 1 },
    { question: "Как можно атаковать JWT токен?", answers: ["Подобрать ключ для токена", "Изменить алгоритм подписи", "Использовать токен после логаута", "Все перечисленные"], correctAnswerIndex: 3 },
    { question: "Что происходит при некорректной инвалидации JWT?", answers: ["Токен остается действительным после выхода", "Токен становится недействительным", "Пользователь не может войти", "Система перезагружается"], correctAnswerIndex: 0 },
    { question: "Какая информация может храниться в cookie?", answers: ["Только ID сессии", "Роль пользователя и права доступа", "Только время последнего входа", "Только имя пользователя"], correctAnswerIndex: 1 },
    { question: "Почему опасно хранить роль в cookie?", answers: ["Cookie медленно работают", "Пользователь может изменить значение", "Cookie занимают много места", "Cookie не поддерживаются старыми браузерами"], correctAnswerIndex: 1 },
    
    { question: "Какой расширение Burp Suite используется для поиска BAC?", answers: ["Intruder", "Autorize", "Scanner", "Comparer"], correctAnswerIndex: 1 },
    { question: "Что делает расширение Turbo Intruder?", answers: ["Сканирует на XSS", "Отправляет большое количество HTTP запросов с высокой скоростью", "Анализирует JavaScript", "Проверяет SSL сертификаты"], correctAnswerIndex: 1 },
    { question: "В каком режиме работает Autorize?", answers: ["Активно сканирует сайт", "Пассивно анализирует запросы", "Перехватывает все запросы", "Модифицирует ответы сервера"], correctAnswerIndex: 1 },
    { question: "Какие вкладки Burp Suite наиболее полезны для ручного тестирования BAC?", answers: ["Proxy, Repeater, Intruder", "Scanner, Spider", "Decoder, Comparer", "Target, Dashboard"], correctAnswerIndex: 0 },
    { question: "Зачем нужны два аккаунта при тестировании с Autorize?", answers: ["Для сравнения скорости", "Для проверки функциональности", "Для сравнения прав доступа разных ролей", "Для нагрузочного тестирования"], correctAnswerIndex: 2 },
    
    { question: "Что важнее: автоматическое или ручное тестирование BAC?", answers: ["Только автоматическое", "Только ручное", "Ручное дает больше результата, но автоматическое ускоряет процесс", "Нет разницы"], correctAnswerIndex: 2 },
    { question: "Когда полезна автоматизация в тестировании BAC?", answers: ["При работе с одной ролью", "При большом количестве ролей и API вызовов", "При тестировании статических страниц", "Автоматизация не нужна"], correctAnswerIndex: 1 },
    { question: "Какой подход рекомендуется: от меньших привилегий к большим или наоборот?", answers: ["От больших к меньшим", "От меньших к большим", "Случайный порядок", "Одновременно все"], correctAnswerIndex: 1 },
    { question: "Что означает 'понять бизнес идею приложения'?", answers: ["Изучить код приложения", "Понять роли пользователей и их права", "Изучить базу данных", "Понять технологии"], correctAnswerIndex: 1 },
    { question: "На что нужно обращать внимание при анализе приложения?", answers: ["Только на технические детали", "На типы пользователей и их права доступа", "Только на UI интерфейс", "Только на производительность"], correctAnswerIndex: 1 },
    
    { question: "Какой принцип безопасности нарушается при отсутствии контроля доступа?", answers: ["Принцип наименьших привилегий", "Принцип разделения обязанностей", "Принцип глубокой защиты", "Все перечисленные"], correctAnswerIndex: 3 },
    { question: "Что означает 'контроль доступа к моделям с помощью права собственности'?", answers: ["Все пользователи могут все", "Пользователь имеет доступ только к своим данным", "Только админ управляет данными", "Данные общедоступны"], correctAnswerIndex: 1 },
    { question: "Зачем нужно отключать перечень каталогов веб-сервера?", answers: ["Для ускорения работы", "Чтобы скрыть структуру файлов от злоумышленников", "Для экономии места", "Для улучшения SEO"], correctAnswerIndex: 1 },
    { question: "Что такое метаданные файлов в контексте безопасности?", answers: ["Размер файлов", "Файлы .git, .svn, резервные копии", "Права доступа к файлам", "Время создания файлов"], correctAnswerIndex: 1 },
    { question: "Зачем регистрировать сбои контроля доступа?", answers: ["Для статистики", "Для выявления атак и уведомления администраторов", "Для оптимизации", "Для отчетности"], correctAnswerIndex: 1 },
    
    { question: "Что такое ограничение скорости (rate limiting)?", answers: ["Ограничение скорости интернета", "Ограничение частоты запросов к API", "Ограничение размера файлов", "Ограничение времени сессии"], correctAnswerIndex: 1 },
    { question: "Зачем нужно ограничение скорости при защите от BAC?", answers: ["Для экономии ресурсов", "Для защиты от автоматизированных атак", "Для улучшения производительности", "Для соблюдения стандартов"], correctAnswerIndex: 1 },
    { question: "Где должна происходить проверка контроля доступа?", answers: ["На стороне клиента", "На стороне сервера", "В базе данных", "В браузере"], correctAnswerIndex: 1 },
    { question: "Почему нельзя полагаться на клиентскую проверку доступа?", answers: ["Она медленная", "Злоумышленник может ее обойти", "Она не работает в старых браузерах", "Она требует JavaScript"], correctAnswerIndex: 1 },
    { question: "Что такое бессерверное API в контексте контроля доступа?", answers: ["API без сервера", "API с серверной проверкой прав", "API без базы данных", "API без авторизации"], correctAnswerIndex: 1 },
    
    { question: "Какой лабораторной работы НЕТ в списке домашних заданий?", answers: ["Unprotected Admin Functionality", "User ID controlled by request parameter", "SQL injection in login", "Method-based access control can be circumvented"], correctAnswerIndex: 2 },
    { question: "Сколько основных лабораторных работ предлагается для изучения?", answers: ["8", "10", "12", "15"], correctAnswerIndex: 2 },
    { question: "Какие лабораторные работы отмечены звездочкой?", answers: ["Самые простые", "Самые сложные", "Дополнительные для углубленного изучения", "Обязательные"], correctAnswerIndex: 2 },
    { question: "На какой платформе размещены рекомендуемые лабораторные работы?", answers: ["OWASP WebGoat", "PortSwigger Web Security Academy", "DVWA", "VulnHub"], correctAnswerIndex: 1 },
    { question: "Что является конечной целью изучения BAC уязвимостей?", answers: ["Сдать экзамен", "Понять на что обращать внимание и как можно повлиять", "Получить сертификат", "Изучить все инструменты"], correctAnswerIndex: 1 }
];

interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
}

const QuizItem: React.FC<QuizItemProps> = ({ question, answers, correctAnswerIndex }) => {
  const [selectedAnswer, setSelectedAnswer] = React.useState<number | null>(null);

  const handleAnswerClick = (index: number) => {
    setSelectedAnswer(index);
  };

  const isAnswered = selectedAnswer !== null;

  return (
    <div className="mb-6 p-4 border rounded-lg bg-card shadow-sm">
      <p className="font-semibold text-foreground mb-3">{question}</p>
      <ul className="space-y-2">
        {answers.map((answer, index) => {
          const isCorrect = index === correctAnswerIndex;
          const isSelected = selectedAnswer === index;
          
          let itemClass = "cursor-pointer p-2 rounded-md transition-colors duration-200 border border-transparent";
          if (isAnswered) {
            if (isCorrect) {
              itemClass = cn(itemClass, "bg-green-100 dark:bg-green-900/30 border-green-500 text-green-800 dark:text-green-300 font-medium");
            } else if (isSelected) {
              itemClass = cn(itemClass, "bg-red-100 dark:bg-red-900/30 border-red-500 text-red-800 dark:text-red-300");
            } else {
               itemClass = cn(itemClass, "text-muted-foreground");
            }
          } else {
            itemClass = cn(itemClass, "hover:bg-accent hover:text-accent-foreground");
          }

          return (
            <li
              key={index}
              onClick={() => !isAnswered && handleAnswerClick(index)}
              className={itemClass}
            >
              <span className="mr-2">{String.fromCharCode(97 + index)})</span>{answer}
              {isAnswered && isSelected && !isCorrect && (
                  <span className="text-xs ml-2 text-red-600 dark:text-red-400">(Неверно)</span>
              )}
               {isAnswered && isCorrect && (
                  <span className="text-xs ml-2 text-green-700 dark:text-green-400 font-bold">(Правильный ответ)</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
};

export default function Module3Lesson4Page() {
  return (
    <ContentPageLayout
      title="Урок 4: Broken access control"
      subtitle="Модуль III: Аутентификация и сессии"
    >
        <div className="mb-8">
            <P><strong>Автор:</strong> Vladyslav Koniakhin</P>
        </div>

        <H2>Что такое нарушение контроля доступа?</H2>
        <P>Нарушение контроля доступа — это уязвимость, которая позволяет злоумышленнику повысить свои права в приложении или получить доступ к ограниченным разделам и функциям.</P>
        <P>Матрица доступа, разработанная и реализованная в проекте, которая на бумаге выглядела так хорошо, может быть неправильно применена к конкретной системе, в результате чего злоумышленники быстро получают доступ к ограниченным разделам сайта или получают возможность изменять права на ресурсы по своему усмотрению.</P>

        <H2>Наиболее распространенные уязвимости системы контроля доступа включают:</H2>
        <ol className="list-decimal list-inside space-y-3 ml-4">
            <li>Обход ограничений доступа путем <strong>изменения URL-адреса</strong>, внутреннего состояния приложения или HTML-страницы, а также использования специально разработанных API;</li>
            <li>Возможность изменения <strong>первичного ключа для доступа к записям других пользователей</strong>, включая просмотр или редактирование чужой учетной записи; повышение привилегий.</li>
            <li><strong>Выполнение операций с правами пользователя без входа в систему или с правами администратора, путем входа в систему с правами пользователя</strong>;</li>
        </ol>
        <P>Например есть два интерфейса для <em>Users</em>, второй для <em>Admin</em>, но на одном API. Создаем Usera с правами Admin(например добавив параметр user_role:admin во время создания юзера). Далее, на admin.example.com мы зайти не можем, но можем все админские действия выполнять из под user.example.com.</P>
        
        <ol className="list-decimal list-inside space-y-3 ml-4" start={4}>
            <li><strong>Манипулирование метаданными</strong>, например воспроизведение или подделка токенов контроля доступа <strong>JWT</strong>(например подбор ключа для токена) или файлов <strong>cookie</strong>(например перебор <strong>cookie</strong>), изменение скрытых полей для повышения привилегий или некорректная аннулирование JWT;</li>
            <li><strong>Несанкционированный доступ к API</strong> из-за неправильной настройки междоменного использования ресурсов (<strong>CORS</strong>);</li>
            <li>Доступ неавторизованных пользователей к страницам, требующим аутентификации, или доступ непривилегированных пользователей к выбранным страницам.</li>
            <li>Доступ к API без контроля привилегий для методов/запросов <strong>POST, PUT, PATCH и DELETE</strong>.</li>
            <li><strong>Просто забытые / не задокументированные API-calls</strong>, которые мы можем обнаружить во время разведки(отличны пример <strong>/actuator</strong> <strong>sping boot</strong>), публично доступные статические файлы и тд.</li>
        </ol>

        <H2>Импакт:</H2>
        <ol className="list-decimal list-inside space-y-2 ml-4">
            <li>Выполнение злоумышленником действий с правами пользователя или администратора;</li>
            <li>Использование привилегированных функций пользователем;</li>
            <li>Создание, просмотр, обновление или удаление любых записей.</li>
            <li>Последствия для бизнеса зависят от критичности приложения и защиты данных.</li>
        </ol>

        <P>То есть, изменить имя админа или другого пользователя это одно, но если помимо этого мы можем загрузить файл на сервер без авторизации, то тут уже может быть все совсем по другому.</P>

        <H2>Процесс эксплуатации</H2>
        <P>На самом деле существует множество способов эксплуатации и метод эксплуатации зависит от места, где находится уязвимость.</P>
        <P>Классический вариант - подмена <strong>ID, UUID</strong> и тд. Либо возможности пользователя с одними правами, совершать действиями, которые ему не доступны. Как пример - есть фича загрузки файлов для админа, которая не доступна для обычного пользователя. Но заменив <strong>cookie / jwt</strong> токен с <strong>админского</strong> на <strong>обычного</strong> юзера и отправив запрос, мы получаем статус ответ <strong>200 ОК</strong>. Далее проверив с админского аккаунта, действительно ли загружен файл и потвердив это, мы можем уверенно сказать, что здесь существует уязвимость.</P>

        <H2>Способы поиска уязвимостей</H2>
        <P>Как и в случае со всеми абсолютно приложениями – это <strong>понять бизнес идею приложения</strong>.</P>
        <P>Рассмотрите типы авторизованных пользователей в вашей системе. Ограничен ли доступ пользователей к функциям и данным, к которым они не должны иметь доступа? Доступны ли какие-либо функции или данные для неавторизованных пользователей? Возможно ли получить доступ к частным данным или функциям путем изменения передаваемого параметра на сервер?</P>

        <H2>Способы защиты от уязвимостей</H2>
        <ol className="list-decimal list-inside space-y-2 ml-4">
            <li>Рекомендуется запретить доступ к функциям по умолчанию.</li>
            <li>Используйте списки контроля доступа и механизмы аутентификации на основе ролей или атрибутов.</li>
        </ol>

        <H2>Ниже приведены векторы атак и способы защиты от них:</H2>
        
        <H3><strong>Insecure IDs</strong></H3>
        <P>— большинство веб-сайтов используют идентификаторы в той или иной форме для обозначения пользователей, ролей, контента, объектов или функций. Если злоумышленник может угадать эти идентификаторы, а предоставленные значения не проверяются на авторизацию для текущего пользователя(поменяли ID, отправили запрос, получили информацию о другом пользователе), он может использовать схему контроля доступа, чтобы узнать, к чему у него есть доступ. Веб-приложения не должны полагаться на конфиденциальность каких-либо идентификаторов для защиты.</P>
        
        <H3><strong>Forced Browsing Past Access Control Checks</strong></H3>
        <P>— многие сайты требуют от пользователей прохождения определенных проверок, прежде чем им будет предоставлен доступ к определенным URL-адресам. Эти проверки не должны быть обходимыми. Допустим, у вас есть учетная запись на веб-сайте, предоставляющем доступ к конфиденциальным данным. Для получения доступа к этим данным требуется определенная проверка, например, ввод правильного имени пользователя и пароля. Однако вы заметили, что в адресной строке браузера URL-адрес содержит уникальный идентификатор страницы с конфиденциальной информацией. Используя этот идентификатор, вы можете попытаться обойти проверку доступа, например, введя его вручную в адресную строку браузера(не всегда работает) или в Burp Suite в вкладке Repeater..</P>
        
        <H3><strong>Path Traversal</strong></H3>
        <P>— эта атака заключается в предоставлении информации об относительном пути (например, "../../target_dir/target_file") в рамках запроса информации. Злоумышленники пытаются получить доступ к файлам, к которым обычно нет прямого доступа.</P>

        <P>Предположим, у вас есть веб-сайт, предоставляющий доступ к файлам, расположенным на сервере. Вы хотите загрузить файлы на сервер, но вам не разрешено загружать файлы в корневой каталог. Однако вы заметите, что запросы к серверу используют относительный путь к каталогу, куда вы загружаете файлы. Например, запрос может выглядеть так: http://example.com/upload?path=uploads/myfile.jpg Вы понимаете, что, изменив относительный путь, вы можете попытаться получить доступ к другим файлам на сервере. Например, вы можете попробовать загрузить файл, используя следующий путь: http://example.com/upload?path=../../etc/passwd. В этом случае, если сервер не проверяет путь к файлу, злоумышленник может загрузить файл в любой каталог на сервере, включая системные каталоги, такие как /etc/, что может привести к возможности выполнения произвольного кода на сервере или получению доступа к конфиденциальной информации.</P>
        
        <H3><strong>File Permissions</strong></H3>
        <P>— только файлы, предназначенные для просмотра веб-пользователями, должны быть помечены как доступные для чтения, большинство каталогов должны быть недоступны для чтения, а минимальное количество файлов должно быть помечено как исполняемые.</P>
        
        <H3><strong>Client Side Caching</strong></H3>
        <P>— многие пользователи обращаются к веб-приложениям с общедоступных компьютеров, расположенных в библиотеках, школах, аэропортах и ​​других общественных местах. Браузеры часто кэшируют веб-страницы, и злоумышленники могут получить доступ к их кэшу и таким образом получить конфиденциальную информацию. Разработчикам необходимо использовать несколько механизмов, включая HTTP-заголовки и метатеги, чтобы гарантировать, что страницы, содержащие конфиденциальную информацию, не будут кэшироваться браузерами пользователей. Обращаем внимание на хедеры Cache, X-Cache и др.</P>

        <H2>Как предотвратить уязвимость</H2>
        <P>Контроль доступа эффективен только в том случае, если он реализован с помощью проверенного серверного кода или бессерверного API, где злоумышленник не может изменить проверки доступа или метаданные.</P>

        <H2>Рекомендуется:</H2>
        <ol className="list-decimal list-inside space-y-2 ml-4">
            <li>По умолчанию запрещать доступ, за исключением открытых ресурсов;</li>
            <li>Внедрять механизмы контроля доступа и использовать их во всех приложениях, а также минимизировать междоменное использование ресурсов;</li>
            <li>Контролировать доступ к моделям с помощью права собственности на записи, а не возможности пользователей создавать, просматривать, обновлять или удалять любые записи; (То есть конкретный пользователь имеет доступ к конкретным данным, предписанным для его роли в модели доступа)</li>
            <li>Использовать доменные модели для реализации ограничений, специфичных для приложения;</li>
            <li>Отключить перечень каталогов веб-сервера и убедиться, что метаданные файлов (такие как .git и тд.) и файлы резервных копий не находятся в корневых каталогах веб-сервера;</li>
            <li>Регистрировать сбои контроля доступа и уведомлять администраторов в случае необходимости (например, если сбои повторяются);</li>
            <li>Ограничить частоту доступа к API и контроллерам, чтобы минимизировать ущерб от инструментов автоматизации атак(ограничение скорости);</li>
            <li>Инвалидировать токены JWT на сервере после выхода из системы.</li>
        </ol>

        <H2>Какие инструменты мы используем?</H2>
        <P>Инструменты, обычно используемые для поиска BAC\IDOR: Burp Suite (Proxy / Intercept / Repeater/ Addon Autorize).</P>
        <P>Инструкция по Autorize:</P>
        <P>
            <Link href="https://authorizedentry.medium.com/how-to-use-autorize-fcd099366239" target="_blank" rel="noopener noreferrer" className={LinkStyle}>
                How to use Autorize
            </Link>
        </P>

        <P>В двух словах - авторизируемся и получаем токен или куки с одного аккаунта, также делаем в со вторым аккаунтом в инкогнито. Вставляем их в расширение и идем по вкладкам от меньшей привелегии к большей. Данные получаем автоматически. Но важно заметить, что ручное тестирование дает больше результата и точности, но если у нас несколько ролей и большой скоуп API-calls, то это упрощает проведение анализа.</P>

        <H2>Burp Suite Extensions</H2>
        <ol className="list-decimal list-inside space-y-4 ml-4">
            <li><strong>Autorize</strong> — популярное расширение для поиска уязвимостей BAC. (Burp Suite Community Edition) GitHub: <Link href="https://github.com/PortSwigger/autorize" target="_blank" rel="noopener noreferrer" className={LinkStyle}>GitHub - PortSwigger/autorize: Automatic authorization enforcement detection extension for burp suite written in Jython developed by Barak Tawily in order to ease application security people work and allow them perform an automatic authorization tests</Link><br />BAppStore: <strong>Autorize</strong></li>
            <li><strong>Turbo Intruder</strong> — благодаря хорошей скорости работы Turbo Intruder удобно использовать для поиска/эксплуатации IDOR-уязвимостей, подбора различных идентификаторов, токенов и других подобных целей. (Burp Suite Community Edition)<br />GitHub: <Link href="https://github.com/PortSwigger/turbo-intruder" target="_blank" rel="noopener noreferrer" className={LinkStyle}>GitHub - PortSwigger/turbo-intruder: Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.</Link><br />bAppStore: <strong>Turbo Intruder</strong></li>
        </ol>

        <H2>Домашнее задание</H2>
        <P>Также дополнительную теорию читаем на <Link href="https://portswigger.net/web-security/access-control" target="_blank" rel="noopener noreferrer" className={LinkStyle}>PortSwigger</Link> и выполняем следующие лабы:</P>

        <ol className="list-decimal list-inside space-y-2 ml-4">
            <li><Link href="https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Unprotected Admin Functionality</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Unprotected admin functionality with unpredictable URL</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User role controlled by request parameter</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User role can be modified in user profile</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User ID controlled by request parameter</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User ID controlled by request parameter, with unpredictable user IDs</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User ID controlled by request parameter with data leakage in redirect</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure" target="_blank" rel="noopener noreferrer" className={LinkStyle}>User ID controlled by request parameter with password disclosure</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Insecure direct object references</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Multi-step process with no access control on one step</Link></li>
        </ol>

        <P>И задания со <strong>*</strong></P>

        <ol className="list-decimal list-inside space-y-2 ml-4" start={11}>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented" target="_blank" rel="noopener noreferrer" className={LinkStyle}>URL-based access control can be circumvented</Link></li>
            <li><Link href="https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Method-based access control can be circumvented</Link></li>
        </ol>

        <P>Не все уязвимости могут встретиться на реальных проектах, не все может получиться при прохождении, но главное – понять суть на что, где и когда обращать внимание и на что мы как атакующие можем повлиять.</P>

        <H2>Контрольные вопросы</H2>
        <Card>
            <CardHeader>
                <CardTitle>Тест по нарушениям контроля доступа</CardTitle>
                <CardDescription>Проверьте понимание материала.</CardDescription>
            </CardHeader>
            <CardContent>
                {quizQuestions.map((q, index) => (
                    <QuizItem key={index} {...q} />
                ))}
            </CardContent>
        </Card>

        <H2>Источники</H2>
        <ol className="list-decimal list-inside space-y-2 text-sm">
            {sourcesData.map(source => (
                <li key={source.id} id={`source-${source.id}`}>
                    {source.url ? (
                        <Link href={source.url} target="_blank" rel="noopener noreferrer" className={LinkStyle}>{source.text}</Link>
                    ) : (
                        source.text
                    )}
                </li>
            ))}
        </ol>

    </ContentPageLayout>
  );
}
