import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { KeyRound, UserCheck, Lock, Users } from 'lucide-react';

export default function ModuleThreePage() {
  return (
    <ContentPageLayout
      title="Модуль III: Атака на Механизмы Аутентификации и Управления Сессиями"
      imageUrl="https://placehold.co/600x400.png"
      imageAlt="Authentication and session security"
      imageAiHint="authentication security"
    >
      <H2><UserCheck className="inline-block mr-2 h-6 w-6 text-primary" />A. Атака на Механизмы Аутентификации</H2>
      <P>Этот раздел углубляется в уязвимости, связанные с проверкой личности пользователя.</P>
      <H3>Перебор Учетных Данных (Credential Stuffing & Brute Force):</H3>
      <Ul items={[
        "Перебор Паролей (Password Brute Forcing): Инструменты: Hydra, Burp Intruder.",
        "Перебор Имен Пользователей (Username Enumeration): Инструменты: Burp Intruder.",
        "Атака Распылением Паролей (Password Spraying): Инструменты: Hydra, скрипты."
      ]} />
      <P>Обсуждение механизмов защиты: блокировка учетных записей, rate limiting, CAPTCHA, MFA.</P>
      <H3>Уязвимости Логики Аутентификации:</H3>
      <Ul items={[
        "Небезопасное Восстановление Пароля: Предсказуемые токены, передача токена в URL, недостаточная проверка, password reset poisoning.",
        "Обход Многофакторной Аутентификации (MFA/2FA): Слабая генерация кодов, отсутствие ограничения на попытки, уязвимости в логике проверки.",
        "Небезопасная Передача Учетных Данных: HTTP вместо HTTPS, HTTP Basic Authentication.",
        "Уязвимости \"Запомнить меня\": Анализ стойкости токенов."
      ]} />
      <P>Тщательное тестирование с ручными методами и инструментами (Hydra, Burp Intruder) является обязательным.</P>

      <H2><Lock className="inline-block mr-2 h-6 w-6 text-primary" />B. Атака на Механизмы Управления Сессиями</H2>
      <P>Этот раздел посвящен уязвимостям, связанным с управлением состоянием пользователя после аутентификации.</P>
      <H3>Анализ Токенов Сессии:</H3>
      <Ul items={[
        "Предсказуемость Токенов: Burp Sequencer для анализа случайности и энтропии.",
        "Структура Токена: Burp Decoder для анализа на наличие осмысленной информации.",
        "JSON Web Tokens (JWT): Атаки на JWT (изменение payload, атаки на подпись), Burp JWT Editor."
      ]} />
      <H3>Небезопасное Обращение с Токенами:</H3>
      <Ul items={[
        "Передача по Незащищенному Каналу: Отсутствие флага Secure.",
        "Доступность для Скриптов: Отсутствие флага HttpOnly.",
        "Фиксация Сессии (Session Fixation): Проверка генерации нового ID сессии после входа.",
        "Недостатки Завершения Сессии: Проверка инвалидации сессии на сервере."
      ]} />
      <P>Инструменты вроде Burp Sequencer и JWT Editor необходимы для глубокого анализа.</P>

      <H2><Users className="inline-block mr-2 h-6 w-6 text-primary" />C. Атака на Механизмы Контроля Доступа</H2>
      <P>Контроль доступа определяет, что пользователь может делать после аутентификации.</P>
      <H3>Вертикальное Повышение Привилегий:</H3>
      <Ul items={[
        "Незашищенная Функциональность: Прямой доступ к административным URL.",
        "Манипуляция Параметрами: Изменение параметров, контролирующих роль пользователя.",
        "Обход на Уровне Платформы/Метода: Использование нестандартных заголовков, изменение HTTP-метода."
      ]} />
      <H3>Горизонтальное Повышение Привилегий и IDOR:</H3>
      <Ul items={[
        "Insecure Direct Object References (IDOR): Подмена ID в запросе. Может привести к утечке данных.",
        "Тестирование IDOR: Требует двух+ учетных записей. Burp Autorize для автоматизации."
      ]} />
      <H3>Другие Уязвимости:</H3>
      <Ul items={[
        "Уязвимости в Многошаговых Процессах.",
        "Контроль доступа на основе заголовка Referer или геолокации."
      ]} />
      <P>Тестирование требует понимания паттернов и часто включает ручную манипуляцию или автоматизацию с Autorize.</P>

      <H2><ListChecks className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Лаборатории и Инструменты</H2>
      <Ul items={[
        "PortSwigger Academy: Лаборатории по аутентификации, контролю доступа, JWT.",
        "OWASP Juice Shop: Задания \"Broken Authentication\", \"Broken Access Control\", задания с JWT.",
        "DVWA: Модули Brute Force, CSRF.",
        "TryHackMe: Комнаты Hydra, Brute Force Heroes, IDOR, Authentication Bypass.",
        "Инструменты: Burp Suite (Intruder, Sequencer, Repeater, Comparer, Autorize, JWT Editor), Hydra."
      ]} />
    </ContentPageLayout>
  );
}
