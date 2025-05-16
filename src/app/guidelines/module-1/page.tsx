import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { BookOpen, Settings, Compass, ListChecks } from 'lucide-react';

export default function ModuleOnePage() {
  return (
    <ContentPageLayout
      title="Модуль I: Основы Безопасности Веб-Приложений и Методология WAHH2"
    >
      <H2><Compass className="inline-block mr-2 h-6 w-6 text-primary" />A. Введение в Безопасность Веб-Приложений</H2>
      <P>
        Этот раздел закладывает фундамент для понимания ландшафта угроз веб-приложений. 
        Рассматриваются основные концепции безопасности, типичные уязвимости и их влияние на бизнес. 
        Обсуждается важность систематического подхода к тестированию на проникновение. 
        Представляется методология, описанная в WAHH2, как основа для всего курса. 
        Подчеркивается значение практического обучения с использованием безопасных и легальных сред, таких как{' '}
        <a href="https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          PortSwigger Web Security Academy 1
        </a>
        {' и '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          OWASP Juice Shop 2
        </a>
        {', которые предоставляют реалистичные сценарии для отработки '}
        <a href="https://community.f5.com/kb/technicalarticles/mitigating-owasp-web-application-risk-server-side-request-forgery-ssrf-using-f5-/340260" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          навыков.2
        </a>
      </P>

      <H2><BookOpen className="inline-block mr-2 h-6 w-6 text-primary" />B. Обзор Методологии WAHH2</H2>
      <P>Детально рассматриваются ключевые этапы методологии WAHH2:</P>
      <Ul items={[
        "Разведка (Reconnaissance): Сбор информации о цели без прямого взаимодействия.",
        "Картирование (Mapping): Анализ структуры и функциональности приложения.",
        "Обнаружение (Discovery): Выявление уязвимостей с помощью ручных и автоматизированных методов.",
        "Эксплуатация (Exploitation): Использование обнаруженных уязвимостей для достижения конкретных целей (например, доступ к данным, выполнение команд)."
      ]} />
      <P>
        Подчеркивается итеративный характер процесса и важность понимания контекста приложения. Обсуждается роль инструментов, таких как{' '}
        <a href="https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Burp Suite 1
        </a>
        {', в каждом этапе.'}
      </P>

      <H2><Settings className="inline-block mr-2 h-6 w-6 text-primary" />C. Настройка Лабораторной Среды</H2>
      <P>Предоставляются инструкции по настройке необходимого программного обеспечения и окружения для практических занятий.</P>
      
      <H3>Установка и настройка Burp Suite:</H3>
      <P>
        Рассматриваются версии {' '}
        <a href="https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Community и Professional.1
        </a>
        {' Объясняется настройка прокси для '}
        <a href="https://github.com/juice-shop/juice-shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
           перехвата трафика браузера.18
        </a>
        {' Демонстрируются основные инструменты Burp Suite (Proxy, Repeater, Intruder, Sequencer, '}
        <a href="https://brightsec.com/blog/ssrf-server-side-request-forgery/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Decoder).21
        </a>
      </P>
      
      <H3>Развертывание Уязвимых Приложений:</H3>
      <P>
        <strong>OWASP Juice Shop:</strong> Рекомендуется использовать {' '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Docker для быстрого развертывания.2
        </a>
        {' Упоминается официальное руководство '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          «Pwning OWASP Juice Shop» 2
        </a>
        {' как важный ресурс для '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          прохождения испытаний.2
        </a>
        {' Juice Shop охватывает широкий спектр уязвимостей, включая '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          OWASP Top 10.2
        </a>
      </P>
      <P>
        <strong>Damn Vulnerable Web Application (DVWA):</strong> Рассматриваются варианты установки ({' '}
        <a href="https://github.com/juice-shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          XAMPP 16
        </a>
        {', '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Docker 16
        </a>
        {', пакеты '}
        <a href="https://github.com/juice-shop/juice-shop/releases/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Kali 27
        </a>
        {'). Объясняется настройка базы данных и уровней безопасности (Low, Medium, High, '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          Impossible).2
        </a>
        {' Указываются учетные данные по умолчанию '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          (admin/password).32
        </a>
        {' DVWA отлично подходит для отработки конкретных уязвимостей, таких как '}
        <a href="https://portswigger.net/web-security/all-materials" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          SQLi, Command Injection, XSS, CSRF.36
        </a>
      </P>

      <H3>Использование Онлайн-Платформ:</H3>
      <P>
        <strong>PortSwigger Web Security Academy:</strong> Бесплатный ресурс с высококачественными учебными материалами и интерактивными лабораториями, созданными {' '}
        <a href="https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          авторами WAHH2.1
        </a>
        {' Охватывает широкий '}
        <a href="https://www.reddit.com/r/tryhackme/comments/1ayxqm4/hi_everybody_here_is_a_walkthrough_of_the_fifth/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          спектр тем 39
        </a>
        {' и предоставляет возможность '}
        <a href="https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          отслеживать прогресс.17
        </a>
      </P>
      <P>
        <strong>TryHackMe:</strong> Платформа с практическими комнатами (rooms) и {' '}
        <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          путями обучения (learning paths) 2
        </a>
        {', включая комнаты, посвященные '}
        <a href="https://portswigger.net/research/burp-clickbandit-a-javascript-based-clickjacking-poc-generator" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          веб-основам 41
        </a>
        {', конкретным уязвимостям '}
        <a href="https://www.vaadata.com/blog/exploiting-the-ssrf-vulnerability/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          и инструментам.47
        </a>
        {' Предлагает как бесплатный, так и '}
        <a href="https://www.vaadata.com/blog/exploiting-the-ssrf-vulnerability/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
          платный контент.12
        </a>
      </P>

      <H2><ListChecks className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Лаборатории и Ресурсы</H2>
      <Ul items={[
        <>
          <a href="https://ilmubersama.com/2022/03/12/cross-site-scripting-xss-reflected-dvwa-1-10-security-level-low/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            PortSwigger Academy: Начальные разделы, основы HTTP, работа с Burp Suite.14
          </a>
        </>,
        <>
          <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            OWASP Juice Shop: Установка, ознакомление с интерфейсом, поиск Score Board.2
          </a>
        </>,
        <>
          <a href="https://portswigger.net/web-security/all-labs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            DVWA: Установка, настройка уровней безопасности, ознакомление с модулями.16
          </a>
        </>,
        <>
          TryHackMe: Комнаты{' '}
          <a href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            "OpenVPN" 47
          </a>
          {', '}
          <a href="https://github.com/tharushkadinujaya05/TryHackMe-Learning-Path-From-Beginner-to-Expert" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            "Welcome" 52
          </a>
          {', '}
          <a href="https://github.com/tharushkadinujaya05/TryHackMe-Learning-Path-From-Beginner-to-Expert" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            "Starting Out In Cyber Sec" 52
          </a>
          {', '}
          <a href="https://github.com/gadoi/tryhackme/blob/main/HTTP%20in%20detail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
            "Linux Fundamentals".52
          </a>
        </>
      ]} />
    </ContentPageLayout>
  );
}
