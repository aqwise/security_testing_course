import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { BookOpen, Settings, FlaskConical, Compass, ListChecks } from 'lucide-react';

export default function ModuleOnePage() {
  return (
    <ContentPageLayout
      title="Модуль I: Основы Безопасности Веб-Приложений и Методология WAHH2"
      imageUrl="https://placehold.co/600x400.png"
      imageAlt="Cybersecurity foundation"
      imageAiHint="security foundation"
    >
      <H2><Compass className="inline-block mr-2 h-6 w-6 text-primary" />A. Введение в Безопасность Веб-Приложений</H2>
      <P>
        Этот раздел закладывает фундамент для понимания ландшафта угроз веб-приложений. Рассматриваются основные концепции безопасности, типичные уязвимости и их влияние на бизнес. Обсуждается важность систематического подхода к тестированию на проникновение. Представляется методология, описанная в WAHH2, как основа для всего курса. Подчеркивается значение практического обучения с использованием безопасных и легальных сред, таких как PortSwigger Web Security Academy и OWASP Juice Shop.
      </P>

      <H2><BookOpen className="inline-block mr-2 h-6 w-6 text-primary" />B. Обзор Методологии WAHH2</H2>
      <P>Детально рассматриваются ключевые этапы методологии WAHH2:</P>
      <Ul items={[
        "Разведка (Reconnaissance): Сбор информации о цели без прямого взаимодействия.",
        "Картирование (Mapping): Анализ структуры и функциональности приложения.",
        "Обнаружение (Discovery): Выявление уязвимостей с помощью ручных и автоматизированных методов.",
        "Эксплуатация (Exploitation): Использование обнаруженных уязвимостей для достижения конкретных целей."
      ]} />
      <P>Подчеркивается итеративный характер процесса и важность понимания контекста приложения. Обсуждается роль инструментов, таких как Burp Suite, в каждом этапе.</P>

      <H2><Settings className="inline-block mr-2 h-6 w-6 text-primary" />C. Настройка Лабораторной Среды</H2>
      <P>Предоставляются инструкции по настройке необходимого программного обеспечения и окружения для практических занятий.</P>
      <H3>Установка и настройка Burp Suite:</H3>
      <P>Рассматриваются версии Community и Professional. Объясняется настройка прокси для перехвата трафика браузера. Демонстрируются основные инструменты Burp Suite (Proxy, Repeater, Intruder, Sequencer, Decoder).</P>
      <H3>Развертывание Уязвимых Приложений:</H3>
      <Ul items={[
        "OWASP Juice Shop: Рекомендуется использовать Docker. Упоминается руководство \"Pwning OWASP Juice Shop\".",
        "Damn Vulnerable Web Application (DVWA): Варианты установки (XAMPP, Docker, пакеты Kali). Настройка БД и уровней безопасности."
      ]} />
      <H3>Использование Онлайн-Платформ:</H3>
      <Ul items={[
        "PortSwigger Web Security Academy: Бесплатный ресурс с лабораториями.",
        "TryHackMe: Платформа с комнатами и путями обучения."
      ]} />

      <H2><ListChecks className="inline-block mr-2 h-6 w-6 text-primary" />D. Рекомендуемые Лаборатории и Ресурсы</H2>
      <Ul items={[
        "PortSwigger Academy: Начальные разделы, основы HTTP, работа с Burp Suite.",
        "OWASP Juice Shop: Установка, ознакомление, Score Board.",
        "DVWA: Установка, настройка уровней, ознакомление с модулями.",
        "TryHackMe: Комнаты \"OpenVPN\", \"Welcome\", \"Starting Out In Cyber Sec\", \"Linux Fundamentals\"."
      ]} />
    </ContentPageLayout>
  );
}
