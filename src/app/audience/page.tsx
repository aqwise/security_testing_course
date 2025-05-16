import { ContentPageLayout, P, Ul, H3 } from '@/components/content/ContentPageLayout';
import { Users, Target, BookOpen, Laptop, Code } from 'lucide-react';
import Link from 'next/link';

export default function AudiencePage() {
  return (
    <ContentPageLayout
      title="III. Пересмотренная Целевая Аудитория"
    >
      <P>
        Данное руководство предназначено для широкого круга лиц, заинтересованных в изучении и совершенствовании практических навыков тестирования безопасности веб-приложений. Основная аудитория включает:
      </P>

      <Ul items={[
        <>Начинающие специалисты по кибербезопасности: Студенты и энтузиасты, делающие первые шаги в области информационной безопасности и желающие получить практический опыт в поиске веб-уязвимостей.8</>,
        <>Тестировщики на проникновение (Penetration Testers): Специалисты, стремящиеся углубить свои знания в области веб-пентестинга, освоить новые техники и инструменты, а также подготовиться к сертификациям, таким как <Link href="https://portswigger.net/burp/certification" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Burp Suite Certified Practitioner</Link>.6</>,
        <>Аналитики безопасности (Security Analysts): Специалисты Blue Team и SOC, которым необходимо понимать векторы атак на веб-приложения для эффективного обнаружения, анализа и реагирования на инциденты.21</>,
        <>Веб-разработчики: Программисты, желающие понять, как злоумышленники могут атаковать их приложения, и научиться писать более безопасный код, предотвращая распространенные уязвимости.10</>,
        <>Охотники за ошибками (Bug Bounty Hunters): Исследователи безопасности, участвующие в программах bug bounty и ищущие способы эффективного обнаружения и эксплуатации уязвимостей в реальных веб-приложениях.8</>,
        <>Преподаватели и инструкторы: Лица, использующие уязвимые приложения, такие как <Link href="https://www.example.com/dvwa" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">DVWA</Link> 12 или <Link href="https://owasp-juice.shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Juice Shop</Link> 10, для обучения студентов основам веб-безопасности.</>
      ]} />

      <H3>Предполагаемые знания:</H3>
      <P>
        Предполагается, что читатели обладают базовым пониманием принципов работы сетей (TCP/IP, DNS, HTTP), веб-технологий (HTML, JavaScript) и имеют опыт работы с операционными системами, в частности, с командной строкой Linux.32 Хотя глубокие знания программирования не являются обязательными, знакомство с Python или JavaScript будет полезным.
      </P>

      <H3>Цель руководства:</H3>
      <P>
        Цель данного руководства – предоставить читателям не только теоретические знания о распространенных веб-уязвимостях (таких как перечисленные в <Link href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Top 10</Link> 17), но и, что более важно, развить практические навыки их обнаружения и эксплуатации с использованием современных инструментов и методологий. Мы будем активно использовать такие платформы, как <Link href="https://portswigger.net/web-security" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">PortSwigger Web Security Academy</Link> 8, <Link href="https://tryhackme.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">TryHackMe</Link> 34, и <Link href="https://www.hackthebox.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Hack The Box</Link> 30, которые предлагают интерактивные лаборатории для отработки навыков в реалистичных условиях.
      </P>
    </ContentPageLayout>
  );
}
