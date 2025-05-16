import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { Users, Target, BookOpen, Laptop, Code } from 'lucide-react';

export default function AudiencePage() {
  return (
    <ContentPageLayout
      title="III. Пересмотренная Целевая Аудитория"
      imageUrl="https://placehold.co/600x400.png"
      imageAlt="Diverse group of people learning"
      imageAiHint="diverse learning"
    >
      <P>
        Данное руководство предназначено для широкого круга лиц, заинтересованных в изучении и совершенствовании практических навыков тестирования безопасности веб-приложений. Основная аудитория включает:
      </P>

      <Ul items={[
        "Начинающие специалисты по кибербезопасности: Студенты и энтузиасты.",
        "Тестировщики на проникновение (Penetration Testers): Специалисты, стремящиеся углубить знания.",
        "Аналитики безопасности (Security Analysts): Специалисты Blue Team и SOC.",
        "Веб-разработчики: Программисты, желающие писать более безопасный код.",
        "Охотники за ошибками (Bug Bounty Hunters): Исследователи безопасности.",
        "Преподаватели и инструкторы: Использующие уязвимые приложения для обучения."
      ]} />

      <div className="mt-8 p-6 bg-primary/10 rounded-lg shadow-inner">
        <div className="flex items-center text-primary mb-3">
          <Laptop className="h-6 w-6 mr-2" />
          <h4 className="text-xl font-semibold">Предполагаемые знания:</h4>
        </div>
        <P>
          Предполагается, что читатели обладают базовым пониманием принципов работы сетей (TCP/IP, DNS, HTTP), веб-технологий (HTML, JavaScript) и имеют опыт работы с операционными системами, в частности, с командной строкой Linux. Хотя глубокие знания программирования не являются обязательными, знакомство с Python или JavaScript будет полезным.
        </P>
      </div>

      <div className="mt-8 p-6 bg-accent/10 rounded-lg shadow-inner">
        <div className="flex items-center text-accent-foreground mb-3">
          <Target className="h-6 w-6 mr-2" />
          <h4 className="text-xl font-semibold">Цель руководства:</h4>
        </div>
        <P>
          Цель данного руководства – предоставить читателям не только теоретические знания о распространенных веб-уязвимостях (таких как перечисленные в OWASP Top 10), но и, что более важно, развить практические навыки их обнаружения и эксплуатации с использованием современных инструментов и методологий. Мы будем активно использовать такие платформы, как PortSwigger Web Security Academy, TryHackMe, и Hack The Box, которые предлагают интерактивные лаборатории для отработки навыков в реалистичных условиях.
        </P>
      </div>
    </ContentPageLayout>
  );
}
