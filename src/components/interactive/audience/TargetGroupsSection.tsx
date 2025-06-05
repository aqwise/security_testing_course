
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';

interface TargetGroup {
  title: string;
  description: React.ReactNode;
}

const targetGroups: TargetGroup[] = [
  {
    title: 'Начинающие специалисты по кибербезопасности',
    description: 'Студенты и энтузиасты, делающие первые шаги в ИБ, желающие получить практический опыт в поиске веб-уязвимостей.',
  },
  {
    title: 'Тестировщики на проникновение (Penetration Testers)',
    description: (
      <>
        Специалисты, стремящиеся углубить знания в веб-пентестинге, освоить новые техники и подготовиться к сертификациям, например,{' '}
        <Link href="https://portswigger.net/web-security/certification" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">
          Burp Suite Certified Practitioner
        </Link>
        .
      </>
    ),
  },
  {
    title: 'Аналитики безопасности (Security Analysts)',
    description: 'Специалисты Blue Team и SOC, которым необходимо понимать векторы атак для эффективного обнаружения, анализа и реагирования на инциденты.',
  },
  {
    title: 'Веб-разработчики',
    description: 'Программисты, желающие понять, как атакуют их приложения, и научиться писать более безопасный код.',
  },
  {
    title: 'Охотники за ошибками (Bug Bounty Hunters)',
    description: 'Исследователи безопасности, участвующие в программах bug bounty, ищущие способы эффективного обнаружения уязвимостей.',
  },
  {
    title: 'Преподаватели и инструкторы',
    description: (
      <>
        Лица, использующие уязвимые приложения ({' '}
        <Link href="http://www.dvwa.co.uk/" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">
          DVWA
        </Link>
        ,{' '}
        <Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">
          OWASP Juice Shop
        </Link>
        ) для обучения студентов.
      </>
    ),
  },
];

export function TargetGroupsSection() {
  return (
    <section id="target-groups" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            Основная аудитория включает:
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {targetGroups.map((group) => (
            <Card key={group.title} className="bg-background flex flex-col shadow-lg hover:shadow-xl transition-shadow duration-300 rounded-xl border">
              <CardHeader>
                <CardTitle className="text-xl font-semibold text-foreground/90">{group.title}</CardTitle>
              </CardHeader>
              <CardContent className="flex-grow">
                <p className="text-muted-foreground">{group.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
