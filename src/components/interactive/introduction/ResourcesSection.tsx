
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";
const IconStyle = "mr-2 text-primary text-lg align-middle";

interface Resource {
  title: string;
  description: React.ReactNode;
  link?: string;
  icon: string;
}

const resources: Resource[] = [
  {
    title: "The Web Application Hacker's Handbook, 2nd Edition (WAHH2)",
    description: (
      <>
        Основополагающий текст (ISBN: 978-1118026472) от Дафидда Статтарда и Маркуса Пинто. Несмотря на публикацию в 2011 году, фундаментальные принципы и методологии остаются актуальными. <Link href="https://edu.anarcho-copy.org/Against%20Security%20-%20Self%20Security/Dafydd%20Stuttard,%20Marcus%20Pinto%20-%20The%20web%20application%20hacker's%20handbook_%20finding%20and%20exploiting%20security%20flaws-Wiley%20(2011).pdf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Ссылка на PDF (если доступно)</Link>.
      </>
    ),
    icon: '📖',
  },
  {
    title: 'PortSwigger Web Security Academy',
    description: 'Постоянно обновляемый центр онлайн-обучения от создателей Burp Suite. Содержит материалы по новейшим угрозам и техникам атак.',
    link: 'https://portswigger.net/web-security',
    icon: '🎓',
  },
  {
    title: 'OWASP Juice Shop',
    description: 'Современное уязвимое приложение на JavaScript-стеке (Node.js, Angular), отражающее актуальные архитектуры и уязвимости.',
    link: 'https://owasp.org/www-project-juice-shop/',
    icon: '🧃',
  },
  {
    title: 'Damn Vulnerable Web Application (DVWA)',
    description: 'Классическое уязвимое приложение, предоставляющее реалистичные сценарии для отработки базовых атак.',
    link: 'http://www.dvwa.co.uk/',
    icon: '🐞',
  },
];

export function ResourcesSection() {
  return (
    <section id="resources" className="py-12 md:py-16">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-10 md:mb-12">
          <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-foreground">
            <span className={IconStyle}>📚</span>
            Ключевые ресурсы и материалы
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8 max-w-4xl mx-auto">
          {resources.map((resource) => (
            <Card key={resource.title} className="shadow-lg flex flex-col">
              <CardHeader>
                <CardTitle className="text-lg md:text-xl font-semibold text-primary flex items-start">
                  <span className="mr-2 text-2xl mt-1">{resource.icon}</span>
                  {resource.link ? (
                    <Link href={resource.link} target="_blank" rel="noopener noreferrer" className={LinkStyle}>
                      {resource.title}
                    </Link>
                  ) : (
                    resource.title
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="flex-grow">
                <p className="text-muted-foreground">{resource.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}

    