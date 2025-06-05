
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';

interface ArsenalItem {
  title: string;
  description: string;
  link: string;
  icon: string; // Emoji or character
}

const arsenalItems: ArsenalItem[] = [
  {
    title: 'Burp Suite',
    description: 'Промышленный стандарт для тестирования безопасности веб-приложений. Используется для перехвата, анализа и модификации трафика.',
    link: 'https://portswigger.net/burp',
    icon: '🔧',
  },
  {
    title: 'OWASP Juice Shop',
    description: 'Современное, но намеренно уязвимое веб-приложение, идеально подходящее для отработки поиска уязвимостей из списка OWASP Top 10.',
    link: 'https://owasp.org/www-project-juice-shop/',
    icon: '🎯',
  },
  {
    title: 'Damn Vulnerable Web Application (DVWA)',
    description: 'Классическое уязвимое приложение для изучения конкретных атак (SQLi, XSS, CSRF) с настраиваемыми уровнями сложности.',
    link: 'http://www.dvwa.co.uk/',
    icon: '🎯',
  },
  {
    title: 'PortSwigger Web Security Academy',
    description: 'Бесплатная онлайн-платформа от создателей Burp Suite с интерактивными лабораториями по всем аспектам веб-безопасности.',
    link: 'https://portswigger.net/web-security',
    icon: '🎓',
  },
  {
    title: 'TryHackMe',
    description: 'Игровая платформа для обучения кибербезопасности через практические "комнаты" и "пути обучения".',
    link: 'https://tryhackme.com/',
    icon: '🎓',
  },
  {
    title: 'Docker',
    description: 'Платформа контейнеризации, которая позволяет быстро и легко разворачивать уязвимые приложения, такие как Juice Shop, в изолированной среде.',
    link: 'https://www.docker.com/',
    icon: '🐳', // Changed to a more common Docker emoji
  },
];

export function ArsenalSection() {
  return (
    <section id="arsenal" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Ваш арсенал для практики</h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-slate-600 dark:text-slate-400">
            Ключевые инструменты и платформы, которые понадобятся вам для настройки лабораторной среды и отработки практических навыков.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {arsenalItems.map((item) => (
            <Card key={item.title} className="bg-card text-card-foreground flex flex-col shadow-lg hover:shadow-xl transition-shadow duration-300 rounded-xl border border-border">
              <CardHeader>
                <CardTitle className="text-xl font-semibold text-foreground flex items-center">
                  <span className="mr-2 text-2xl">{item.icon}</span>
                  {item.title}
                </CardTitle>
              </CardHeader>
              <CardContent className="flex-grow">
                <p className="text-muted-foreground">{item.description}</p>
              </CardContent>
              <div className="p-6 pt-0">
                <Link
                  href={item.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-block text-primary font-semibold hover:text-primary/80"
                >
                  Узнать больше →
                </Link>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
