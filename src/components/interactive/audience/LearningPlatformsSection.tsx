
import Link from 'next/link';

interface Platform {
  name: string;
  url: string;
  gridClasses?: string;
}

const platforms: Platform[] = [
  { name: 'PortSwigger Web Security Academy', url: 'https://portswigger.net/web-security' },
  { name: 'TryHackMe', url: 'https://tryhackme.com/' },
  { name: 'Hack The Box', url: 'https://www.hackthebox.com/' },
  { 
    name: 'DVWA', 
    url: 'http://www.dvwa.co.uk/',
    gridClasses: "sm:col-start-auto lg:col-start-1 lg:col-span-1 sm:col-span-2"
  },
  { 
    name: 'OWASP Juice Shop', 
    url: 'https://owasp.org/www-project-juice-shop/',
    gridClasses: "sm:col-span-2 lg:col-span-2"
  },
];

export function LearningPlatformsSection() {
  return (
    <section id="platforms" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            Активно используемые учебные платформы
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Для отработки навыков в реалистичных условиях мы будем использовать следующие интерактивные платформы:
          </p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-4xl mx-auto">
          {platforms.map((platform) => (
            <Link
              key={platform.name}
              href={platform.url}
              target="_blank"
              rel="noopener noreferrer"
              className={`block bg-primary hover:bg-primary/90 text-primary-foreground p-6 rounded-lg shadow-md transition-transform hover:scale-105 text-center ${platform.gridClasses || ''}`}
            >
              <h4 className="text-xl font-semibold">{platform.name}</h4>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}
