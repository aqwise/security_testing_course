
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function EvolutionSection() {
  return (
    <section id="evolution" className="py-12 md:py-16 bg-background">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-10 md:mb-12">
          <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-foreground">
            <span className="mr-2 text-primary text-2xl md:text-3xl align-middle">🚀</span>
            Эволюция веб-безопасности
          </h2>
        </div>
        <Card className="max-w-3xl mx-auto shadow-lg">
          <CardContent className="p-6 md:p-8">
            <p className="text-md md:text-lg text-foreground/90 leading-relaxed mb-4">
              Ландшафт веб-безопасности постоянно меняется. Появляются новые технологии, фреймворки и, соответственно, новые векторы атак и классы уязвимостей.
            </p>
            <h4 className="text-lg font-semibold text-foreground/80 mb-2">Ключевые изменения и современные угрозы включают:</h4>
            <ul className="list-disc list-inside space-y-1 text-muted-foreground">
              <li>Новые технологии: HTML5, REST API, WebSocket, облачные сервисы, LLM.</li>
              <li>
                Атаки на API (<Link href="https://owasp.org/www-project-api-security/" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">OWASP API Security Top 10</Link>).
              </li>
              <li>Небезопасная десериализация.</li>
              <li>Атаки на JWT (JSON Web Tokens).</li>
              <li>Уязвимости в облачных и контейнеризированных средах.</li>
            </ul>
            <p className="mt-4 text-md md:text-lg text-foreground/90 leading-relaxed">
              Современные ресурсы, такие как <Link href="https://portswigger.net/web-security" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">PortSwigger Web Security Academy</Link> и уязвимые приложения вроде <Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">OWASP Juice Shop</Link>, активно отражают эти изменения.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
