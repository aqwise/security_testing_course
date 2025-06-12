
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";
const IconStyle = "mr-2 text-primary text-xl"; // Adjusted size to xl for better visibility

export function KnowledgeSection() {
  return (
    <section id="knowledge" className="py-16 md:py-24 bg-background">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            <span className={IconStyle}>🧠</span>A. Концептуальные Знания
          </h2>
        </div>
        <Card className="max-w-3xl mx-auto">
          <CardContent className="p-6">
            <ul className="space-y-3 text-foreground/90">
              <li className="flex items-start">
                <span className={IconStyle}>🌐</span>
                <div>
                  <strong>Основы веб-технологий:</strong> Понимание клиент-серверной архитектуры, различий front-end/back-end. Знание HTML, CSS, JavaScript.
                </div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>🔗</span>
                <div>
                  <strong>Протокол HTTP/HTTPS:</strong> Структура запросов/ответов, методы (GET, POST и др.), заголовки (Host, User-Agent, Cookie и т.д.), коды состояния, сессии, cookie. Ресурс: <Link href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className={LinkStyle}>TryHackMe "HTTP in Detail"</Link>.
                </div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>💻</span>
                <div>
                  <strong>Основы сетей:</strong> Базовое понимание TCP/IP, DNS, IP-адресации, портов, межсетевых экранов, прокси.
                </div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>🛡️</span>
                <div>
                  <strong>Осведомленность об уязвимостях:</strong> Общее представление о классах уязвимостей (инъекции, XSS, IDOR, CSRF) из <Link href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP Top 10</Link>.
                </div>
              </li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

