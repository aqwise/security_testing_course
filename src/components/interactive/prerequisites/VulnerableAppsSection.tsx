
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";
const IconStyle = "mr-2 text-primary text-xl"; 
const SubIconStyle = "mr-2 text-primary text-lg mt-1"; // Added mt-1 for alignment

export function VulnerableAppsSection() {
  return (
    <section id="vuln-apps" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            <span className={IconStyle}>🎯</span>C.1 Уязвимые Приложения для Практики
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-3xl mx-auto">
          <Card>
            <CardHeader>
              <CardTitle className="text-xl font-semibold text-primary flex items-start">
                <span className={SubIconStyle}>🐞</span>
                <Link href="http://www.dvwa.co.uk/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>
                  Damn Vulnerable Web Application (DVWA)
                </Link>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Классическое приложение PHP/MySQL. Репозиторий: <Link href="https://github.com/digininja/DVWA" target="_blank" rel="noopener noreferrer" className={LinkStyle}>digininja/DVWA</Link>. Docker: vulnerables/web-dvwa. Учетные данные: admin/password.
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-xl font-semibold text-primary flex items-start">
                <span className={SubIconStyle}>🧃</span>
                <Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>
                  OWASP Juice Shop
                </Link>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Современное приложение JavaScript (Node.js/Angular). GitHub: <Link href="https://github.com/juice-shop/juice-shop" target="_blank" rel="noopener noreferrer" className={LinkStyle}>juice-shop/juice-shop</Link>.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
