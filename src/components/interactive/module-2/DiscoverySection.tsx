
import Link from 'next/link';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export function DiscoverySection() {
  return (
    <section id="discovery" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            B.1 Обнаружение Скрытого Контента и Поддоменов
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Поиск ресурсов, не связанных напрямую с видимыми страницами, и идентификация поддоменов для расширения поверхности атаки.
          </p>
        </div>
        <div className="space-y-8">
          <div>
            <h3 className="text-2xl font-semibold text-foreground mb-4">📄 Обнаружение Скрытого Контента</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">Перебор по словарю</h4>
                <p className="text-sm text-muted-foreground">
                  Инструменты: <Link href="https://tools.kali.org/information-gathering/dirb" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Dirb</Link>, <Link href="https://github.com/OJ/gobuster" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Gobuster</Link>, <Link href="https://github.com/ffuf/ffuf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ffuf</Link>, Burp Content Discovery. Списки: <Link href="https://github.com/danielmiessler/SecLists" target="_blank" rel="noopener noreferrer" className={LinkStyle}>SecLists</Link>. Цель: админ-панели, конфиги, бэкапы.
                </p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">Анализ JavaScript</h4>
                <p className="text-sm text-muted-foreground">
                  Изучение клиентского кода на предмет скрытых API-путей, комментариев, переменных.
                </p>
              </div>
            </div>
          </div>
          <div>
            <h3 className="text-2xl font-semibold text-foreground mb-4">🌐 Обнаружение Поддоменов</h3>
            <div className="bg-background/70 p-4 rounded-lg border">
              <p className="text-muted-foreground">
                Инструменты: <Link href="https://github.com/aboul3la/Sublist3r" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Sublist3r</Link>, <Link href="https://github.com/OWASP/Amass" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Amass</Link>. Техники: DNS-запросы (AXFR), <Link href="https://certificate.transparency.dev/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>CT logs</Link>, поисковые системы. Цель: найти тестовые или устаревшие версии приложений.
              </p>
            </div>
          </div>
          <p className="text-center text-md text-muted-foreground/80 italic">
            Автоматизированные инструменты ускоряют процесс, но их результаты всегда требуют ручной проверки и анализа.
          </p>
        </div>
      </div>
    </section>
  );
}
