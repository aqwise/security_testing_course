
import Link from 'next/link';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export function ReconnaissanceSection() {
  return (
    <section id="reconnaissance" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            A. Пассивная и Активная Разведка
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Разведка — это сбор информации. Пассивная не взаимодействует с целью напрямую, активная — использует запросы к приложению.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="bg-background p-6 rounded-xl shadow-lg border">
            <h3 className="text-xl font-semibold text-foreground mb-3">🕵️ Пассивная Разведка</h3>
            <p className="text-muted-foreground mb-4">
              Сбор информации из общедоступных источников без прямого контакта с целевой системой.
            </p>
            <ul className="list-disc list-inside space-y-2 text-muted-foreground">
              <li>Поисковые системы (<Link href="https://www.exploit-db.com/google-hacking-database" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Google Dorking</Link>)</li>
              <li><Link href="https://www.whois.com/whois/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>WHOIS</Link>, DNS-записи (<Link href="https://linux.die.net/man/1/nslookup" target="_blank" rel="noopener noreferrer" className={LinkStyle}>nslookup</Link>, <Link href="https://linux.die.net/man/1/dig" target="_blank" rel="noopener noreferrer" className={LinkStyle}>dig</Link>)</li>
              <li>Социальные сети, <Link href="https://github.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>GitHub</Link>, архивы веб-сайтов</li>
              <li>Утечки данных (<Link href="https://haveibeenpwned.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Have I Been Pwned</Link>)</li>
            </ul>
            <p className="mt-3 text-sm text-muted-foreground/80">Цель: информация об инфраструктуре, технологиях, пользователях.</p>
          </div>
          <div className="bg-background p-6 rounded-xl shadow-lg border">
            <h3 className="text-xl font-semibold text-foreground mb-3">📡 Активная Разведка</h3>
            <p className="text-muted-foreground mb-4">
              Взаимодействие с целью для получения информации. Требует осторожности.
            </p>
            <ul className="list-disc list-inside space-y-2 text-muted-foreground">
              <li>Сканирование портов (<Link href="https://nmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Nmap</Link>)</li>
              <li>Определение технологий (<Link href="https://www.wappalyzer.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Wappalyzer</Link>, <Link href="https://builtwith.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>BuiltWith</Link>)</li>
              <li>Анализ HTTP-заголовков, robots.txt, sitemap.xml</li>
            </ul>
            <p className="mt-3 text-sm text-muted-foreground/80">Цель: технические детали, версии ПО, структура.</p>
          </div>
        </div>
      </div>
    </section>
  );
}
