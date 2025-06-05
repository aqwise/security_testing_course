
import Link from 'next/link';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export function MappingSection() {
  return (
    <section id="mapping" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            B. Картирование Приложения
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Понимание структуры, функций и потоков данных приложения для выявления потенциальных векторов атак.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="bg-card p-6 rounded-xl shadow-lg border">
            <h3 className="text-xl font-semibold text-card-foreground mb-3">🖐️ Ручное Исследование</h3>
            <p className="text-muted-foreground">
              Систематический просмотр страниц и функций, взаимодействие с элементами. Использование Developer Tools для анализа HTML, JS, сетевых запросов, хранилища (Cookies, Local/Session Storage).
            </p>
          </div>
          <div className="bg-card p-6 rounded-xl shadow-lg border">
            <h3 className="text-xl font-semibold text-card-foreground mb-3">🤖 Автоматизированное Картирование (Spidering)</h3>
            <p className="text-muted-foreground">
              Использование <Link href="https://portswigger.net/burp/documentation/scanner/crawling" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Suite Spider</Link> или <Link href="https://www.zaproxy.org/docs/desktop/addons/spider/options/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP ZAP Spider</Link> для автоматического обхода ссылок. Важна правильная настройка области сканирования (scope).
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
