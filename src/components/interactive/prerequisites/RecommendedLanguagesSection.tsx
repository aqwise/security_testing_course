
import Link from 'next/link';
import { Card, CardContent } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";
const IconStyle = "mr-2 text-primary text-xl";

export function RecommendedLanguagesSection() {
  return (
    <section id="languages" className="py-16 md:py-24 bg-background">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            <span className={IconStyle}>📜</span>D. Рекомендуемые Языки
          </h2>
          <p className="mt-2 text-lg text-muted-foreground">
            Для написания скриптов и лучшего понимания кода.
          </p>
        </div>
        <Card className="max-w-3xl mx-auto">
          <CardContent className="p-6">
            <ul className="space-y-3 text-foreground/90">
              <li className="flex items-start">
                <span className={IconStyle}>🐍</span>
                <div>
                  <strong><Link href="https://www.python.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Python</Link>:</strong> Широко используется в ИБ для автоматизации, эксплойтов. Многие инструменты (sqlmap, Autorize) на Python. <Link href="https://www.python.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Python.org</Link>.
                </div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>✍️</span>
                <div>
                  <strong>JavaScript:</strong> Крайне важен для клиентских уязвимостей (XSS и др.) и анализа современных веб-приложений (SPA).
                </div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>💲</span> {/* Changed from $ to avoid confusion with shell prompt itself */}
                <div>
                  <strong>Bash/Shell Scripting:</strong> Полезен для автоматизации в Linux и работы с CLI-инструментами.
                </div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>🐘</span>
                <div>
                  <strong>(Опционально) <Link href="https://www.php.net/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>PHP</Link>, <Link href="https://ru.wikipedia.org/wiki/SQL" target="_blank" rel="noopener noreferrer" className={LinkStyle}>SQL</Link>:</strong> Базовое понимание синтаксиса поможет при анализе кода (DVWA) и SQL-инъекциях.
                </div>
              </li>
            </ul>
            <p className="mt-6 text-sm text-muted-foreground text-center">
              Убедитесь, что ваше окружение соответствует этим требованиям для максимальной пользы от изучения.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
