
import Link from 'next/link';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const accessControlAttackItems = [
  {
    id: "vertical-privesc",
    title: "Вертикальное Повышение Привилегий",
    content: (
      <p className="text-muted-foreground">
        Получение доступа к функциям для более привилегированных пользователей (например, администраторов). Поиск незащищенной функциональности (прямой доступ к URL), манипуляция параметрами, обход на уровне платформы/метода.
      </p>
    )
  },
  {
    id: "horizontal-idor",
    title: "Горизонтальное Повышение Привилегий и IDOR",
    content: (
      <>
        <p className="text-muted-foreground mb-2"><strong>Горизонтальное:</strong> Доступ к данным других пользователей того же уровня привилегий.</p>
        <p className="text-muted-foreground"><strong>Insecure Direct Object References (IDOR):</strong> Приложение использует идентификатор объекта от пользователя для прямого доступа к ресурсу без проверки прав. Атакующий подменяет ID. Тестирование требует нескольких учетных записей. Инструмент: <Link href="https://portswigger.net/bappstore/f9bb5f0207e34820b83d49d70958ac94" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Autorize</Link>.</p>
      </>
    )
  },
  {
    id: "other-access-vulns",
    title: "Другие Уязвимости Контроля Доступа",
    content: (
      <p className="text-muted-foreground">
        Уязвимости в многошаговых процессах, контроль доступа на основе Referer или геолокации (обход через прокси/VPN).
      </p>
    )
  }
];

export function AccessControlAttacksSection() {
  return (
    <section id="access-control-attacks" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            C. Атака на Механизмы Контроля Доступа
          </h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">
            Контроль доступа определяет, что пользователь может делать после аутентификации. Уязвимости здесь часто критичны и входят в <Link href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP Top 10</Link>.
          </p>
        </div>
        <Accordion type="single" collapsible className="w-full max-w-3xl mx-auto space-y-3">
          {accessControlAttackItems.map((item) => (
            <AccordionItem value={item.id} key={item.id} className="border bg-card rounded-md shadow-sm hover:shadow-md transition-shadow">
              <AccordionTrigger className="bg-primary/10 hover:bg-primary/20 text-foreground p-4 font-semibold hover:no-underline">
                {item.title}
              </AccordionTrigger>
              <AccordionContent className="p-4 pt-2 bg-background rounded-b-md border border-t-0">
                {item.content}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </div>
    </section>
  );
}
