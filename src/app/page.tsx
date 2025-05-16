import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CheckCircle2 } from "lucide-react";
import { P } from "@/components/content/ContentPageLayout";
import Link from "next/link";

export default function IntroPage() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 md:p-8 bg-gradient-to-br from-background to-secondary/30">
      <Card className="w-full max-w-4xl shadow-2xl overflow-hidden rounded-xl">
        <div className="md:flex">
          <div className="md:w-1/3 bg-primary/10 p-8 flex flex-col items-center justify-center">
            <ShieldCheckIcon className="w-24 h-24 text-primary mb-6" />
            <div className="text-center">
              <h1 className="text-3xl md:text-4xl font-bold text-primary tracking-tight">
                Безопасность Веб-Приложений
              </h1>
              <p className="text-lg text-foreground/80 mt-2">На Основе WAHH2</p>
              <hr className="my-6 border-accent w-1/4 mx-auto" />
              <p className="text-sm text-muted-foreground">Обновленное Издание</p>
            </div>
          </div>
          
          <div className="md:w-2/3 p-8 md:p-12">
            <CardHeader className="px-0 pt-0">
              <CardTitle className="text-3xl font-semibold text-foreground">I. Введение</CardTitle>
            </CardHeader>
            <CardContent className="px-0 text-base md:text-lg text-foreground/90 space-y-6">
              <P>
                Добро пожаловать в обновленное руководство по практическому тестированию безопасности веб-приложений. В современном цифровом мире веб-приложения являются неотъемлемой частью бизнеса, государственных услуг и повседневной жизни. Однако они также представляют собой значительную поверхность атаки, и уязвимости могут привести к серьезным последствиям, включая утечки данных, финансовые потери и компрометацию систем.1 Понимание и умение выявлять и эксплуатировать эти уязвимости – критически важные навыки для любого специалиста по кибербезопасности.
              </P>
              <P>
                Данное руководство придерживается практического подхода, сочетая теоретические основы с интенсивными практическими упражнениями. Мы будем использовать стандартные отраслевые инструменты и специально созданные уязвимые веб-приложения, чтобы вы могли отточить свои навыки в безопасной и контролируемой среде. Среди ключевых ресурсов, на которые мы будем опираться, – <Link href="https://portswigger.net/web-security" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">PortSwigger Web Security Academy</Link> 8, постоянно обновляемый центр онлайн-обучения, и такие приложения, как <Link href="https://owasp-juice.shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Juice Shop</Link> 10 и <Link href="https://www.example.com/dvwa" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Damn Vulnerable Web Application (DVWA)</Link> 12 (здесь предполагается, что для DVWA должна быть ссылка, если нет, текст "Damn Vulnerable Web Application (DVWA) 12" останется без ссылки), которые предоставляют реалистичные сценарии для отработки атак.
              </P>
              <P>
                Основополагающим текстом в области тестирования веб-приложений является книга "The Web Application Hacker's Handbook, 2nd Edition" (WAHH2) (ISBN: 978-1118026472) 6, написанная Дафиддом Статтардом (Dafydd Stuttard) и Маркусом Пинто (Marcus Pinto). Дафидд Статтард также является создателем Burp Suite и основателем PortSwigger.6 Несмотря на то, что книга была опубликована в 2011 году 6, изложенные в ней фундаментальные принципы и методологии тестирования остаются актуальными и крайне ценными для понимания основ веб-безопасности. <Link href="https://archive.org/details/TheWebApplicationHackerSHandbookFindingAndExploitingSecurityFlaws_201805/mode/2up" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">WAHH2</Link> 6 заложила основу для многих современных подходов к пентестингу веб-приложений.
              </P>
              <P>
                Однако ландшафт веб-безопасности постоянно меняется. Появляются новые технологии (HTML5, REST API, WebSocket, облачные сервисы, LLM), фреймворки и, соответственно, новые векторы атак и классы уязвимостей.7 Такие ресурсы, как <Link href="https://portswigger.net/web-security" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">PortSwigger Web Security Academy</Link> 8, постоянно обновляются, добавляя материалы по новейшим угрозам, таким как атаки на API 15, небезопасная десериализация 15, атаки на JWT 15 и уязвимости в облачных и контейнеризированных средах.20 Современные уязвимые приложения, такие как <Link href="https://github.com/juice-shop/juice-shop" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">OWASP Juice Shop</Link> 22, построенные на JavaScript-стеке (Node.js, Angular) 24, отражают эти изменения и предоставляют платформу для изучения уязвимостей, характерных для современных архитектур.
              </P>
              <P>
                Это руководство призвано стать вашим надежным спутником в освоении практических навыков, необходимых для навигации в этой динамичной области. Мы начнем с основ и постепенно перейдем к более сложным техникам, всегда подкрепляя теорию практикой.
              </P>
            </CardContent>
          </div>
        </div>
      </Card>
    </div>
  );
}

function ShieldCheckIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  )
}
