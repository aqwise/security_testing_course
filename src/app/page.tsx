import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import Image from "next/image";
import { ArrowRightCircle, CheckCircle2 } from "lucide-react";

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
              <p>
                Добро пожаловать в обновленное руководство по практическому тестированию безопасности веб-приложений. В современном цифровом мире веб-приложения являются неотъемлемой частью бизнеса, государственных услуг и повседневной жизни. Однако они также представляют собой значительную поверхность атаки, и уязвимости могут привести к серьезным последствиям, включая утечки данных, финансовые потери и компрометацию систем. Понимание и умение выявлять и эксплуатировать эти уязвимости – критически важные навыки для любого специалиста по кибербезопасности.
              </p>
              <p>
                Данное руководство придерживается практического подхода, сочетая теоретические основы с интенсивными практическими упражнениями. Мы будем использовать стандартные отраслевые инструменты и специально созданные уязвимые веб-приложения, чтобы вы могли отточить свои навыки в безопасной и контролируемой среде.
              </p>
              <div className="space-y-3 text-foreground/80">
                <h3 className="text-xl font-medium text-accent-foreground mb-3">Ключевые ресурсы:</h3>
                {[
                  "PortSwigger Web Security Academy",
                  "OWASP Juice Shop",
                  "Damn Vulnerable Web Application (DVWA)"
                ].map(item => (
                  <div key={item} className="flex items-start">
                    <CheckCircle2 className="h-6 w-6 text-accent mr-3 mt-1 flex-shrink-0" />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
              <p>
                Основополагающим текстом является "The Web Application Hacker's Handbook, 2nd Edition" (WAHH2). Несмотря на публикацию в 2011 году, фундаментальные принципы остаются актуальными. Однако ландшафт веб-безопасности постоянно меняется, появляются новые технологии и векторы атак. Современные ресурсы, такие как PortSwigger Web Security Academy, постоянно обновляются.
              </p>
              <p>
                Это руководство призвано стать вашим надежным спутником в освоении практических навыков, необходимых для навигации в этой динамичной области. Мы начнем с основ и постепенно перейдем к более сложным техникам, всегда подкрепляя теорию практикой.
              </p>
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
