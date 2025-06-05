
import Link from 'next/link';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const analysisItems = [
  {
    id: "authn",
    title: "Аутентификация",
    content: "Анализ процесса входа (формы, MFA), регистрации, восстановления пароля, \"запомнить меня\". Поиск слабых мест: предсказуемые учетные данные, отсутствие блокировки, небезопасная передача паролей."
  },
  {
    id: "session",
    title: "Управление Сессиями",
    content: <>Исследование отслеживания состояния пользователя (cookies, токены). Анализ генерации токенов (<Link href="https://portswigger.net/burp/documentation/desktop/tools/sequencer" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Sequencer</Link>), проверка флагов cookie (HttpOnly, Secure), уязвимости фиксации сессии, недостатки завершения сессии.</>
  },
  {
    id: "access-control",
    title: "Контроль Доступа",
    content: "Определение ролей пользователей и привилегий. Анализ применения ограничений доступа. Поиск возможностей вертикального и горизонтального повышения привилегий."
  },
  {
    id: "input-handling",
    title: "Обработка Пользовательского Ввода",
    content: "Идентификация всех точек ввода данных (URL-параметры, POST, HTTP-заголовки, cookies). Анализ обработки и проверки данных. Поиск векторов для инъекционных атак."
  }
];

export function AnalysisSection() {
  return (
    <section id="analysis" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            C. Анализ Основных Механизмов Приложения
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Глубокое изучение ключевых компонентов для выявления логических уязвимостей и слабых мест.
          </p>
        </div>
        <Accordion type="single" collapsible className="w-full max-w-3xl mx-auto space-y-3">
          {analysisItems.map((item) => (
            <AccordionItem value={item.id} key={item.id} className="border bg-card rounded-md shadow-sm hover:shadow-md transition-shadow">
              <AccordionTrigger className="bg-primary/10 hover:bg-primary/20 text-foreground p-4 font-semibold hover:no-underline">
                {item.title}
              </AccordionTrigger>
              <AccordionContent className="p-4 pt-2 text-muted-foreground bg-background rounded-b-md border border-t-0">
                {item.content}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </div>
    </section>
  );
}
