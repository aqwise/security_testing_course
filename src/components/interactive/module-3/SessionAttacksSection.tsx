
import Link from 'next/link';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sessionAttackItems = [
  {
    id: "token-analysis",
    title: "Анализ Токенов Сессии",
    content: (
      <>
        <p className="text-muted-foreground mb-2"><strong>Предсказуемость:</strong> Использование <Link href="https://portswigger.net/burp/documentation/desktop/tools/sequencer" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Sequencer</Link> для анализа случайности и энтропии токенов. Недостаточная случайность позволяет угадать токен.</p>
        <p className="text-muted-foreground mb-2"><strong>Структура Токена:</strong> Анализ (<Link href="https://portswigger.net/burp/documentation/desktop/tools/decoder" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Decoder</Link>) на наличие осмысленной информации (имя, время, привилегии), которую можно изменить.</p>
        <p className="text-muted-foreground"><strong>JSON Web Tokens (JWT):</strong> Атаки на JWT (изменение payload, атаки на подпись - alg:none, слабые секреты). Инструмент: <Link href="https://portswigger.net/bappstore/jwt-editor" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp JWT Editor</Link>.</p>
      </>
    )
  },
  {
    id: "insecure-handling",
    title: "Небезопасное Обращение с Токенами",
    content: (
      <>
        <p className="text-muted-foreground mb-2"><strong>Передача по HTTP:</strong> Отсутствие флага <Link href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#secure_and_httponly_cookies" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Secure</Link> у cookie позволяет перехватить токен.</p>
        <p className="text-muted-foreground"><strong>Доступность для Скриптов:</strong> Отсутствие флага <Link href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#secure_and_httponly_cookies" target="_blank" rel="noopener noreferrer" className={LinkStyle}>HttpOnly</Link> делает токен уязвимым для кражи через XSS.</p>
      </>
    )
  },
  {
    id: "fixation-termination",
    title: "Фиксация и Завершение Сессии",
    content: (
      <>
        <p className="text-muted-foreground mb-2"><strong>Фиксация Сессии (Session Fixation):</strong> Атакующий заставляет жертву использовать известный ему ID сессии. Проверяется, генерируется ли новый ID сессии после входа.</p>
        <p className="text-muted-foreground"><strong>Недостатки Завершения Сессии:</strong> Проверка, инвалидируется ли сессия на сервере после выхода или по таймауту.</p>
      </>
    )
  }
];

export function SessionAttacksSection() {
  return (
    <section id="session-attacks" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            B. Атака на Механизмы Управления Сессиями
          </h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">
            Уязвимости в управлении состоянием пользователя после аутентификации могут позволить атакующему выдать себя за легитимного пользователя.
          </p>
        </div>
        <Accordion type="single" collapsible className="w-full max-w-3xl mx-auto space-y-3">
          {sessionAttackItems.map((item) => (
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
