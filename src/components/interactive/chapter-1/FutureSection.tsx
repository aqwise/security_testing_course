
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function FutureSection() {
  return (
    <section id="future">
      <h2 className="text-2xl md:text-3xl font-bold text-center mb-2 text-primary/90">Будущее Безопасности Веб-Приложений</h2>
      <p className="text-center text-muted-foreground mb-8 md:mb-12 max-w-3xl mx-auto">
        Ландшафт угроз постоянно меняется. Хотя старые уязвимости постепенно устраняются, появляются новые, а некоторые "классические" проблемы, связанные с бизнес-логикой, остаются актуальными как никогда.
      </p>
      <div className="grid md:grid-cols-2 gap-6 md:gap-8">
        <Card className="shadow-md">
          <CardHeader>
            <CardTitle className="text-lg md:text-xl font-semibold text-foreground/90">Наблюдаемые Тенденции</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 md:space-y-3 list-inside list-disc text-muted-foreground text-sm md:text-base">
              <li><span className="font-semibold text-foreground/80">Смещение фокуса на клиента:</span> Атаки все чаще нацелены не на сервер, а на других пользователей приложения (XSS, CSRF).</li>
              <li><span className="font-semibold text-foreground/80">Усложнение уязвимостей:</span> Простые эксплойты встречаются реже, злоумышленники используют более тонкие и сложные методы.</li>
              <li><span className="font-semibold text-foreground/80">Web 2.0 и Облака:</span> Технологии, такие как AJAX, API, и облачные сервисы, создают новые векторы атак и размывают периметр организации.</li>
            </ul>
          </CardContent>
        </Card>
        <Card className="shadow-md">
          <CardHeader>
            <CardTitle className="text-lg md:text-xl font-semibold text-foreground/90">Что Остается Неизменным?</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 md:space-y-3 list-inside list-disc text-muted-foreground text-sm md:text-base">
              <li><span className="font-semibold text-foreground/80">Дефекты бизнес-логики:</span> Ошибки в логике приложения, которые позволяют обойти правила, остаются распространенной и серьезной проблемой.</li>
              <li><span className="font-semibold text-foreground/80">Проблемы с контролем доступа:</span> Некорректная проверка прав пользователей по-прежнему позволяет получать несанкционированный доступ к данным.</li>
              <li><span className="font-semibold text-foreground/80">Человеческий фактор:</span> Недостаток знаний и ресурсов остается ключевым фактором, приводящим к появлению уязвимостей.</li>
            </ul>
          </CardContent>
        </Card>
      </div>
      <p className="mt-6 md:mt-8 text-center text-md md:text-lg text-foreground/80 max-w-3xl mx-auto">
        Битва за безопасность веба далека от завершения. Это постоянный процесс обучения, адаптации и внедрения защитных механизмов на всех уровнях разработки.
      </p>
    </section>
  );
}
