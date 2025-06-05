
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function CoreProblemSection() {
  return (
    <section id="core-problem">
      <h2 className="text-2xl md:text-3xl font-bold text-center mb-2 text-primary/90">Ключевая Проблема Безопасности</h2>
      <p className="text-center text-muted-foreground mb-8 md:mb-12 max-w-3xl mx-auto">
        В основе большинства уязвимостей лежит одна фундаментальная проблема: приложение должно доверять данным, поступающим от клиента, который находится вне его контроля. Злоумышленник может отправить любые данные, чтобы обмануть логику приложения.
      </p>
      <Card className="p-6 md:p-8 shadow-md">
        <CardContent className="pt-6">
          <div className="flex flex-col md:flex-row items-center justify-center gap-6 md:gap-8">
            <div className="text-center">
              <div className="text-5xl md:text-6xl">👤</div>
              <p className="font-bold mt-2 text-foreground/90">Злоумышленник</p>
              <p className="text-xs md:text-sm text-muted-foreground">Контролирует клиент</p>
            </div>
            <div className="text-2xl md:text-3xl text-destructive font-mono animate-pulse w-full md:w-auto text-center break-all">
              → &lbrace; "price": 0.01 &rbrace; →<br className="md:hidden"/>
              → ' OR 1=1; -- →
            </div>
            <div className="text-center">
              <div className="text-5xl md:text-6xl">💻</div>
              <p className="font-bold mt-2 text-foreground/90">Сервер Приложения</p>
              <p className="text-xs md:text-sm text-muted-foreground">Должен обрабатывать ввод</p>
            </div>
          </div>
          <div className="mt-6 md:mt-8">
            <h3 className="text-lg md:text-xl font-semibold text-center mb-3 md:mb-4 text-foreground/80">Проявления проблемы:</h3>
            <ul className="list-disc list-inside space-y-1 md:space-y-2 text-muted-foreground max-w-2xl mx-auto text-sm md:text-base">
              <li>Пользователи могут изменять любые данные, передаваемые с клиента: параметры, cookie, HTTP-заголовки.</li>
              <li>Любая валидация на стороне клиента может быть легко обойдена.</li>
              <li>Пользователи могут отправлять запросы в произвольной последовательности, нарушая логику приложения.</li>
              <li>Для атак могут использоваться не только браузеры, но и специализированные инструменты.</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
