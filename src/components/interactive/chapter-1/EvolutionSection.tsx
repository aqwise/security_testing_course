
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function EvolutionSection() {
  return (
    <section id="evolution">
      <h2 className="text-2xl md:text-3xl font-bold text-center mb-2 text-primary/90">Эволюция Веба</h2>
      <p className="text-center text-muted-foreground mb-8 md:mb-12 max-w-3xl mx-auto">
        Веб прошел путь от простых статических сайтов до сложных, функциональных приложений. Эта трансформация кардинально изменила поток информации и требования к безопасности, создав новые векторы для атак.
      </p>
      <div className="grid md:grid-cols-2 gap-6 md:gap-8 items-start">
        <Card className="shadow-md hover:shadow-lg transition-shadow">
          <CardHeader>
            <CardTitle className="text-xl md:text-2xl font-semibold text-center text-foreground/90">Тогда: Статические Сайты</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center text-center space-y-3 md:space-y-4">
            <div className="text-5xl md:text-6xl">📄</div>
            <p className="font-semibold">Односторонний поток информации</p>
            <p className="text-muted-foreground text-sm">Сервер → Браузер</p>
            <p className="font-semibold">Статичный контент</p>
            <p className="text-muted-foreground text-sm">Одна и та же информация для всех</p>
            <p className="font-semibold">Отсутствие аутентификации</p>
            <p className="text-muted-foreground text-sm">Пользователи анонимны</p>
            <p className="font-semibold">Угрозы</p>
            <p className="text-muted-foreground text-sm">В основном, уязвимости веб-сервера</p>
          </CardContent>
        </Card>
        <Card className="shadow-md hover:shadow-lg transition-shadow border-2 border-primary/50">
          <CardHeader>
            <CardTitle className="text-xl md:text-2xl font-semibold text-center text-foreground/90">Сейчас: Веб-Приложения</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center text-center space-y-3 md:space-y-4">
            <div className="text-5xl md:text-6xl">🔄</div>
            <p className="font-semibold">Двусторонний поток информации</p>
            <p className="text-muted-foreground text-sm">Сервер ↔ Браузер</p>
            <p className="font-semibold">Динамический контент</p>
            <p className="text-muted-foreground text-sm">Персонализация для каждого пользователя</p>
            <p className="font-semibold">Аутентификация и сессии</p>
            <p className="text-muted-foreground text-sm">Обработка конфиденциальных данных</p>
            <p className="font-semibold">Угрозы</p>
            <p className="text-muted-foreground text-sm">Уникальные уязвимости в коде приложения</p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
