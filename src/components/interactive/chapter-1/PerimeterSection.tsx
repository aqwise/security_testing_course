
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function PerimeterSection() {
  return (
    <section id="perimeter">
      <h2 className="text-2xl md:text-3xl font-bold text-center mb-2 text-primary/90">Смещение Периметра Безопасности</h2>
      <p className="text-center text-muted-foreground mb-8 md:mb-12 max-w-3xl mx-auto">
        Веб-приложения кардинально изменили ландшафт безопасности. Раньше основной защитой был сетевой периметр. Теперь же само приложение стало частью этого периметра, открывая злоумышленникам прямой путь к критически важным внутренним системам.
      </p>
      <div className="grid md:grid-cols-2 gap-6 md:gap-8 items-center">
        <Card className="shadow-md text-center">
          <CardHeader>
            <CardTitle className="text-lg md:text-xl font-semibold text-foreground/90">Раньше: Сетевой Периметр</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-muted/30 p-4 rounded-lg">
              <p>Интернет 👤</p>
              <p className="text-2xl font-bold text-destructive">↓</p>
              <div className="border-2 border-destructive p-2 rounded my-1">🔥 Межсетевой экран 🔥</div>
              <p className="text-2xl font-bold">↓</p>
              <p>Внутренняя сеть 🏢</p>
            </div>
            <p className="mt-4 text-muted-foreground text-sm">Основная защита — на уровне сети.</p>
          </CardContent>
        </Card>
        <Card className="shadow-md text-center border-2 border-primary/50">
          <CardHeader>
            <CardTitle className="text-lg md:text-xl font-semibold text-foreground/90">Сейчас: Периметр Приложения</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-muted/30 p-4 rounded-lg">
              <p>Интернет 👤</p>
              <p className="text-xs text-muted-foreground">(Вредоносный HTTP/S трафик)</p>
              <p className="text-2xl font-bold text-green-600 dark:text-green-500">↓</p>
              <div className="border-2 border-green-600 dark:border-green-500 p-2 rounded my-1">🔥 Межсетевой экран (пропускает HTTP/S) 🔥</div>
              <p className="text-2xl font-bold">↓</p>
              <p>🌐 Веб-приложение 🌐</p>
              <p className="text-2xl font-bold text-destructive">↓</p>
              <p>Внутренние системы (Базы данных, и т.д.) 🏢</p>
            </div>
            <p className="mt-4 text-muted-foreground text-sm">Атака проходит через сетевую защиту и нацелена на логику приложения.</p>
          </CardContent>
        </Card>
      </div>
      <p className="mt-6 md:mt-8 text-center text-foreground/80 max-w-3xl mx-auto text-sm md:text-base">
        Одна строка уязвимого кода в веб-приложении может сделать всю внутреннюю инфраструктуру организации доступной для атаки извне. Периметр безопасности теперь находится внутри самого кода.
      </p>
    </section>
  );
}
