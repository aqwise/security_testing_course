
import { Card, CardContent } from '@/components/ui/card';

export function ApproachSection() {
  return (
    <section id="approach" className="py-12 md:py-16 bg-secondary/30">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-10 md:mb-12">
          <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-foreground">
            <span className="mr-2 text-primary text-2xl md:text-3xl align-middle">🧭</span>
            Наш подход к обучению
          </h2>
        </div>
        <Card className="max-w-3xl mx-auto shadow-lg">
          <CardContent className="p-6 md:p-8">
            <p className="text-md md:text-lg text-foreground/90 leading-relaxed">
              Данное руководство придерживается практического подхода, сочетая теоретические основы с интенсивными практическими упражнениями. Мы будем использовать стандартные отраслевые инструменты и специально созданные уязвимые веб-приложения, чтобы вы могли отточить свои навыки в безопасной и контролируемой среде.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
