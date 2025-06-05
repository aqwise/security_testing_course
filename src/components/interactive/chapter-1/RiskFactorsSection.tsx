
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface Factor {
  icon: string;
  title: string;
  details: string;
}

const factorData: Factor[] = [
  { icon: '🧠', title: 'Недостаточная осведомленность', details: 'Многие разработчики не до конца понимают концепции безопасности веб-приложений, делая ложные предположения о защите, предоставляемой фреймворками.' },
  { icon: '🏗️', title: 'Заказная разработка', details: 'Большинство приложений создаются на заказ, что означает наличие уникального кода и, следовательно, уникальных уязвимостей, в отличие от стандартных продуктов.' },
  { icon: '🎭', title: 'Обманчивая простота', details: 'Современные инструменты позволяют легко создавать функциональные приложения, но написание безопасного кода требует глубоких знаний, которых часто не хватает.' },
  { icon: '⚡', title: 'Быстро меняющийся профиль угроз', details: 'Новые типы атак появляются быстрее, чем команды разработчиков успевают о них узнать и внедрить защиту.' },
  { icon: '⏳', title: 'Ограничения ресурсов и времени', details: 'Сжатые сроки и бюджеты часто приводят к тому, что безопасность отходит на второй план по сравнению с функциональностью.' },
  { icon: '🔩', title: 'Чрезмерно растянутые технологии', details: 'Старые технологии, такие как JavaScript, адаптируются для новых задач, для которых они не предназначались, что приводит к непредвиденным уязвимостям.' },
];

const FactorCard = ({ factor }: { factor: Factor }) => (
  <div className="relative group rounded-lg border bg-card text-card-foreground shadow-sm p-6 text-center overflow-hidden transition-all duration-300 hover:shadow-xl hover:-translate-y-1">
    <div className="text-4xl md:text-5xl mb-3 md:mb-4">{factor.icon}</div>
    <h3 className="text-md md:text-lg font-semibold text-foreground/90">{factor.title}</h3>
    <div className="absolute inset-0 bg-background/95 backdrop-blur-sm p-4 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity duration-300">
      <p className="text-muted-foreground text-sm">{factor.details}</p>
    </div>
  </div>
);

export function RiskFactorsSection() {
  return (
    <section id="factors">
      <h2 className="text-2xl md:text-3xl font-bold text-center mb-2 text-primary/90">Факторы, усугубляющие проблему</h2>
      <p className="text-center text-muted-foreground mb-8 md:mb-12 max-w-3xl mx-auto">
        Множество факторов в индустрии разработки программного обеспечения способствуют тому, что веб-приложения остаются небезопасными. Наведите курсор на карточку, чтобы прочитать подробности.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8">
        {factorData.map((factor, index) => (
          <FactorCard key={index} factor={factor} />
        ))}
      </div>
    </section>
  );
}
