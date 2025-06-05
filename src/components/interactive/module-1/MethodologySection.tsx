
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface Step {
  id: number;
  title: string;
  description: string;
}

const methodologySteps: Step[] = [
  {
    id: 1,
    title: 'Разведка',
    description: 'Сбор информации о цели без прямого взаимодействия. Анализ открытых источников, доменов, технологий.',
  },
  {
    id: 2,
    title: 'Картирование',
    description: 'Анализ структуры и функциональности приложения, определение точек входа и векторов атак.',
  },
  {
    id: 3,
    title: 'Обнаружение',
    description: 'Выявление уязвимостей с помощью ручных и автоматизированных методов. Фаззинг, сканирование.',
  },
  {
    id: 4,
    title: 'Эксплуатация',
    description: 'Использование уязвимостей для достижения целей: доступ к данным, выполнение команд.',
  },
];

export function MethodologySection() {
  return (
    <section id="methodology" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">Обзор методологии WAHH2</h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Это итеративный процесс, который лежит в основе профессионального тестирования на проникновение. Каждый этап важен для полного понимания и оценки безопасности приложения.
          </p>
        </div>
        <div className="relative">
          {/* Decorative line */}
          <div className="hidden md:block absolute top-1/2 left-0 w-full h-0.5 bg-primary/20 -translate-y-1/2" aria-hidden="true"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {methodologySteps.map((step) => (
              <div key={step.id} className="relative bg-background p-6 rounded-xl shadow-lg border border-border hover:shadow-xl transition-shadow duration-300">
                <div className="absolute -top-4 -left-4 w-12 h-12 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-xl font-bold shadow-md">
                  {step.id}
                </div>
                <h3 className="text-xl font-semibold text-foreground/90 mt-4">{step.title}</h3>
                <p className="mt-2 text-muted-foreground">{step.description}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
