
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface StepItem {
  id: number;
  title: string;
  description: string;
}

const steps: StepItem[] = [
  {
    id: 1,
    title: 'Настройте Burp Suite',
    description: 'Установите Community Edition и настройте прокси для вашего браузера. Познакомьтесь с вкладками Proxy и Repeater.',
  },
  {
    id: 2,
    title: 'Разверните DVWA',
    description: 'Используйте Docker или XAMPP для установки. Войдите с учетными данными по умолчанию (admin/password) и попробуйте решить задания на уровне Low.',
  },
  {
    id: 3,
    title: 'Начните с PortSwigger Academy',
    description: 'Пройдите начальные разделы, посвященные основам HTTP и работе с Burp Suite. Это даст прочную теоретическую базу.',
  },
  {
    id: 4,
    title: 'Пройдите базовые комнаты на TryHackMe',
    description: 'Зарегистрируйтесь и пройдите комнаты "Welcome" и "Starting Out In Cyber Sec" для знакомства с платформой.',
  },
];

export function FirstStepsSection() {
  return (
    <section id="start" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">Рекомендуемые первые шаги</h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Не знаете, с чего начать? Вот конкретный план действий для погружения в практику.
          </p>
        </div>
        <ul className="space-y-4 max-w-3xl mx-auto">
          {steps.map((step) => (
            <li key={step.id} className="bg-background/50 p-4 rounded-lg flex items-start space-x-4 border border-border shadow-sm">
              <div className="flex-shrink-0 h-6 w-6 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold mt-1">
                {step.id}
              </div>
              <div>
                <h4 className="font-semibold text-foreground/90">{step.title}</h4>
                <p className="text-muted-foreground">{step.description}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
