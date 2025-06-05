
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function GoalsSection() {
  return (
    <section id="goals" className="py-12 md:py-16">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-10 md:mb-12">
          <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-foreground">
            <span className="mr-2 text-primary text-2xl md:text-3xl align-middle">🎯</span>
            Цель нашего руководства
          </h2>
        </div>
        <Card className="max-w-3xl mx-auto shadow-lg bg-card">
          <CardContent className="p-6 md:p-8">
            <p className="text-md md:text-lg text-foreground/90 leading-relaxed">
              Это руководство призвано стать вашим надежным спутником в освоении практических навыков, необходимых для навигации в динамичной области веб-безопасности. Мы начнем с основ и постепенно перейдем к более сложным техникам, всегда подкрепляя теорию практикой. Наша цель — помочь вам развить глубокое понимание веб-уязвимостей и методов их эксплуатации, чтобы вы могли эффективно защищать веб-приложения или проводить их качественное тестирование.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
