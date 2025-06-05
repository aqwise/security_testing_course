
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';

export function GuideGoalsSection() {
  return (
    <section id="guide-goals" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-bold tracking-tight text-foreground">
              Цель руководства
            </h2>
          </div>
          <Card className="bg-background p-8 rounded-xl shadow-lg border text-center">
            <CardContent className="pt-0">
              <p className="text-lg text-foreground/90 leading-relaxed">
                Предоставить читателям не только теоретические знания о распространенных веб-уязвимостях (таких как перечисленные в{' '}
                <Link href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 hover:underline">
                  OWASP Top 10
                </Link>
                ), но и, что более важно, развить практические навыки их обнаружения и эксплуатации с использованием современных инструментов и методологий.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
