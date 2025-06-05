
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { BookOpen, Shield } from 'lucide-react';

export function WelcomeSection() {
  return (
    <section id="welcome" className="py-16 md:py-24 text-center">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <Shield className="mx-auto h-16 w-16 text-primary mb-6" />
        <h2 className="text-3xl font-bold tracking-tight text-foreground sm:text-4xl md:text-5xl">
          I. Введение
        </h2>
        <p className="mt-6 max-w-3xl mx-auto text-lg text-muted-foreground leading-relaxed">
          Добро пожаловать в обновленное руководство по практическому тестированию безопасности веб-приложений. В современном цифровом мире веб-приложения являются неотъемлемой частью бизнеса, государственных услуг и повседневной жизни. Однако они также представляют собой значительную поверхность атаки, и уязвимости могут привести к серьезным последствиям, включая утечки данных, финансовые потери и компрометацию систем. Понимание и умение выявлять и эксплуатировать эти уязвимости – критически важные навыки для любого специалиста по кибербезопасности.
        </p>
        <div className="mt-10 flex justify-center gap-4">
          <Button size="lg" asChild>
            <Link href="/guidelines/module-1">
              <BookOpen className="mr-2 h-5 w-5" />
              Начать с Модуля I
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
}
