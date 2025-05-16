import { ContentPageLayout, P } from '@/components/content/ContentPageLayout';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import { BookOpen } from 'lucide-react';

export default function GuidelinesOverviewPage() {
  return (
    <ContentPageLayout
      title="Руководство по Практическому Тестированию Безопасности Веб-Приложений"
      subtitle="Обновленное Издание"
    >
      <P>
        Это руководство проведет вас через ключевые аспекты тестирования безопасности веб-приложений,
        основываясь на методологии WAHH2 и современных практиках. Каждый модуль посвящен
        конкретным областям, от основ и разведки до атак на различные компоненты приложения.
      </P>
      <P>
        Выберите модуль из навигационного меню слева, чтобы начать изучение.
      </P>
      <div className="mt-8 flex flex-col sm:flex-row gap-4">
        <Button asChild size="lg">
          <Link href="/guidelines/module-1">
            <BookOpen className="mr-2 h-5 w-5" /> Начать с Модуля I
          </Link>
        </Button>
      </div>
    </ContentPageLayout>
  );
}
