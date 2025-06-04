
import { ContentPageLayout } from '@/components/content/ContentPageLayout';

export default function InteractiveChapterOnePage() {
  // Next.js automatically handles basePath for assets in the public folder.
  // So, '/interactive-chapters/chapter-01.html' should resolve correctly
  // both in development and in production (e.g., /security_testing_course/interactive-chapters/chapter-01.html).
  const iframeSrc = "/interactive-chapters/chapter-01.html";

  return (
    <ContentPageLayout
      title="Интерактивная Глава 1: (Не)безопасность Веб-Приложений"
      subtitle="Погрузитесь в основы веб-безопасности с интерактивными примерами."
    >
      <div className="aspect-[16/12] w-full md:aspect-[16/10] lg:aspect-[16/9]">
        <iframe
          src={iframeSrc}
          title="Интерактивная Глава 1"
          className="w-full h-full border-0 rounded-md shadow-lg"
          allowFullScreen
        />
      </div>
      <p className="mt-4 text-sm text-muted-foreground text-center">
        Это интерактивное руководство загружено в iframe. Для лучшего опыта вы можете открыть его в 
        <a 
          href={iframeSrc} 
          target="_blank" 
          rel="noopener noreferrer" 
          className="text-primary hover:underline"
        >
          полноэкранном режиме
        </a>.
      </p>
    </ContentPageLayout>
  );
}
