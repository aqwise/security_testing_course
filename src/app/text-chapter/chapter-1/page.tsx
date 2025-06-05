
import { BookChapterTextSection } from '@/components/interactive/chapter-1/BookChapterTextSection';
import { ChapterFooter } from '@/components/interactive/chapter-1/ChapterFooter';
import { Separator } from '@/components/ui/separator';

export default function TextChapterOnePage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <BookChapterTextSection />
      <Separator className="my-12 md:my-16" />
      <ChapterFooter />
    </div>
  );
}
