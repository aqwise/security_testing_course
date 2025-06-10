
'use client';

import { BookChapterTextSection } from '@/components/interactive/chapter-3/BookChapterTextSection';
import { ChapterFooter } from '@/components/interactive/chapter-3/ChapterFooter';
import { Separator } from '@/components/ui/separator';

export default function TextChapterThreePage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <BookChapterTextSection />
      <Separator className="my-12 md:my-16" />
      <ChapterFooter />
    </div>
  );
}
