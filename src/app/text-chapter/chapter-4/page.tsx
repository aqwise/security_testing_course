'use client';

import { BookChapterTextSection } from '@/components/interactive/chapter-4/BookChapterTextSection';
import { ChapterFooter } from '@/components/interactive/chapter-4/ChapterFooter';
import { Separator } from '@/components/ui/separator';

export default function TextChapterFourPage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <BookChapterTextSection />
      <Separator className="my-12 md:my-16" />
      <ChapterFooter />
    </div>
  );
} 