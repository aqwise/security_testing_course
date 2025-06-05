
import { HeroSection } from '@/components/interactive/chapter-1/HeroSection';
import { EvolutionSection } from '@/components/interactive/chapter-1/EvolutionSection';
import { VulnerabilitiesSection } from '@/components/interactive/chapter-1/VulnerabilitiesSection';
import { CoreProblemSection } from '@/components/interactive/chapter-1/CoreProblemSection';
import { RiskFactorsSection } from '@/components/interactive/chapter-1/RiskFactorsSection';
import { PerimeterSection } from '@/components/interactive/chapter-1/PerimeterSection';
import { FutureSection } from '@/components/interactive/chapter-1/FutureSection';
import { ChapterFooter } from '@/components/interactive/chapter-1/ChapterFooter';
import { Separator } from '@/components/ui/separator';

export default function InteractiveChapterOnePage() {
  return (
    <div className="container mx-auto p-0 md:p-4"> {/* Adjusted padding for better control by sections */}
      <HeroSection />
      <div className="space-y-16 md:space-y-24 mt-12 md:mt-16">
        <EvolutionSection />
        <VulnerabilitiesSection />
        <CoreProblemSection />
        <RiskFactorsSection />
        <PerimeterSection />
        <FutureSection />
      </div>
      <Separator className="my-12 md:my-16" />
      <ChapterFooter />
    </div>
  );
}
