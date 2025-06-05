
import { IntroPrerequisitesSection } from '@/components/interactive/prerequisites/IntroPrerequisitesSection';
import { KnowledgeSection } from '@/components/interactive/prerequisites/KnowledgeSection';
import { HardwareSection } from '@/components/interactive/prerequisites/HardwareSection';
import { SoftwareSection } from '@/components/interactive/prerequisites/SoftwareSection';
import { VulnerableAppsSection } from '@/components/interactive/prerequisites/VulnerableAppsSection';
import { RecommendedLanguagesSection } from '@/components/interactive/prerequisites/RecommendedLanguagesSection';
import { PrerequisitesPageFooter } from '@/components/interactive/prerequisites/PrerequisitesPageFooter';
import { Separator } from '@/components/ui/separator';

export default function PrerequisitesPageInteractive() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroPrerequisitesSection />
      <KnowledgeSection />
      <HardwareSection />
      <SoftwareSection />
      <VulnerableAppsSection />
      <RecommendedLanguagesSection />
      <Separator className="my-12 md:my-16" />
      <PrerequisitesPageFooter />
    </div>
  );
}
