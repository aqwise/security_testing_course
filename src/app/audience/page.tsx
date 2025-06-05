
import { IntroAudienceSection } from '@/components/interactive/audience/IntroAudienceSection';
import { TargetGroupsSection } from '@/components/interactive/audience/TargetGroupsSection';
import { PrerequisitesKnowledgeSection } from '@/components/interactive/audience/PrerequisitesKnowledgeSection';
import { GuideGoalsSection } from '@/components/interactive/audience/GuideGoalsSection';
import { LearningPlatformsSection } from '@/components/interactive/audience/LearningPlatformsSection';
import { AudiencePageFooter } from '@/components/interactive/audience/AudiencePageFooter';
import { Separator } from '@/components/ui/separator';

export default function AudiencePageInteractive() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroAudienceSection />
      <TargetGroupsSection />
      <PrerequisitesKnowledgeSection />
      <GuideGoalsSection />
      <LearningPlatformsSection />
      <Separator className="my-12 md:my-16" />
      <AudiencePageFooter />
    </div>
  );
}
