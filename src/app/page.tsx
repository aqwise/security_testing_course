
import { WelcomeSection } from '@/components/interactive/introduction/WelcomeSection';
import { ApproachSection } from '@/components/interactive/introduction/ApproachSection';
import { ResourcesSection } from '@/components/interactive/introduction/ResourcesSection';
import { EvolutionSection } from '@/components/interactive/introduction/EvolutionSection';
import { GoalsSection } from '@/components/interactive/introduction/GoalsSection';
import { IntroModuleFooter } from '@/components/interactive/introduction/IntroModuleFooter';
import { Separator } from '@/components/ui/separator';

export default function InteractiveIntroPage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <WelcomeSection />
      <Separator className="my-8 md:my-12" />
      <ApproachSection />
      <Separator className="my-8 md:my-12" />
      <ResourcesSection />
      <Separator className="my-8 md:my-12" />
      <EvolutionSection />
      <Separator className="my-8 md:my-12" />
      <GoalsSection />
      <Separator className="my-12 md:my-16" />
      <IntroModuleFooter />
    </div>
  );
}
