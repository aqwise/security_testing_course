
import { IntroSection } from '@/components/interactive/module-1/IntroSection';
import { MethodologySection } from '@/components/interactive/module-1/MethodologySection';
import { ArsenalSection } from '@/components/interactive/module-1/ArsenalSection';
import { FirstStepsSection } from '@/components/interactive/module-1/FirstStepsSection';
import { ResourceComparisonSection } from '@/components/interactive/module-1/ResourceComparisonSection';
import { ModuleFooter } from '@/components/interactive/module-1/ModuleFooter';
import { Separator } from '@/components/ui/separator';

export default function InteractiveModuleOnePage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroSection />
      <MethodologySection />
      <ArsenalSection />
      <FirstStepsSection />
      <ResourceComparisonSection />
      <Separator className="my-12 md:my-16" />
      <ModuleFooter />
    </div>
  );
}
