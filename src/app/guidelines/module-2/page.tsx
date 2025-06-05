
import { IntroSectionMod2 } from '@/components/interactive/module-2/IntroSectionMod2';
import { ReconnaissanceSection } from '@/components/interactive/module-2/ReconnaissanceSection';
import { MappingSection } from '@/components/interactive/module-2/MappingSection';
import { DiscoverySection } from '@/components/interactive/module-2/DiscoverySection';
import { AnalysisSection } from '@/components/interactive/module-2/AnalysisSection';
import { LabsAndToolsSection } from '@/components/interactive/module-2/LabsAndToolsSection';
import { ModuleFooterMod2 } from '@/components/interactive/module-2/ModuleFooterMod2';
import { Separator } from '@/components/ui/separator';

export default function InteractiveModuleTwoPage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroSectionMod2 />
      <ReconnaissanceSection />
      <MappingSection />
      <DiscoverySection />
      <AnalysisSection />
      <LabsAndToolsSection />
      <Separator className="my-12 md:my-16" />
      <ModuleFooterMod2 />
    </div>
  );
}
