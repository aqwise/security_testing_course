
import { IntroSectionMod4 } from '@/components/interactive/module-4/IntroSectionMod4';
import { SqlInjectionSection } from '@/components/interactive/module-4/SqlInjectionSection';
import { OsCommandInjectionSection } from '@/components/interactive/module-4/OsCommandInjectionSection';
import { PathTraversalSection } from '@/components/interactive/module-4/PathTraversalSection';
import { FileUploadVulnerabilitiesSection } from '@/components/interactive/module-4/FileUploadVulnerabilitiesSection';
import { LabsAndToolsSectionMod4 } from '@/components/interactive/module-4/LabsAndToolsSectionMod4';
import { ModuleFooterMod4 } from '@/components/interactive/module-4/ModuleFooterMod4';
import { Separator } from '@/components/ui/separator';

export default function InteractiveModuleFourPage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroSectionMod4 />
      <SqlInjectionSection />
      <OsCommandInjectionSection />
      <PathTraversalSection />
      <FileUploadVulnerabilitiesSection />
      <LabsAndToolsSectionMod4 />
      <Separator className="my-12 md:my-16" />
      <ModuleFooterMod4 />
    </div>
  );
}
