
import { IntroSectionMod3 } from '@/components/interactive/module-3/IntroSectionMod3';
import { AuthnAttacksSection } from '@/components/interactive/module-3/AuthnAttacksSection';
import { SessionAttacksSection } from '@/components/interactive/module-3/SessionAttacksSection';
import { AccessControlAttacksSection } from '@/components/interactive/module-3/AccessControlAttacksSection';
import { LabsAndToolsSectionMod3 } from '@/components/interactive/module-3/LabsAndToolsSectionMod3';
import { ModuleFooterMod3 } from '@/components/interactive/module-3/ModuleFooterMod3';
import { Separator } from '@/components/ui/separator';

export default function InteractiveModuleThreePage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroSectionMod3 />
      <AuthnAttacksSection />
      <SessionAttacksSection />
      <AccessControlAttacksSection />
      <LabsAndToolsSectionMod3 />
      <Separator className="my-12 md:my-16" />
      <ModuleFooterMod3 />
    </div>
  );
}
