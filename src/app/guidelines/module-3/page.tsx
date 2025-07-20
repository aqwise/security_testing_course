
import { IntroSectionMod3 } from '@/components/interactive/module-3/IntroSectionMod3';
import { AuthnAttacksSection } from '@/components/interactive/module-3/AuthnAttacksSection';
import { SessionAttacksSection } from '@/components/interactive/module-3/SessionAttacksSection';
import { AccessControlAttacksSection } from '@/components/interactive/module-3/AccessControlAttacksSection';
import { LabsAndToolsSectionMod3 } from '@/components/interactive/module-3/LabsAndToolsSectionMod3';
import { ModuleFooterMod3 } from '@/components/interactive/module-3/ModuleFooterMod3';
import { Separator } from '@/components/ui/separator';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function InteractiveModuleThreePage() {
  return (
    <div className="container mx-auto p-0 md:p-4">
      <IntroSectionMod3 />
      <div className="text-center my-8">
        <Button asChild size="lg">
          <Link href="/guidelines/module-3/lesson-1">
            Перейти к Уроку 1: Атака на Аутентификацию
          </Link>
        </Button>
      </div>
      <AuthnAttacksSection />
      <SessionAttacksSection />
      <AccessControlAttacksSection />
      <LabsAndToolsSectionMod3 />
      <Separator className="my-12 md:my-16" />
      <ModuleFooterMod3 />
    </div>
  );
}
