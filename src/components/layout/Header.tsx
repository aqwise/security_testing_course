import { SidebarTrigger } from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';
import { Github } from 'lucide-react';
import Link from 'next/link';

export function Header() {
  return (
    <header className="sticky top-0 z-10 flex h-16 items-center gap-4 border-b bg-background/80 backdrop-blur-sm px-4 md:px-6">
      <SidebarTrigger className="md:hidden" />
      <div className="flex-1">
        {/* Optional: Add breadcrumbs or page title here */}
      </div>
      <Button variant="ghost" size="icon" asChild>
        <Link href="https://github.com" target="_blank" aria-label="GitHub Repository">
          <Github className="h-5 w-5" />
        </Link>
      </Button>
    </header>
  );
}
