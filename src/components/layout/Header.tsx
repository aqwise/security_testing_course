'use client';

import { SidebarTrigger } from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';
import { Github, LogOut } from 'lucide-react';
import Link from 'next/link';
import { useAuth } from '@/components/auth/AuthContext';

export function Header() {
  const { isAuthenticated, logout } = useAuth();

  return (
    <header className="sticky top-0 z-10 flex h-16 items-center gap-4 border-b bg-background/80 backdrop-blur-sm px-4 md:px-6">
      <SidebarTrigger className="md:hidden" />
      <div className="flex-1">
        {/* Optional: Add breadcrumbs or page title here */}
      </div>
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="icon" asChild>
          <Link href="https://github.com" target="_blank" aria-label="GitHub Repository">
            <Github className="h-5 w-5" />
          </Link>
        </Button>
        {isAuthenticated && (
          <Button
            variant="ghost"
            size="icon"
            onClick={logout}
            aria-label="Выйти"
            title="Выйти из системы"
          >
            <LogOut className="h-5 w-5" />
          </Button>
        )}
      </div>
    </header>
  );
}
