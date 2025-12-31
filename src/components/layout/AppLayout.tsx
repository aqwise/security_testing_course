'use client';

import type { ReactNode } from 'react';
import { useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import {
  SidebarProvider,
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarFooter,
  SidebarInset,
  useSidebar
} from '@/components/ui/sidebar';
import { Header } from './Header';
import { SidebarNav } from './SidebarNav';
import { ScrollArea } from '@/components/ui/scroll-area';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Home, BookOpen, FileText, Users, ShieldCheck, AlertTriangle, Server, Info, ListChecks, PanelLeft } from 'lucide-react';
import { ClientOnly } from '@/components/common/ClientOnly';
import { useAuth } from '@/components/auth/AuthContext';

// Public routes that don't require authentication (only login page)
const PUBLIC_ROUTES = ['/login'];

function isPublicRoute(pathname: string): boolean {
  // Check exact matches
  if (PUBLIC_ROUTES.includes(pathname)) return true;
  // Handle trailing slashes
  if (PUBLIC_ROUTES.includes(pathname.replace(/\/$/, ''))) return true;
  return false;
}

function AppLayoutClient({ children }: { children: ReactNode }) {
  const { toggleSidebar } = useSidebar();
  const { isAuthenticated, isLoading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  // Global auth check for non-public routes
  useEffect(() => {
    if (!isLoading && !isAuthenticated && !isPublicRoute(pathname)) {
      sessionStorage.setItem('redirectAfterLogin', pathname);
      router.push('/login');
    }
  }, [isAuthenticated, isLoading, pathname, router]);

  // Show loading for protected routes while checking auth
  if (isLoading && !isPublicRoute(pathname)) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Block rendering of protected content if not authenticated
  if (!isAuthenticated && !isPublicRoute(pathname)) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  // For login page, render without sidebar
  if (pathname === '/login') {
    return (
      <div className="min-h-screen">
        {children}
      </div>
    );
  }

  return (
    <>
      {isAuthenticated && (
        <Sidebar className="border-r" collapsible="icon">
          <SidebarHeader className="p-4 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2 text-lg font-semibold text-sidebar-primary hover:text-sidebar-primary/90 transition-colors group-data-[collapsible=icon]:hidden">
              <ShieldCheck className="h-7 w-7" />
              <span >Security Testing Course</span>
            </Link>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={toggleSidebar}>
              <PanelLeft />
              <span className="sr-only">Toggle Sidebar</span>
            </Button>
          </SidebarHeader>
          <ScrollArea className="flex-1">
            <SidebarContent>
              <SidebarNav />
            </SidebarContent>
          </ScrollArea>
          <SidebarFooter className="p-2 border-t">
            <Button variant="ghost" className="w-full justify-start group-data-[collapsible=icon]:justify-center" asChild>
              <Link href="/sources">
                <FileText className="h-4 w-4" />
                <span className="group-data-[collapsible=icon]:hidden ml-2">Источники</span>
              </Link>
            </Button>
          </SidebarFooter>
        </Sidebar>
      )}
      <SidebarInset className="flex flex-col">
        {isAuthenticated && <Header />}
        <ScrollArea className="flex-1">
          <main className="container mx-auto px-4 py-8 md:px-6 lg:px-8">
            {children}
          </main>
        </ScrollArea>
      </SidebarInset>
    </>
  )
}


export function AppLayout({ children }: { children: ReactNode }) {
  return (
    <ClientOnly>
      <SidebarProvider>
        <AppLayoutClient>{children}</AppLayoutClient>
      </SidebarProvider>
    </ClientOnly>
  );
}

