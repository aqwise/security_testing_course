'use client';

import type { ReactNode } from 'react';
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


function AppLayoutClient({ children }: { children: ReactNode }) {
  const { toggleSidebar } = useSidebar();
  return (
    <>
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
      <SidebarInset className="flex flex-col">
        <Header />
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
    <SidebarProvider>
      <AppLayoutClient>{children}</AppLayoutClient>
    </SidebarProvider>
  );
}
