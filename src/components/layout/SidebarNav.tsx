'use client';

import {
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarMenuSub,
  SidebarMenuSubItem,
  SidebarMenuSubButton,
} from '@/components/ui/sidebar';
import { navigationLinks, type NavLink } from '@/constants/navigation';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ChevronDown } from 'lucide-react';
import React from 'react';

export function SidebarNav() {
  const pathname = usePathname();

  const renderLink = (link: NavLink, isSubItem = false) => {
    const isActive = pathname === link.href || (link.href !== '/' && pathname.startsWith(link.href));
    
    const ButtonComponent = isSubItem ? SidebarMenuSubButton : SidebarMenuButton;
    const ItemComponent = isSubItem ? SidebarMenuSubItem : SidebarMenuItem;

    return (
      <ItemComponent key={link.href}>
        <ButtonComponent
          asChild
          isActive={isActive}
          tooltip={{ children: link.label, side: 'right', className: 'bg-card text-card-foreground border-border' }}
        >
          <Link href={link.href}>
            {link.icon && <link.icon className="h-4 w-4" />}
            <span>{link.label}</span>
            {link.children && <ChevronDown className="ml-auto h-4 w-4 transition-transform group-data-[state=open]:rotate-180" />}
          </Link>
        </ButtonComponent>
        {link.children && (
          <SidebarMenuSub>
            {link.children.map(child => renderLink(child, true))}
          </SidebarMenuSub>
        )}
      </ItemComponent>
    );
  };

  return (
    <SidebarMenu>
      {navigationLinks.map(link => renderLink(link))}
    </SidebarMenu>
  );
}
