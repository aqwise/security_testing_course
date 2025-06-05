
import type { LucideIcon } from 'lucide-react';
import { Home, Info, Users, ListChecks, BookOpen, Shield, Microscope, KeyRound, ServerIcon, FileText, PlayCircle, Package, BookMarked } from 'lucide-react';

export interface NavLink {
  href: string;
  label: string;
  icon?: LucideIcon;
  children?: NavLink[];
}

export const navigationLinks: NavLink[] = [
  { href: '/', label: 'Главная', icon: Home },
  { href: '/concepts', label: 'Концепции', icon: Info },
  { href: '/audience', label: 'Аудитория', icon: Users },
  { href: '/prerequisites', label: 'Требования', icon: ListChecks },
  {
    href: '/guidelines',
    label: 'Руководство',
    icon: BookOpen,
    children: [
      {
        href: '/guidelines/module-1',
        label: 'Модуль I: Основы',
        icon: Shield,
        children: [
          {
            href: '/guidelines/module-1/lesson-1',
            label: 'Урок 1: Лаборатория',
            icon: BookMarked
          },
          {
            href: '/guidelines/module-1/lesson-2',
            label: 'Урок 2: DVWA',
            icon: Package // Added icon Package
          }
        ]
      },
      { href: '/guidelines/module-2', label: 'Модуль II: Разведка', icon: Microscope },
      { href: '/guidelines/module-3', label: 'Модуль III: Аутентификация', icon: KeyRound },
      { href: '/guidelines/module-4', label: 'Модуль IV: Серверные Уязвимости', icon: ServerIcon },
    ],
  },
  { href: '/interactive/chapter-1', label: 'Интерактивная Глава 1', icon: PlayCircle },
  { href: '/text-chapter/chapter-1', label: 'Текстовая Глава 1', icon: FileText },
  // Source link is handled in AppLayout footer
];
