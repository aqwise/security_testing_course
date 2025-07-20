
import type { LucideIcon } from 'lucide-react';
import { Home, Info, Users, ListChecks, BookOpen, Shield, Microscope, KeyRound, ServerIcon, FileText, PlayCircle, Package, BookMarked, ShoppingBasket, DatabaseZap, ShieldAlert, LibraryBig, Wrench, Zap, Smartphone, AlertTriangle } from 'lucide-react';

export interface NavLink {
  href: string;
  label: string;
  icon?: LucideIcon;
  children?: NavLink[];
}

export const navigationLinks: NavLink[] = [
  { href: '/', label: 'Введение', icon: Home },
  { href: '/legal', label: 'Правовая информация', icon: AlertTriangle },
  { href: '/concepts', label: 'Концепции', icon: Info },
  { href: '/audience', label: 'Требования к кандидатам', icon: Users },
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
            icon: Package
          },
          {
            href: '/guidelines/module-1/lesson-3',
            label: 'Урок 3: Juice Shop',
            icon: ShoppingBasket
          },
          {
            href: '/guidelines/module-1/lesson-4',
            label: 'Урок 4: SQL-инъекции',
            icon: DatabaseZap
          }
        ]
      },
      { 
        href: '/guidelines/module-2', 
        label: 'Модуль II: Разведка', 
        icon: Microscope,
        children: [
          {
            href: '/guidelines/module-2/lesson-1',
            label: 'Урок 1: Механизмы Защиты',
            icon: ShieldAlert 
          }
        ]
      },
      { 
        href: '/guidelines/module-3/lesson-1', 
        label: 'Модуль III: Аутентификация', 
        icon: KeyRound,
        children: [
            {
                href: '/guidelines/module-3/lesson-1',
                label: 'Урок 1: Атака на Аутентификацию',
                icon: ShieldAlert
            }
        ]
      },
      { href: '/guidelines/module-4', label: 'Модуль IV: Серверные Уязвимости', icon: ServerIcon },
    ],
  },
  {
    href: '/wiki/devsecops-tools',
    label: 'Wiki',
    icon: LibraryBig,
    children: [
      {
        href: '/wiki/devsecops-tools',
        label: 'Инструменты AppSec (SafeCode)',
        icon: Wrench,
      },
      {
        href: '/wiki/owasp-zap-setup',
        label: 'Настройка OWASP ZAP',
        icon: Zap,
      },
      {
        href: '/wiki/mobsf-setup',
        label: 'Настройка MobSF',
        icon: Smartphone,
      },
    ],
  },
  { href: '/interactive/chapter-1', label: 'Интерактивная Глава 1', icon: PlayCircle },
  { href: '/text-chapter/chapter-1', label: 'Глава 1', icon: FileText },
  { href: '/text-chapter/chapter-2', label: 'Глава 2', icon: FileText },
  { href: '/text-chapter/chapter-3', label: 'Глава 3', icon: FileText },
  { href: '/text-chapter/chapter-4', label: 'Глава 4', icon: FileText },
];
