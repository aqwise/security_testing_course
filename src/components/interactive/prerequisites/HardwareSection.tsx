
import Link from 'next/link';
import { Card, CardContent } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";
const IconStyle = "mr-2 text-primary text-xl";

export function HardwareSection() {
  return (
    <section id="hardware" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            <span className={IconStyle}>🖥️</span>B. Оборудование
          </h2>
        </div>
        <Card className="max-w-3xl mx-auto">
          <CardContent className="p-6">
            <ul className="space-y-3 text-foreground/90">
              <li className="flex items-start">
                <span className={IconStyle}>💻</span>
                <div><strong>Компьютер:</strong> Современный ноутбук или настольный ПК.</div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>💾</span>
                <div><strong>Оперативная память (RAM):</strong> Минимум 8 ГБ, рекомендуется 16 ГБ+ для виртуальных машин и Burp Suite.</div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>💽</span>
                <div><strong>Место на диске:</strong> Достаточное для ОС, инструментов, VM/контейнеров и словарей (например, <Link href="https://github.com/danielmiessler/SecLists" target="_blank" rel="noopener noreferrer" className={LinkStyle}>SecLists</Link>).</div>
              </li>
              <li className="flex items-start">
                <span className={IconStyle}>📶</span>
                <div><strong>Интернет-соединение:</strong> Стабильное.</div>
              </li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
