'use client';

import Link from 'next/link';
import { Bar } from 'react-chartjs-2';
import 'chart.js/auto';
import type { ChartOptions, ChartData } from 'chart.js';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';


const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const labFocusChartDataMod4: ChartData<'bar'> = {
  labels: [
    'SQLi Labs (PortSwigger)', 
    'OS Cmd Inj. Labs (PortSwigger)', 
    'Path Traversal Labs (PortSwigger)', 
    'File Upload Labs (PortSwigger)',
    'DVWA (SQLi, Cmd Inj.)',
    'Juice Shop (SQLi, LFI)'
  ],
  datasets: [{
    label: 'Примерный Фокус Лаборатории',
    data: [9, 8, 7, 7, 8, 7], 
    backgroundColor: 'hsl(var(--primary) / 0.6)', 
    borderColor: 'hsl(var(--primary))',
    borderWidth: 1,
    borderRadius: 4,
  }]
};

const labFocusChartOptionsMod4: ChartOptions<'bar'> = {
  indexAxis: 'y',
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'hsl(var(--card))', /* slate-800 from your HTML becomes card */
      titleColor: 'hsl(var(--card-foreground))',
      bodyColor: 'hsl(var(--card-foreground))',
      borderColor: 'hsl(var(--border))',
      borderWidth: 1,
      displayColors: false,
       callbacks: {
        label: function(context) {
          return (context.dataset.label || '') + ': ' + context.parsed.x;
        }
      }
    },
    title: {
      display: true,
      text: 'Релевантность темам Модуля IV (1-10)',
      color: 'hsl(var(--foreground))', /* slate-700 becomes foreground */
      font: { size: 16 }
    }
  },
  scales: {
    x: {
      beginAtZero: true,
      max:10,
      grid: { color: 'hsl(var(--border) / 0.5)' }, /* slate-200 becomes border/0.5 */
      ticks: { color: 'hsl(var(--muted-foreground))' }, /* slate-600 becomes muted-foreground */
      title: { display: true, text: 'Условная Релевантность', color: 'hsl(var(--muted-foreground))' }
    },
    y: {
      grid: { display: false },
      ticks: { color: 'hsl(var(--muted-foreground))', autoSkip: false } /* slate-600 */
    }
  }
};

export function LabsAndToolsSectionMod4() {
  return (
    <section id="labs-mod4" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">E. Рекомендуемые Лаборатории и Инструменты (Модуль IV)</h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">Практические ресурсы для отработки атак на серверные уязвимости.</p>
          <p className="mt-4 text-md text-muted-foreground/80 italic">(Примечание: Список конкретных лабораторий и инструментов для этого модуля будет добавлен позже. Ниже представлена общая диаграмма-плейсхолдер.)</p>
        </div>
         <Card className="shadow-lg rounded-xl border border-border">
            <CardContent className="p-4 md:p-6">
                <div className="relative w-full max-w-3xl mx-auto h-[400px] md:h-[480px]"> {/* Adjusted height from HTML */}
                <Bar options={labFocusChartOptionsMod4} data={labFocusChartDataMod4} />
                </div>
            </CardContent>
        </Card>
        <div className="mt-8 text-center">
          <p className="text-muted-foreground">
            Ключевые инструменты, которые часто используются для эксплуатации серверных уязвимостей, включают <Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Suite</Link> (особенно Repeater, Intruder) и <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link>.
          </p>
        </div>
      </div>
    </section>
  );
}
