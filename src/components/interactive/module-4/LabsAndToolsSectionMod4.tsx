'use client';

import Link from 'next/link';
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { Card, CardContent } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const labFocusChartDataMod4 = [
  { lab: 'SQLi Labs (PortSwigger)', Релевантность: 9 },
  { lab: 'OS Cmd Inj. Labs (PortSwigger)', Релевантность: 8 },
  { lab: 'Path Traversal Labs (PortSwigger)', Релевантность: 7 },
  { lab: 'File Upload Labs (PortSwigger)', Релевантность: 7 },
  { lab: 'DVWA (SQLi, Cmd Inj.)', Релевантность: 8 },
  { lab: 'Juice Shop (SQLi, LFI)', Релевантность: 7 },
];

const labFocusChartConfigMod4 = {
  "Релевантность": {
    label: "Релевантность темам Модуля IV (1-10)",
    color: "hsl(var(--chart-1))",
  },
} satisfies ChartConfig;

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
              <ChartContainer config={labFocusChartConfigMod4} className="h-[480px] w-full">
                <BarChart accessibilityLayer data={labFocusChartDataMod4} layout="vertical" margin={{ left: 20 }}>
                  <CartesianGrid horizontal={false} />
                  <YAxis
                    dataKey="lab"
                    type="category"
                    tickLine={false}
                    tickMargin={10}
                    axisLine={false}
                    className="fill-muted-foreground"
                  />
                  <XAxis dataKey="Релевантность" type="number" domain={[0, 10]} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
                  <Bar dataKey="Релевантность" layout="vertical" radius={4} />
                </BarChart>
              </ChartContainer>
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
