'use client';

import { Card, CardContent } from '@/components/ui/card';
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"

const chartData = [
  { resource: 'TryHackMe: Welcome', Сложность: 1 },
  { resource: 'DVWA (Low)', Сложность: 3 },
  { resource: 'PortSwigger (Basics)', Сложность: 4 },
  { resource: 'TryHackMe: Web Fun.', Сложность: 5 },
  { resource: 'OWASP Juice Shop (Start)', Сложность: 7 },
  { resource: 'DVWA (High)', Сложность: 8 },
];

const chartConfig = {
  "Сложность": {
    label: "Условная сложность (1-10)",
    color: "hsl(var(--chart-1))",
  },
} satisfies ChartConfig


export function ResourceComparisonSection() {
  return (
    <section id="compare" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">Сравнение практических ресурсов</h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Эта диаграмма поможет вам выбрать подходящий ресурс для практики, исходя из его предполагаемой сложности и широты охвата тем.
          </p>
        </div>
        <Card className="shadow-lg rounded-xl border border-border">
          <CardContent className="p-4 md:p-6">
            <ChartContainer config={chartConfig} className="h-[450px] w-full">
              <BarChart
                accessibilityLayer
                data={chartData}
                layout="vertical"
                margin={{
                  left: 20,
                }}
              >
                <CartesianGrid horizontal={false} />
                <YAxis
                  dataKey="resource"
                  type="category"
                  tickLine={false}
                  tickMargin={10}
                  axisLine={false}
                  className="fill-muted-foreground"
                />
                <XAxis dataKey="Сложность" type="number" domain={[0, 10]} />
                <ChartTooltip
                  cursor={false}
                  content={<ChartTooltipContent hideLabel />}
                />
                <Bar
                  dataKey="Сложность"
                  layout="vertical"
                  radius={4}
                />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
