'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Bar } from 'react-chartjs-2';
import 'chart.js/auto';
import type { ChartOptions, ChartData } from 'chart.js';

const resourceChartData: ChartData<'bar'> = {
  labels: [
    'TryHackMe: Welcome',
    'DVWA (Low Security)',
    'PortSwigger Academy (Basics)',
    'TryHackMe: Web Fundamentals',
    'OWASP Juice Shop (Начало)',
    'DVWA (High Security)'
  ],
  datasets: [{
    label: 'Сложность / Объем',
    data: [1, 3, 4, 5, 7, 8],
    backgroundColor: 'hsl(var(--primary) / 0.6)',
    borderColor: 'hsl(var(--primary))',
    borderWidth: 1,
    borderRadius: 4,
  }]
};

const resourceChartOptions: ChartOptions<'bar'> = {
  indexAxis: 'y',
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: false
    },
    title: {
      display: true,
      text: 'Сравнение практических ресурсов',
      font: { size: 16, family: 'Inter, sans-serif' },
      color: 'hsl(var(--foreground))'
    },
    tooltip: {
      backgroundColor: 'hsl(var(--card))',
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
    }
  },
  scales: {
    x: {
      beginAtZero: true,
      max: 10, // Assuming a scale of 1-10
      grid: {
        color: 'hsl(var(--border) / 0.5)'
      },
      ticks: {
        color: 'hsl(var(--muted-foreground))'
      },
      title: {
        display: true,
        text: 'Условная сложность (от 1 до 10)',
        color: 'hsl(var(--foreground))'
      }
    },
    y: {
      grid: {
        display: false
      },
      ticks: {
        color: 'hsl(var(--muted-foreground))',
        autoSkip: false,
         callback: function(value: string | number) {
            // In Chart.js, 'this' inside a callback refers to the scale instance.
            // We need to cast 'this' to 'any' or a more specific type if available
            // to access getLabelForValue.
            const scale = this as any; 
            const label = scale.getLabelForValue(typeof value === 'string' ? parseFloat(value) : value);
            if (typeof label === 'string' && label.length > 25) {
                return label.slice(0, 25) + '...';
            }
            return label;
        }
      }
    }
  }
};

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
            <div className="relative w-full max-w-3xl mx-auto h-[450px] md:h-[500px]">
              <Bar options={resourceChartOptions} data={resourceChartData} />
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}
