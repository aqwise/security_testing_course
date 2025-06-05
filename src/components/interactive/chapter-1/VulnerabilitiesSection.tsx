
'use client';

import { Card, CardContent } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
  ChartData
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const vulnerabilityChartData: ChartData<'bar'> = {
  labels: [
    'Подделка межсайтовых запросов (CSRF)',
    'Утечка информации',
    'Межсайтовый скриптинг (XSS)',
    'SQL-инъекция',
    'Нарушение контроля доступа',
    'Нарушение аутентификации'
  ],
  datasets: [{
    label: 'Частота в протестированных приложениях (%)',
    data: [92, 78, 94, 32, 71, 62],
    backgroundColor: 'hsl(var(--primary) / 0.6)',
    borderColor: 'hsl(var(--primary))',
    borderWidth: 1,
    borderRadius: 4,
  }]
};

const vulnerabilityChartOptions: ChartOptions<'bar'> = {
  indexAxis: 'y',
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: false
    },
    title: {
      display: true,
      text: 'Частота распространенных уязвимостей',
      font: { size: 16, family: 'Inter, sans-serif' },
      color: 'hsl(var(--foreground))'
    },
    tooltip: {
      callbacks: {
        label: function(context) {
          return context.dataset.label + ': ' + context.parsed.x + '%';
        }
      }
    }
  },
  scales: {
    x: {
      beginAtZero: true,
      max: 100,
      ticks: {
        callback: function(value) {
          return value + '%'
        },
        color: 'hsl(var(--muted-foreground))',
      },
      grid: {
        color: 'hsl(var(--border) / 0.5)'
      }
    },
    y: {
      ticks: {
        autoSkip: false,
        color: 'hsl(var(--muted-foreground))',
        callback: function(value, index, values) {
            const label = this.getLabelForValue(value as number);
            if (label.length > 25) { // Ensure type safety for label
                return label.slice(0, 25) + '...';
            }
            return label;
        }
      },
       grid: {
        color: 'hsl(var(--border) / 0.5)'
      }
    }
  }
};

const accordionData = [
    { title: 'Нарушение аутентификации (62%)', content: 'Охватывает различные дефекты в механизме входа в приложение, которые могут позволить злоумышленнику угадать слабые пароли, запустить атаку методом перебора или обойти вход в систему.' },
    { title: 'Нарушение контроля доступа (71%)', content: 'Это случаи, когда приложение не может должным образом защитить доступ к своим данным и функциям, потенциально позволяя злоумышленнику просматривать конфиденциальные данные других пользователей, хранящиеся на сервере, или выполнять привилегированные действия.' },
    { title: 'SQL-инъекция (32%)', content: 'Эта уязвимость позволяет злоумышленнику отправлять специально созданные входные данные для вмешательства во взаимодействие приложения с внутренними базами данных. Злоумышленник может получить произвольные данные из приложения, вмешаться в его логику или выполнить команды на самом сервере базы данных.' },
    { title: 'Межсайтовый скриптинг (XSS) (94%)', content: 'Эта уязвимость позволяет злоумышленнику атаковать других пользователей приложения, потенциально получая доступ к их данным, выполняя несанкционированные действия от их имени или осуществляя другие атаки против них.' },
    { title: 'Утечка информации (78%)', content: 'Это случаи, когда приложение разглашает конфиденциальную информацию, полезную злоумышленнику для разработки атаки на приложение, из-за дефектной обработки ошибок или другого поведения.' },
    { title: 'Подделка межсайтовых запросов (CSRF) (92%)', content: 'Этот недостаток означает, что пользователей приложения можно склонить к выполнению непреднамеренных действий в приложении в контексте их пользователя и уровня привилегий. Уязвимость позволяет вредоносному веб-сайту, посещенному пользователем-жертвой, взаимодействовать с приложением для выполнения действий, которые пользователь не намеревался совершать.' }
];

export function VulnerabilitiesSection() {
  return (
    <section id="vulnerabilities">
      <h2 className="text-2xl md:text-3xl font-bold text-center mb-2 text-primary/90">Распространенные Уязвимости</h2>
      <p className="text-center text-muted-foreground mb-8 md:mb-12 max-w-3xl mx-auto">
        Несмотря на заявления о безопасности и использование SSL, большинство веб-приложений уязвимы. Данные, основанные на тестировании сотен приложений, показывают тревожную картину. Наведите курсор на столбцы диаграммы для получения точных значений.
      </p>
      <Card className="p-4 md:p-6 shadow-md">
        <CardContent className="pt-6">
          <div className="relative w-full max-w-3xl mx-auto h-[300px] md:h-[400px]">
            <Bar options={vulnerabilityChartOptions} data={vulnerabilityChartData} />
          </div>
        </CardContent>
      </Card>
      <div className="mt-10 md:mt-12">
        <p className="text-center text-muted-foreground mb-8 max-w-3xl mx-auto">
          Нажмите на каждую категорию, чтобы узнать больше о конкретной уязвимости и о том, как она используется злоумышленниками.
        </p>
        <Accordion type="single" collapsible className="w-full max-w-4xl mx-auto space-y-3">
          {accordionData.map((item, index) => (
            <AccordionItem value={`item-${index}`} key={index} className="border bg-card rounded-md shadow-sm hover:shadow-md transition-shadow">
              <AccordionTrigger className="p-4 md:p-5 text-left font-semibold text-foreground/90 hover:no-underline">
                {item.title}
              </AccordionTrigger>
              <AccordionContent className="p-4 md:p-5 pt-0 text-muted-foreground">
                {item.content}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </div>
    </section>
  );
}
