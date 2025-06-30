'use client';

import { Card, CardContent } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"

const chartData = [
  { vulnerability: 'XSS', "Частота": 94 },
  { vulnerability: 'CSRF', "Частота": 92 },
  { vulnerability: 'Утечка информации', "Частота": 78 },
  { vulnerability: 'Контроль доступа', "Частота": 71 },
  { vulnerability: 'Аутентификация', "Частота": 62 },
  { vulnerability: 'SQL-инъекция', "Частота": 32 },
];

const chartConfig = {
  "Частота": {
    label: "Частота в протестированных приложениях (%)",
    color: "hsl(var(--chart-1))",
  },
} satisfies ChartConfig

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
        Несмотря на заявления о безопасности и использование SSL, большинство веб-приложений уязвимы. Данные, основанные на тестировании сотен приложений, показывают тревожную картину.
      </p>
      <Card className="p-4 md:p-6 shadow-md">
        <CardContent className="pt-6">
          <ChartContainer config={chartConfig} className="h-[400px] w-full">
            <BarChart
              accessibilityLayer
              data={chartData}
              layout="vertical"
              margin={{ left: 20 }}
            >
              <CartesianGrid horizontal={false} />
              <YAxis
                dataKey="vulnerability"
                type="category"
                tickLine={false}
                tickMargin={10}
                axisLine={false}
                className="fill-muted-foreground"
                tickFormatter={(value) => value.length > 25 ? `${value.slice(0, 25)}...` : value}
              />
              <XAxis dataKey="Частота" type="number" hide />
              <ChartTooltip
                cursor={false}
                content={<ChartTooltipContent hideLabel />}
              />
              <Bar dataKey="Частота" layout="vertical" radius={5} />
            </BarChart>
          </ChartContainer>
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
