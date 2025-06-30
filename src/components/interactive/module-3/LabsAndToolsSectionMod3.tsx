'use client';

import Link from 'next/link';
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const labFocusChartDataMod3 = [
  { lab: 'PortSwigger (Аутентификация)', Релевантность: 9 },
  { lab: 'PortSwigger (Контроль Доступа)', Релевантность: 8 },
  { lab: 'OWASP Juice Shop (Аутентиф./JWT)', Релевантность: 7 },
  { lab: 'OWASP Juice Shop (Контроль Доступа)', Релевантность: 7 },
  { lab: 'DVWA (Брутфорс)', Релевантность: 6 },
  { lab: 'TryHackMe (IDOR/Auth Bypass)', Релевантность: 8 },
];

const labFocusChartConfigMod3 = {
  "Релевантность": {
    label: "Релевантность Темам Модуля III (1-10)",
    color: "hsl(var(--chart-1))",
  },
} satisfies ChartConfig;

export function LabsAndToolsSectionMod3() {
  return (
    <section id="labs-mod3" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            D. Рекомендуемые Лаборатории и Инструменты
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Практические ресурсы и ключевые инструменты для отработки атак на аутентификацию, сессии и контроль доступа.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
          <Card className="bg-background/70 shadow-md">
            <CardHeader>
                <CardTitle className="text-xl font-semibold text-primary mb-0">🎯 Учебные Платформы</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground">
                <li><strong><Link href="https://portswigger.net/web-security" target="_blank" rel="noopener noreferrer" className={LinkStyle}>PortSwigger Academy</Link>:</strong> Лабы по <Link href="https://portswigger.net/web-security/authentication" target="_blank" rel="noopener noreferrer" className={LinkStyle}>аутентификации</Link> (перечисление, обход 2FA, сброс пароля, брутфорс "remember me"), <Link href="https://portswigger.net/web-security/access-control" target="_blank" rel="noopener noreferrer" className={LinkStyle}>контролю доступа</Link> (IDOR, обход по методу), <Link href="https://portswigger.net/web-security/jwt" target="_blank" rel="noopener noreferrer" className={LinkStyle}>JWT</Link>.</li>
                <li><strong><Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP Juice Shop</Link>:</strong> Категории "Broken Authentication", "Broken Access Control", задания с JWT. <Link href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Руководство</Link>.</li>
                <li><strong><Link href="http://www.dvwa.co.uk/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>DVWA</Link>:</strong> Модули Brute Force, CSRF (для понимания токенов сессии).</li>
                <li><strong><Link href="https://tryhackme.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>TryHackMe</Link>:</strong> Комнаты <Link href="https://tryhackme.com/room/hydra" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Hydra</Link>, <Link href="https://tryhackme.com/room/bruteforceheroes" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Brute Force Heroes</Link>, <Link href="https://tryhackme.com/room/idor" target="_blank" rel="noopener noreferrer" className={LinkStyle}>IDOR</Link>, <Link href="https://tryhackme.com/room/authenticationbypass" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Authentication Bypass</Link>.</li>
              </ul>
            </CardContent>
          </Card>
          <Card className="bg-background/70 shadow-md">
             <CardHeader>
                <CardTitle className="text-xl font-semibold text-primary mb-0">🛠️ Ключевые Инструменты</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-muted-foreground">
                <li><Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Suite</Link> (Intruder, Sequencer, Repeater, Comparer, <Link href="https://portswigger.net/bappstore/f9bb5f0207e34820b83d49d70958ac94" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Autorize ext.</Link>, <Link href="https://portswigger.net/bappstore/jwt-editor" target="_blank" rel="noopener noreferrer" className={LinkStyle}>JWT Editor ext.</Link>)</li>
                <li><Link href="https://github.com/vanhauser-thc/thc-hydra" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Hydra</Link></li>
              </ul>
            </CardContent>
          </Card>
        </div>
        <Card className="shadow-lg rounded-xl border border-border">
          <CardContent className="p-4 md:p-6">
            <ChartContainer config={labFocusChartConfigMod3} className="h-[500px] w-full">
              <BarChart accessibilityLayer data={labFocusChartDataMod3} layout="vertical" margin={{ left: 20 }}>
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
      </div>
    </section>
  );
}
