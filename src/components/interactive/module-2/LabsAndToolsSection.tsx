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

const labFocusChartData = [
  { lab: 'PortSwigger (Info Discl.)', Релевантность: 7 },
  { lab: 'Juice Shop (API/Hidden)', Релевантность: 8 },
  { lab: 'DVWA (Cmd/File Incl.)', Релевантность: 6 },
  { lab: 'TryHackMe (Content Disc.)', Релевантность: 9 },
  { lab: 'TryHackMe (Subdomain Enum.)', Релевантность: 7 },
];

const labFocusChartConfig = {
  "Релевантность": {
    label: "Релевантность Темам Модуля II (1-10)",
    color: "hsl(var(--chart-1))",
  },
} satisfies ChartConfig;


export function LabsAndToolsSection() {
  return (
    <section id="labs-mod2" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            D. Рекомендуемые Лаборатории и Инструменты
          </h2>
          <p className="mt-2 max-w-2xl mx-auto text-lg text-muted-foreground">
            Практические ресурсы и ключевые инструменты для отработки навыков разведки и картирования.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
          <div className="bg-background/70 p-6 rounded-xl border">
            <h3 className="text-xl font-semibold text-primary mb-3">🎯 Учебные Платформы</h3>
            <ul className="space-y-2 text-muted-foreground">
              <li><strong><Link href="https://portswigger.net/web-security" target="_blank" rel="noopener noreferrer" className={LinkStyle}>PortSwigger Academy</Link>:</strong> Лабы по <Link href="https://portswigger.net/web-security/information-disclosure" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Information disclosure</Link>, <Link href="https://portswigger.net/web-security/file-path-traversal" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Path traversal</Link>, <Link href="https://portswigger.net/web-security/api-testing" target="_blank" rel="noopener noreferrer" className={LinkStyle}>API testing</Link>.</li>
              <li><strong><Link href="https://owasp.org/www-project-juice-shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP Juice Shop</Link>:</strong> Задания на Score Board, Admin Section, исследование API (/metrics), поиск backup files. <Link href="https://pwning.owasp-juice.shop/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Руководство</Link>.</li>
              <li><strong><Link href="http://www.dvwa.co.uk/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>DVWA</Link>:</strong> Модули Command Injection, File Inclusion. Используйте Dirb/Gobuster.</li>
              <li><strong><Link href="https://tryhackme.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>TryHackMe</Link>:</strong> Комнаты "<Link href="https://tryhackme.com/room/howthewebworks" target="_blank" rel="noopener noreferrer" className={LinkStyle}>How The Web Works</Link>", "<Link href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className={LinkStyle}>HTTP in Detail</Link>", "<Link href="https://tryhackme.com/room/contentdiscovery" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Content Discovery</Link>", "<Link href="https://tryhackme.com/room/subdomainenumeration" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Subdomain Enumeration</Link>", "<Link href="https://tryhackme.com/room/walkinganapplication" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Walking An Application</Link>".</li>
            </ul>
          </div>
          <div className="bg-background/70 p-6 rounded-xl border">
            <h3 className="text-xl font-semibold text-primary mb-3">🛠️ Ключевые Инструменты</h3>
            <ul className="space-y-2 text-muted-foreground">
              <li><Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Suite</Link> (Proxy, Spider, Target, Repeater, Intruder, Content Discovery)</li>
              <li>Инструменты разработчика браузера</li>
              <li><Link href="https://nmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Nmap</Link></li>
              <li><Link href="https://github.com/OJ/gobuster" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Gobuster</Link>, <Link href="https://tools.kali.org/information-gathering/dirb" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Dirb</Link>, <Link href="https://github.com/ffuf/ffuf" target="_blank" rel="noopener noreferrer" className={LinkStyle}>ffuf</Link></li>
              <li><Link href="https://github.com/aboul3la/Sublist3r" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Sublist3r</Link>, <Link href="https://github.com/OWASP/Amass" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Amass</Link></li>
            </ul>
          </div>
        </div>
         <Card className="shadow-lg rounded-xl border border-border">
          <CardContent className="p-4 md:p-6">
            <ChartContainer config={labFocusChartConfig} className="h-[500px] w-full">
              <BarChart accessibilityLayer data={labFocusChartData} layout="vertical" margin={{ left: 20 }}>
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
