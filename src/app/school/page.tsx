'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Target, BookOpen, Award, KeyRound, Wrench, Globe, Server, FileUp } from 'lucide-react';
import Link from 'next/link';

export default function SchoolPage() {
  return (
    <ContentPageLayout title="Школа Безопасности">
      <div className="space-y-8">
        <section>
          <P>
            Добро пожаловать в Школу Безопасности! Здесь вы найдете структурированные курсы по различным аспектам
            безопасности веб-приложений, основанные на реальных практиках и лучших источниках индустрии.
          </P>
        </section>

        <section>
          <H2>Доступные курсы</H2>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <Link href="/school/injections">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-6 w-6 text-primary" />
                    Инъекции
                  </CardTitle>
                  <CardDescription>
                    Изучение различных типов инъекций: SQL, XSS, Command, HTML, XXE
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>5+ типов уязвимостей</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Теория и практика</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Реальные примеры</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/broken-access-control">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-6 w-6 text-destructive" />
                    Broken Access Control
                  </CardTitle>
                  <CardDescription>
                    Нарушение контроля доступа, IDOR и повышение привилегий
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>IDOR, Privilege Escalation</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Теория и практика</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Лабораторные PortSwigger</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/broken-authentication">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <KeyRound className="h-6 w-6 text-destructive" />
                    Broken Authentication
                  </CardTitle>
                  <CardDescription>
                    Атаки на аутентификацию, сессии и JWT
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>Brute-force, Session Hijacking</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Теория и практика</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Лабораторные PortSwigger</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/sensitive-data-exposure">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-6 w-6 text-warning" />
                    Sensitive Data Exposure
                  </CardTitle>
                  <CardDescription>
                    Утечки данных, PII, секреты в коде и конфигурациях
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>MitM, Weak Crypto, PII Leaks</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Теория и чек-листы</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Инструменты поиска</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/security-misconfiguration">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Wrench className="h-6 w-6 text-orange-500" />
                    Security Misconfiguration
                  </CardTitle>
                  <CardDescription>
                    Ошибки настройки, дефолтные конфиги, лишние службы
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>CVE, Headers, Default Creds</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Hardening Checklist</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Лабораторные PortSwigger</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/cors-csrf">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Globe className="h-6 w-6 text-blue-500" />
                    CORS & CSRF
                  </CardTitle>
                  <CardDescription>
                    Безопасность междоменных запросов (SOP, Origin, Tokens)
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>Origin Reflection, CSRF Attack</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Теория и методы защиты</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Лабораторные PortSwigger</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/ssrf">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Server className="h-6 w-6 text-indigo-500" />
                    SSRF
                  </CardTitle>
                  <CardDescription>
                    Server-Side Request Forgery и доступ к внутренней сети
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>Internal Scanning, Cloud Metadata</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Bypasses (Decimal IP, Redir)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Лабораторные PortSwigger</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Link href="/school/file-upload">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileUp className="h-6 w-6 text-pink-500" />
                    File Upload
                  </CardTitle>
                  <CardDescription>
                    Загрузка вредоносных файлов, Web Shell, RCE
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      <span>Web Shell, RCE, DoS</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>Bypasses (Extensions, MIME)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" />
                      <span>Лабораторные PortSwigger</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>

            <Card className="opacity-50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-6 w-6" />
                  Криптография
                </CardTitle>
                <CardDescription>Скоро...</CardDescription>
              </CardHeader>
            </Card>
          </div>
        </section>
      </div>
    </ContentPageLayout>
  );
}
