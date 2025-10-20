'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Target, BookOpen, Award } from 'lucide-react';
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

            <Card className="opacity-50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-6 w-6" />
                  Аутентификация
                </CardTitle>
                <CardDescription>Скоро...</CardDescription>
              </CardHeader>
            </Card>

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
