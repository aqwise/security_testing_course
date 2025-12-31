'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, Globe, Lock, ArrowRight, ShieldCheck, Server } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function CorsCsrfPage() {
    return (
        <ContentPageLayout
            title="CORS & CSRF"
            subtitle="Безопасность междоменных запросов"
        >
            <div className="space-y-8">
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4041113655/CORS+и+CSRF"
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — CORS и CSRF <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Definitions */}
                <section>
                    <H2>Определения и Различия</H2>
                    <div className="grid gap-6 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Globe className="h-5 w-5 text-primary" />
                                    CORS
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="font-medium">Cross-Origin Resource Sharing</p>
                                <P className="text-sm text-muted-foreground mt-2">
                                    Механизм браузера, решающий, можно ли сайту с одного домена <strong>читать данные</strong> с другого.
                                    Контролирует доступ к ресурсам.
                                </P>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <ShieldAlert className="h-5 w-5 text-destructive" />
                                    CSRF
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="font-medium">Cross-Site Request Forgery</p>
                                <P className="text-sm text-muted-foreground mt-2">
                                    Атака, заставляющая браузер пользователя выполнить <strong>нежелательное действие</strong> (перевод денег, смена пароля)
                                    на доверенном сайте, где пользователь авторизован.
                                </P>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* SOP */}
                <section>
                    <H2>SOP (Same-Origin Policy)</H2>
                    <Alert className="mt-4">
                        <Lock className="h-4 w-4" />
                        <AlertTitle>Политика одного источника</AlertTitle>
                        <AlertDescription>
                            Базовый механизм безопасности. Доступ разрешен только если совпадают:
                            <ul className="list-disc list-inside mt-2 font-medium">
                                <li>Протокол (http/https)</li>
                                <li>Домен</li>
                                <li>Порт</li>
                            </ul>
                            CORS позволяет безопасно ослабить это ограничение.
                        </AlertDescription>
                    </Alert>
                </section>

                {/* CSRF Scenario */}
                <section>
                    <H2>Сценарий CSRF атаки</H2>
                    <div className="flex flex-col md:flex-row items-center gap-4 mt-6 text-sm text-muted-foreground bg-muted p-6 rounded-lg overflow-x-auto">
                        <div className="flex flex-col items-center gap-2 text-center min-w-[120px]">
                            <div className="bg-background p-3 rounded-full border shadow-sm">
                                <Globe className="h-6 w-6 text-blue-500" />
                            </div>
                            <span>1. Пользователь логинится в bank.com</span>
                        </div>
                        <ArrowRight className="h-5 w-5 hidden md:block" />
                        <div className="flex flex-col items-center gap-2 text-center min-w-[120px]">
                            <div className="bg-background p-3 rounded-full border shadow-sm">
                                <ShieldAlert className="h-6 w-6 text-red-500" />
                            </div>
                            <span>2. Заходит на evil.com (ссылка/письмо)</span>
                        </div>
                        <ArrowRight className="h-5 w-5 hidden md:block" />
                        <div className="flex flex-col items-center gap-2 text-center min-w-[120px]">
                            <div className="bg-background p-3 rounded-full border shadow-sm">
                                <Server className="h-6 w-6 text-purple-500" />
                            </div>
                            <span>3. evil.com шлет скрытый запрос к bank.com</span>
                        </div>
                        <ArrowRight className="h-5 w-5 hidden md:block" />
                        <div className="flex flex-col items-center gap-2 text-center min-w-[120px]">
                            <div className="bg-background p-3 rounded-full border shadow-sm">
                                <ShieldCheck className="h-6 w-6 text-green-600" />
                            </div>
                            <span>4. Браузер добавляет куки &rarr; Деньги ушли</span>
                        </div>
                    </div>
                </section>

                {/* Prevention */}
                <section>
                    <H2>Методы защиты</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">1. CSRF Tokens</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Уникальный, непредсказуемый токен для каждой сессии или запроса. Сервер проверяет его наличие при каждом изменении данных.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">2. SameSite Cookie</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Атрибут <code>SameSite=Strict</code> или <code>Lax</code> запрещает отправку кук при сторонних запросах.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">3. CORS Configuration</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Строгий белый список доменов в <code>Access-Control-Allow-Origin</code>. Никогда не использовать <code>null</code> или wildcard <code>*</code> с Credentials.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">4. Origin Verification</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Проверка заголовков <code>Origin</code> и <code>Referer</code> на сервере.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Labs */}
                <section>
                    <H2>Домашнее задание (PortSwigger Labs)</H2>
                    <P className="mb-4">
                        Практика по темам <Link href="https://portswigger.net/web-security/cors" target="_blank" className="text-primary hover:underline">CORS</Link> и <Link href="https://portswigger.net/web-security/csrf" target="_blank" className="text-primary hover:underline">CSRF</Link>.
                    </P>
                    <div className="grid gap-2 text-sm">
                        {[
                            { title: 'CORS vulnerability with basic origin reflection', url: 'https://portswigger.net/web-security/cors/lab-basic-origin-reflection' },
                            { title: 'CORS vulnerability with trusted null origin', url: 'https://portswigger.net/web-security/cors/lab-null-origin' },
                            { title: 'CSRF vulnerability with no defenses', url: 'https://portswigger.net/web-security/csrf/lab-no-defenses' },
                            { title: 'CSRF where token validation depends on request method', url: 'https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method' },
                            { title: 'CSRF where token is not tied to user session', url: 'https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session' },
                        ].map((lab, i) => (
                            <Link key={i} href={lab.url} target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                                <ExternalLink className="h-4 w-4 text-primary" />
                                <span>{i + 1}. {lab.title}</span>
                            </Link>
                        ))}
                    </div>
                </section>

                {/* Quiz Section */}
                <section>
                    <H2>Проверка знаний</H2>
                    <div className="space-y-6 mt-4">
                        {quizQuestions.map((q, index) => (
                            <QuizItem
                                key={index}
                                question={q.question}
                                answers={q.answers}
                                correctAnswerIndex={q.correctAnswerIndex}
                            />
                        ))}
                    </div>
                </section>
            </div>
        </ContentPageLayout>
    );
}
