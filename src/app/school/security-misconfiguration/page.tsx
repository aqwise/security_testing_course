'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, Settings, AlertTriangle, CheckCircle2, Wrench, Search, Lock } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function SecurityMisconfigurationPage() {
    return (
        <ContentPageLayout
            title="Security Misconfiguration"
            subtitle="Неправильная настройка безопасности"
        >
            <div className="space-y-8">
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4046717620/Security+Misconfiguration"
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — Security Misconfiguration <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Theory */}
                <section>
                    <Alert>
                        <ShieldAlert className="h-4 w-4" />
                        <AlertTitle>Что это такое?</AlertTitle>
                        <AlertDescription>
                            Security Misconfiguration возникает, когда компоненты инфраструктуры (веб-сервер, БД, фреймворки)
                            настроены небезопасно или используют настройки по умолчанию. Это может происходить на любом уровне стека:
                            от сетевых служб до уровня приложения.
                        </AlertDescription>
                    </Alert>

                    <div className="mt-6 grid gap-4 md:grid-cols-2">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Settings className="h-4 w-4 text-primary" />
                                    Примеры ошибок
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm">
                                <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                                    <li>Включенные по умолчанию аккаунты (admin/admin).</li>
                                    <li>Открытые облачные хранилища (S3 Buckets).</li>
                                    <li>Отсутствие флагов безопасности у Cookies (HttpOnly, Secure).</li>
                                    <li>Подробные сообщения об ошибках (Stack Traces).</li>
                                </ul>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <AlertTriangle className="h-4 w-4 text-destructive" />
                                    Влияние (Impact)
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Позволяет злоумышленникам получить несанкционированный доступ к данным (кража сессий),
                                функциям системы или полностью скомпрометировать сервер.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Attacks */}
                <section>
                    <H2>Процесс эксплуатации (Attacks)</H2>
                    <div className="space-y-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">1. Компоненты с известными уязвимостями (CVE)</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm text-muted-foreground mb-4">
                                    Поиск уязвимостей в старых версиях ПО.
                                </P>
                                <div className="grid gap-2 text-sm">
                                    <div className="flex items-center gap-2 border p-2 rounded">
                                        <Search className="h-4 w-4 text-primary" />
                                        <span><strong>Wappalyzer:</strong> Определение версий технологий.</span>
                                    </div>
                                    <div className="flex items-center gap-2 border p-2 rounded">
                                        <Search className="h-4 w-4 text-primary" />
                                        <span><strong>Exploit DB / CVE:</strong> Поиск готовых эксплойтов (<code>wordpress 6.2.2 vulnerabilities</code>).</span>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">2. Анализ заголовков (Headers)</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm text-muted-foreground mb-2">Отсутствие важных заголовков безопасности:</P>
                                <ul className="grid gap-2 text-sm text-muted-foreground sm:grid-cols-2">
                                    <li className="flex items-center gap-2"><div className="h-1.5 w-1.5 rounded-full bg-red-500" />X-Frame-Options (Clickjacking)</li>
                                    <li className="flex items-center gap-2"><div className="h-1.5 w-1.5 rounded-full bg-red-500" />X-XSS-Protection</li>
                                    <li className="flex items-center gap-2"><div className="h-1.5 w-1.5 rounded-full bg-red-500" />Content-Security-Policy (CSP)</li>
                                    <li className="flex items-center gap-2"><div className="h-1.5 w-1.5 rounded-full bg-red-500" />Strict-Transport-Security (HSTS)</li>
                                </ul>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">3. Дефолтные учетные данные</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm text-muted-foreground">
                                    Проверка стандартных пар: <code>admin/admin</code>, <code>root/root</code>, <code>guest/guest</code>, <code>123456</code>.
                                </P>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Tools & Checklist */}
                <section>
                    <div className="grid gap-6 md:grid-cols-2">
                        <div>
                            <H2>Инструменты поиска</H2>
                            <ul className="space-y-2 mt-4">
                                <li className="border p-3 rounded-md text-sm">
                                    <strong>Nuclei:</strong> Сканирование по шаблонам.
                                </li>
                                <li className="border p-3 rounded-md text-sm">
                                    <strong>Nmap:</strong> <code>nmap -Pn -sV -sC -O [target]</code> (поиск портов и служб).
                                </li>
                                <li className="border p-3 rounded-md text-sm">
                                    <strong>Вызов ошибок:</strong> Ввод спецсимволов для получения Stack Trace.
                                </li>
                                <li className="border p-3 rounded-md text-sm">
                                    <strong>Debug Mode:</strong> Проверка <code>Debuggable=True</code> на проде.
                                </li>
                            </ul>
                        </div>
                        <div>
                            <H2>Чек-лист Cookie</H2>
                            <Card className="mt-4 h-fit">
                                <CardContent className="pt-6">
                                    <ul className="space-y-4">
                                        <li className="flex items-start gap-3">
                                            <CheckCircle2 className="h-5 w-5 text-green-600 shrink-0" />
                                            <div className="text-sm">
                                                <strong>Session ID:</strong> Уникален, случаен, непредсказуем.
                                            </div>
                                        </li>
                                        <li className="flex items-start gap-3">
                                            <CheckCircle2 className="h-5 w-5 text-green-600 shrink-0" />
                                            <div className="text-sm">
                                                <strong>Remember Me:</strong> Токен надежно зашифрован, не содержит данных в открытом виде.
                                            </div>
                                        </li>
                                        <li className="flex items-start gap-3">
                                            <CheckCircle2 className="h-5 w-5 text-green-600 shrink-0" />
                                            <div className="text-sm">
                                                <strong>CSRF Token:</strong> Присутствует и уникален для защиты от подделки запросов.
                                            </div>
                                        </li>
                                    </ul>
                                </CardContent>
                            </Card>
                        </div>
                    </div>
                </section>

                {/* Remediation */}
                <section>
                    <H2>Рекомендации (Remediation)</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Wrench className="h-4 w-4 text-primary" />
                                    Hardening
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Отключение ненужных служб, портов API и неиспользуемых функций фреймворка.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Lock className="h-4 w-4 text-primary" />
                                    Безопасные конфиги
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Смена всех дефолтных паролей. Настройка Security Headers. Обновление ПО.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Labs */}
                <section>
                    <H2>Домашнее задание (PortSwigger Labs)</H2>
                    <P className="mb-4">
                        Практика по темам <Link href="https://portswigger.net/web-security/file-path-traversal" target="_blank" className="text-primary hover:underline">Path Traversal</Link> и <Link href="https://portswigger.net/web-security/clickjacking" target="_blank" className="text-primary hover:underline">Clickjacking</Link>.
                    </P>
                    <div className="grid gap-2 text-sm">
                        {[
                            { title: 'File path traversal, simple case', url: 'https://portswigger.net/web-security/file-path-traversal/lab-simple-case' },
                            { title: 'File path traversal, traversal sequences blocked with absolute path bypass', url: 'https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass' },
                            { title: 'File path traversal, traversal sequences stripped non-recursively', url: 'https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively' },
                            { title: 'File path traversal, traversal sequences stripped with superfluous URL-decode', url: 'https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode' },
                            { title: 'File path traversal, validation of start of path', url: 'https://portswigger.net/web-security/file-path-traversal/lab-validation-of-start-of-path' },
                            { title: 'File path traversal, validation of file extension with null byte bypass', url: 'https://portswigger.net/web-security/file-path-traversal/lab-validation-of-file-extension-with-null-byte-bypass' },
                            { title: 'Basic clickjacking with CSRF token protection', url: 'https://portswigger.net/web-security/clickjacking/lab-basic-clickjacking-with-csrf-token-protection' },
                            { title: 'Clickjacking with a frame buster script', url: 'https://portswigger.net/web-security/clickjacking/lab-clickjacking-with-a-frame-buster-script' },
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
