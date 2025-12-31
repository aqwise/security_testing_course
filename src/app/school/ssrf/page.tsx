'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, Server, Globe, Search, Network, Info, Scan, ShieldCheck } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function SsrfPage() {
    return (
        <ContentPageLayout
            title="SSRF"
            subtitle="Server-Side Request Forgery"
        >
            <div className="space-y-8">
                {/* Source Link */}
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4066115981/SSRF"
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — SSRF <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Theory */}
                <section>
                    <H2>Теория</H2>
                    <Alert className="mt-4">
                        <Server className="h-4 w-4" />
                        <AlertTitle>Определение</AlertTitle>
                        <AlertDescription>
                            <strong>SSRF (Server-Side Request Forgery)</strong> — уязвимость, позволяющая злоумышленнику заставить серверное приложение
                            выполнять HTTP-запросы к произвольным ресурсам. Это позволяет атаковать внутреннюю сеть (admin panels, databases)
                            или внешние сервисы от имени доверенного сервера.
                        </AlertDescription>
                    </Alert>

                    <div className="grid gap-6 md:grid-cols-2 mt-6">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Globe className="h-5 w-5 text-primary" />
                                    Как это работает?
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Сервер принимает URL от пользователя (например, для загрузки аватарки) и делает к нему запрос без должной проверки.
                                Хакер может подставить <code>http://localhost/admin</code> или <code>file:///etc/passwd</code>.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <Network className="h-5 w-5 text-destructive" />
                                    Отличие от LFI
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                <strong>LFI/Path Traversal</strong> читает файлы локально. <br />
                                <strong>SSRF</strong> выполняет полноценный сетевой запрос (HTTP, FTP, Gopher и др.), что дает доступ к сервисам на других портах и серверах.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Detection */}
                <section>
                    <H2>Как искать?</H2>
                    <div className="space-y-4 mt-4">
                        <Card>
                            <CardContent className="pt-6">
                                <ul className="space-y-2 text-sm text-muted-foreground">
                                    <li className="flex items-center gap-2">
                                        <Search className="h-4 w-4 text-primary" />
                                        Параметры в URL: <code>?url=</code>, <code>?image=</code>, <code>?proxy=</code>, <code>?api_url=</code>, <code>?callback=</code>
                                    </li>
                                    <li className="flex items-center gap-2">
                                        <Info className="h-4 w-4 text-primary" />
                                        Используйте <strong>OAST (Out-of-band)</strong>: Burp Collaborator или webhook.site.
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <Scan className="h-4 w-4 text-primary shrink-0" />
                                        <span>
                                            <strong>Виды:</strong>
                                            <br />- <em>Basic:</em> Виден ответ сервера.
                                            <br />- <em>Blind:</em> Ответ не виден, судим по времени (Timing) или DNS запросам.
                                        </span>
                                    </li>
                                </ul>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Bypasses */}
                <section>
                    <H2>Техники обхода (Bypass)</H2>
                    <P className="text-muted-foreground mb-4">
                        Если <code>127.0.0.1</code> или <code>localhost</code> заблокированы:
                    </P>
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base">IP Variations</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm font-mono text-muted-foreground">
                                0.0.0.0<br />
                                [::]<br />
                                127.1
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base">Decimal / Octal / Hex</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm font-mono text-muted-foreground">
                                2130706433 (Decimal)<br />
                                0177.0.0.1 (Octal)<br />
                                0x7f000001 (Hex)
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base">Redirect & DNS</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                DNS Rebinding<br />
                                Redirect to localhost (302) from external site
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Tools */}
                <section>
                    <H2>Полезные ссылки</H2>
                    <div className="grid gap-2 text-sm mt-4">
                        <Link href="https://h.43z.one/ipconverter/" target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                            <ExternalLink className="h-4 w-4 text-primary" />
                            <span>IP Converter (h.43z.one) — перевод IP в разные форматы</span>
                        </Link>
                        <Link href="https://qaz.wtf/u/convert.cgi" target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                            <ExternalLink className="h-4 w-4 text-primary" />
                            <span>Unicode Text Converter — обход фильтров</span>
                        </Link>
                        <Link href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery" target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                            <ExternalLink className="h-4 w-4 text-primary" />
                            <span>PayloadsAllTheThings — SSRF Cheat Sheet</span>
                        </Link>
                    </div>
                </section>


                {/* Labs */}
                <section>
                    <H2>Домашнее задание (PortSwigger Labs)</H2>
                    <P className="mb-4">
                        Практика по теме <Link href="https://portswigger.net/web-security/ssrf" target="_blank" className="text-primary hover:underline">SSRF</Link>.
                    </P>
                    <div className="grid gap-2 text-sm">
                        {[
                            { title: 'Basic SSRF against the local server', url: 'https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost' },
                            { title: 'Basic SSRF against another back-end system', url: 'https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system' },
                            { title: 'SSRF with blacklist-based input filter', url: 'https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter' },
                            { title: 'SSRF with filter bypass via open redirection vulnerability', url: 'https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection' },
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
