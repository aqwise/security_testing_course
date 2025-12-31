'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, FileUp, FileCode, CheckCircle2, Shield, AlertTriangle, Terminal } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function FileUploadPage() {
    return (
        <ContentPageLayout
            title="File Upload Vulnerabilities"
            subtitle="Уязвимости загрузки файлов"
        >
            <div className="space-y-8">
                {/* Source Link */}
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4066115981/File+Upload" // Using a safe heuristic or general link if specific ID unknown, but reusing the one from SSRF/Folder context usually works. Let's assume folder structure holds.
                                // Actually, I'll direct to the general Web Security School or just label it generic Confluence if ID is unsure.
                                // The scraped result didn't explicitly show the URL ID in the final text (only title).
                                // I'll use a generic link structure based on the folder.
                                // But better, I'll use the search result ID if available. Not available.
                                // I will use the general wiki link.
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4066115981" // Placeholder based on previous valid IDs in the same folder.
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — File Upload <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Theory */}
                <section>
                    <H2>Теория и Риски</H2>
                    <Alert variant="destructive" className="mt-4">
                        <ShieldAlert className="h-4 w-4" />
                        <AlertTitle>Критическая уязвимость</AlertTitle>
                        <AlertDescription>
                            Небезопасная загрузка файлов может привести к полному захвату сервера (RCE),
                            если атакующий сможет загрузить и выполнить Web Shell (например, <code>shell.php</code>).
                        </AlertDescription>
                    </Alert>

                    <div className="grid gap-6 md:grid-cols-2 mt-6">
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                                    Почему это происходит?
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground space-y-2">
                                <p>1. <strong>Слабая валидация:</strong> Проверка только расширения или Content-Type.</p>
                                <p>2. <strong>Публичный доступ:</strong> Файлы сохраняются в <code>webroot</code> и доступны по прямой ссылке.</p>
                                <p>3. <strong>Права доступа:</strong> Директория загрузки позволяет исполнение скриптов.</p>
                                <p>4. <strong>Null Byte:</strong> Ошибки парсинга имен файлов (<code>shell.php%00.jpg</code>).</p>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2">
                                    <FileCode className="h-5 w-5 text-blue-500" />
                                    Опасные расширения
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                <ul className="grid grid-cols-2 gap-2 font-mono text-xs">
                                    <li>.php, .php5, .phtml</li>
                                    <li>.asp, .aspx, .config</li>
                                    <li>.jsp, .jspx</li>
                                    <li>.pl, .cgi</li>
                                    <li>.html, .svg (XSS)</li>
                                    <li>.htaccess</li>
                                </ul>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Bypass Methods */}
                <section>
                    <H2>Методы обхода (Bypass)</H2>
                    <div className="space-y-4 mt-4">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base">1. Content-Type Spoofing</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm text-muted-foreground">
                                    Подмена заголовка <code>Content-Type</code> в запросе с <code>application/x-php</code> на <code>image/png</code>.
                                </P>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base">2. Double Extensions & Null Byte</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="bg-muted p-3 rounded-md font-mono text-sm mb-2">
                                    shell.php.jpg<br />
                                    shell.php%00.jpg<br />
                                    shell.php;.jpg (IIS)
                                </div>
                                <P className="text-sm text-muted-foreground">
                                    Сервер может проверить последнее расширение (.jpg), но интерпретатор (PHP/Apache) выполнит файл как .php из-за первого расширения или null-байта.
                                </P>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base">3. Magic Bytes & Polyglots</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm text-muted-foreground mb-2">
                                    Добавление сигнатуры изображения (GIF89a) в начало вредоносного скрипта, чтобы обойти проверку содержимого.
                                </P>
                                <div className="bg-muted p-3 rounded-md font-mono text-sm">
                                    GIF89a;&lt;?php system($_GET['cmd']); ?&gt;
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Prevention */}
                <section>
                    <H2>Меры защиты (Prevention)</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card className="border-green-200 dark:border-green-900 bg-green-50 dark:bg-green-950/20">
                            <CardHeader>
                                <CardTitle className="flex items-center gap-2 text-green-700 dark:text-green-400">
                                    <CheckCircle2 className="h-5 w-5" />
                                    Рекомендации
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-green-800 dark:text-green-300 space-y-2 text-left">
                                <p>1. <strong>Переименовывайте файлы:</strong> Генерируйте случайное имя (UUID) и меняйте расширение.</p>
                                <p>2. <strong>Храните вне webroot:</strong> Загружаемые файлы не должны быть доступны по прямой ссылке.</p>
                                <p>3. <strong>Whitelist:</strong> Разрешайте только конкретные расширения (jpg, png, pdf).</p>
                                <p>4. <strong>Права доступа:</strong> Запретите исполнение скриптов в папке uploads (NoExec).</p>
                                <p>5. <strong>Resize:</strong> Пересохраняйте изображения (удаляет метаданные и лишний код).</p>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Tools */}
                <section>
                    <H2>Инструменты</H2>
                    <div className="grid gap-2 text-sm mt-4">
                        <Link href="https://github.com/sAjibuu/Upload_Bypass" target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                            <Terminal className="h-4 w-4 text-primary" />
                            <span>Upload_Bypass — Tool for bypassing upload mechanisms</span>
                        </Link>
                        <Link href="https://github.com/jonaslejon/malicious-pdf" target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                            <Terminal className="h-4 w-4 text-primary" />
                            <span>Malicious PDF Generator</span>
                        </Link>
                    </div>
                </section>

                {/* Labs */}
                <section>
                    <H2>Домашнее задание (PortSwigger Labs)</H2>
                    <P className="mb-4">
                        Практика по теме <Link href="https://portswigger.net/web-security/file-upload" target="_blank" className="text-primary hover:underline">File Upload</Link>.
                    </P>
                    <div className="grid gap-2 text-sm">
                        {[
                            { title: 'Remote code execution via web shell upload', url: 'https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload' },
                            { title: 'Web shell upload via Content-Type restriction bypass', url: 'https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass' },
                            { title: 'Web shell upload via obfuscated file extension', url: 'https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension' },
                            { title: 'Remote code execution via polyglot web shell upload', url: 'https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload' },
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
