'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, KeyRound, Lock, UserCheck, Shield } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function BrokenAuthenticationPage() {
    return (
        <ContentPageLayout
            title="Broken Authentication"
            subtitle="Уязвимости аутентификации и управления сессиями"
        >
            <div className="space-y-8">
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4041408529/Broken+Authentication"
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — Broken Authentication <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Intro */}
                <section>
                    <Alert>
                        <ShieldAlert className="h-4 w-4" />
                        <AlertTitle>Что такое Broken Authentication?</AlertTitle>
                        <AlertDescription>
                            Уязвимости аутентификации позволяют злоумышленникам компрометировать пароли, ключи или токены сессий,
                            чтобы временно или постоянно захватывать учетные записи пользователей. Это часто происходит из-за
                            слабой защиты учетных данных, отсутствия ротации сессий или возможности перебора.
                        </AlertDescription>
                    </Alert>
                    <P className="mt-4">
                        Важно различать <strong>Аутентификацию</strong> (проверка того, кем является пользователь) и
                        <strong> Авторизацию</strong> (проверка того, что пользователю разрешено делать).
                        Broken Authentication атакует первый этап.
                    </P>
                </section>

                {/* Common Vulnerabilities */}
                <section>
                    <H2>Распространенные проблемы</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">1. Слабые пароли</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Использование слабых, дефолтных или часто используемых паролей.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">2. Brute-force</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Отсутствие защиты от перебора паролей и Credential Stuffing атак.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">3. Нет MFA</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Отсутствие многофакторной аутентификации (MFA), особенно для важных действий.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">4. Незащищенные каналы</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Передача учетных данных по HTTP или в URL-адресе.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">5. Слабое хеширование</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Использование устаревших алгоритмов (MD5, SHA1) без соли.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">6. Session ID в URL</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Раскрытие идентификаторов сессий (Session ID) в адресной строке.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">7. Управление сессиями</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Отсутствие инвалидации сессии после выхода или длительного простоя (таймаута).
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">8. Восстановление пароля</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Уязвимая логика восстановления пароля (например, подсказки о существовании пользователя).
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Prevention: AAL Levels */}
                <section>
                    <H2>Уровни гарантии аутентификации (NIST AAL)</H2>
                    <div className="grid gap-4 md:grid-cols-3 mt-4">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <UserCheck className="h-4 w-4 text-primary" />
                                    AAL 1
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Однофакторная аутентификация (обычно пароль). Требует надежных паролей и защиты от перебора.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <KeyRound className="h-4 w-4 text-primary" />
                                    AAL 2
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Двухфакторная аутентификация (MFA). Пароль + что-то, чем владеете (код из SMS, приложение).
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Shield className="h-4 w-4 text-primary" />
                                    AAL 3
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Аппаратный токен, криптографическая подпись. Самый высокий уровень защиты.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Tech Details: JWT & Cookies */}
                <section>
                    <H2>Безопасность Сессий и Токенов</H2>
                    <div className="grid gap-6 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center gap-2">
                                    <Shield className="h-5 w-5 text-primary" />
                                    Cookies
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <ul className="space-y-3">
                                    <li className="flex flex-col gap-1">
                                        <span className="font-medium text-sm">HttpOnly</span>
                                        <span className="text-sm text-muted-foreground">Запрещает доступ JavaScript к кукам, защищая от XSS атак.</span>
                                    </li>
                                    <li className="flex flex-col gap-1">
                                        <span className="font-medium text-sm">Secure</span>
                                        <span className="text-sm text-muted-foreground">Разрешает передачу кук только по зашифрованному HTTPS соединению.</span>
                                    </li>
                                    <li className="flex flex-col gap-1">
                                        <span className="font-medium text-sm">SameSite</span>
                                        <span className="text-sm text-muted-foreground">Защищает от CSRF атак. Рекомендуется использовать Strict или Lax.</span>
                                    </li>
                                </ul>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center gap-2">
                                    <KeyRound className="h-5 w-5 text-primary" />
                                    JWT (JSON Web Tokens)
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="space-y-4">
                                    <P className="text-sm">
                                        Токены без сохранения состояния (Stateless). Основные правила безопасности:
                                    </P>
                                    <ul className="grid gap-2 text-sm text-muted-foreground">
                                        <li className="flex items-center gap-2">
                                            <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                            Всегда проверяйте подпись (Signature).
                                        </li>
                                        <li className="flex items-center gap-2">
                                            <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                            Запрещайте алгоритм "None".
                                        </li>
                                        <li className="flex items-center gap-2">
                                            <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                            Не храните чувствительные данные в Payload.
                                        </li>
                                        <li className="flex items-center gap-2">
                                            <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                            Используйте надежный секретный ключ.
                                        </li>
                                    </ul>
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Labs */}
                <section>
                    <H2>Домашнее задание (PortSwigger Labs)</H2>
                    <P className="mb-4">
                        Теория доступна на <Link href="https://portswigger.net/web-security/authentication" target="_blank" className="text-primary hover:underline">PortSwigger Authentication</Link> и <Link href="https://portswigger.net/web-security/jwt" target="_blank" className="text-primary hover:underline">JWT</Link>.
                    </P>
                    <div className="grid gap-2 text-sm">
                        {[
                            { id: 1, title: 'Username enumeration via different responses', url: 'https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses' },
                            { id: 2, title: 'Username enumeration via subtly different responses', url: 'https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses' },
                            { id: 3, title: 'Broken brute-force protection, IP block', url: 'https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-ip-block' },
                            { id: 4, title: 'Username enumeration via account lock', url: 'https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock' },
                            { id: 5, title: '2FA simple bypass', url: 'https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass' },
                            { id: 6, title: 'Password reset broken logic', url: 'https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic' },
                            { id: 7, title: 'Password reset poisoning via middleware', url: 'https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware' },
                            { id: 8, title: 'Password brute-force via password change', url: 'https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change' },
                            { id: 9, title: 'JWT authentication bypass via unverified signature', url: 'https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature' },
                            { id: 10, title: 'JWT authentication bypass via flawed signature verification', url: 'https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification' },
                            { id: 11, title: 'JWT authentication bypass via weak signing key', url: 'https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key' },
                        ].map((lab) => (
                            <Link key={lab.id} href={lab.url || '#'} target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                                <ExternalLink className="h-4 w-4 text-primary" />
                                <span>{lab.id}. {lab.title}</span>
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
                                explanation={q.explanation}
                                link={q.link}
                            />
                        ))}
                    </div>
                </section>
            </div>
        </ContentPageLayout>
    );
}
