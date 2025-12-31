'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, Terminal, Lock } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function BrokenAccessControlPage() {
    return (
        <ContentPageLayout
            title="Broken Access Control"
            subtitle="Нарушение контроля доступа и повышение привилегий"
        >
            <div className="space-y-8">
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4040884229/Broken+access+control"
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — Broken Access Control <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Author & Intro */}
                <section>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground mb-4">
                        <span>Автор: Vladyslav Koniakhin</span>
                    </div>

                    <Alert>
                        <ShieldAlert className="h-4 w-4" />
                        <AlertTitle>Что такое нарушение контроля доступа?</AlertTitle>
                        <AlertDescription>
                            Нарушение контроля доступа — это уязвимость, которая позволяет злоумышленнику повысить свои права в приложении
                            или получить доступ к ограниченным разделам и функциям. Даже если матрица доступа выглядит идеально на бумаге,
                            ее реализация может содержать ошибки, позволяющие обходить ограничения.
                        </AlertDescription>
                    </Alert>
                </section>

                {/* Common Vulnerabilities */}
                <section>
                    <H2>Распространенные уязвимости</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">1. Изменение URL и состояния</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Обход ограничений доступа путем изменения URL-адреса, внутреннего состояния приложения или HTML-страницы.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">2. IDOR (Insecure Direct Object References)</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Изменение первичного ключа для доступа к записям других пользователей.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">3. Privilege Escalation</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Выполнение административных действий с правами обычного пользователя (Horizontal/Vertical).
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">4. Манипуляция метаданными</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Подделка JWT, Cookie или скрытых полей для повышения привилегий.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">5. CORS Misconfiguration</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Неправильная настройка CORS, позволяющая несанкционированный доступ к API.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">6. Forced Browsing</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Доступ к скрытым страницам или API без аутентификации.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">7. HTTP Methods</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Отсутствие контроля доступа для методов POST, PUT, PATCH, DELETE.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">8. Недокументированные API</CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Доступ к забытым API (например, <code className="bg-muted px-1 rounded">/actuator</code> в Spring Boot).
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Impact */}
                <section>
                    <H2>Последствия (Impact)</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Lock className="h-4 w-4 text-primary" />
                                    Несанкционированные действия
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Выполнение действий от имени других пользователей или администраторов.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Terminal className="h-4 w-4 text-primary" />
                                    Утечка и манипуляция данными
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Создание, просмотр, обновление или удаление записей, к которым у атакующего не должно быть доступа.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Exploitation Process */}
                <section>
                    <H2>Процесс эксплуатации</H2>
                    <P>
                        Метод эксплуатации зависит от контекста. Классический пример — подмена <strong>ID</strong> или <strong>UUID</strong> в запросе.
                    </P>
                    <P>
                        Например, есть функция загрузки файлов, доступная только администратору. Злоумышленник может попробовать перехватить запрос
                        и подменить Cookie/JWT токен с администраторского на пользовательский (или наоборот, если уязвимость в проверке ролей),
                        чтобы проверить, выполняется ли действие.
                    </P>
                </section>

                {/* Detection */}
                <section>
                    <H2>Способы поиска уязвимостей</H2>
                    <P>
                        Главное — <strong>понять бизнес-логику приложения</strong>.
                    </P>
                    <div className="space-y-4 mt-4">
                        <Card>
                            <CardContent className="pt-6">
                                <div className="flex items-start gap-4">
                                    <div className="p-2 bg-primary/10 rounded-full">
                                        <ShieldAlert className="h-6 w-6 text-primary" />
                                    </div>
                                    <div>
                                        <p className="font-medium">1. Анализ ролей</p>
                                        <p className="text-sm text-muted-foreground">Ограничен ли доступ пользователей к функциям, которые им не положены?</p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardContent className="pt-6">
                                <div className="flex items-start gap-4">
                                    <div className="p-2 bg-primary/10 rounded-full">
                                        <ShieldAlert className="h-6 w-6 text-primary" />
                                    </div>
                                    <div>
                                        <p className="font-medium">2. Манипуляция параметрами</p>
                                        <p className="text-sm text-muted-foreground">Можно ли получить доступ к приватным данным, изменив параметры запроса (ID, имя пользователя)?</p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardContent className="pt-6">
                                <div className="flex items-start gap-4">
                                    <div className="p-2 bg-primary/10 rounded-full">
                                        <ShieldAlert className="h-6 w-6 text-primary" />
                                    </div>
                                    <div>
                                        <p className="font-medium">3. Публичный доступ</p>
                                        <p className="text-sm text-muted-foreground">Есть ли доступные функции для неаутентифицированных пользователей?</p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Prevention Vectors */}
                <section>
                    <H2>Векторы атак и защита</H2>
                    <div className="space-y-6 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Insecure IDs</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm mb-2"><strong className="text-destructive">Атака:</strong> Угадывание или перебор идентификаторов (IDOR) для доступа к чужим данным.</P>
                                <P className="text-sm"><strong className="text-green-600">Защита:</strong> Не полагайтесь на скрытность ID. Проверяйте права доступа для каждого объекта при каждом запросе.</P>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Forced Browsing</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm mb-2"><strong className="text-destructive">Атака:</strong> Прямой переход по URL, минуя интерфейс (например, /admin/users).</P>
                                <P className="text-sm"><strong className="text-green-600">Защита:</strong> Проверяйте права доступа на уровне контроллера или middleware для каждого URL.</P>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Path Traversal</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm mb-2"><strong className="text-destructive">Атака:</strong> Использование относительных путей (<code>../../</code>) для доступа к файловой системе.</P>
                                <P className="text-sm"><strong className="text-green-600">Защита:</strong> Валидация входных данных, использование безопасных API для работы с файлами, настройки прав файловой системы.</P>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Client Side Caching</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm mb-2"><strong className="text-destructive">Атака:</strong> Извлечение конфиденциальных данных из кэша браузера на общедоступных компьютерах.</P>
                                <P className="text-sm"><strong className="text-green-600">Защита:</strong> Использование заголовков <code>Cache-Control</code>, <code>No-Store</code> для чувствительных страниц.</P>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Prevention General */}
                <section>
                    <H2>Общие рекомендации по защите</H2>
                    <Card className="mt-4">
                        <CardContent className="pt-6">
                            <ul className="grid gap-3">
                                {[
                                    "Запрещайте доступ по умолчанию (Deny by Default).",
                                    "Внедряйте централизованные механизмы контроля доступа.",
                                    "Контролируйте доступ на основе владения (Ownership) и ролей.",
                                    "Не полагайтесь на скрытие элементов интерфейса — проверяйте права на сервере.",
                                    "Отключите листинг директорий веб-сервера.",
                                    "Логируйте попытки несанкционированного доступа.",
                                    "Ограничивайте частоту запросов (Rate Limiting).",
                                    "Инвалидируйте JWT и сессии после выхода."
                                ].map((item, i) => (
                                    <li key={i} className="flex items-center gap-2 text-sm text-muted-foreground">
                                        <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                        {item}
                                    </li>
                                ))}
                            </ul>
                        </CardContent>
                    </Card>
                </section>

                {/* Tools */}
                <section>
                    <H2>Инструменты</H2>
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 mt-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Burp Suite Autorize</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm">
                                    Автоматическая проверка авторизации. Позволяет повторять запросы от имени другого пользователя (или без аутентификации) и сравнивать ответы.
                                </P>
                                <Link href="https://github.com/PortSwigger/autorize" target="_blank" className="text-primary hover:underline text-sm flex items-center gap-1 mt-2">
                                    GitHub <ExternalLink className="h-3 w-3" />
                                </Link>
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Turbo Intruder</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <P className="text-sm">
                                    Быстрая отправка запросов. Идеально для перебора ID и токенов при поиске IDOR.
                                </P>
                                <Link href="https://github.com/PortSwigger/turbo-intruder" target="_blank" className="text-primary hover:underline text-sm flex items-center gap-1 mt-2">
                                    GitHub <ExternalLink className="h-3 w-3" />
                                </Link>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Labs */}
                <section>
                    <H2>Домашнее задание (PortSwigger Labs)</H2>
                    <P className="mb-4">
                        Рекомендуется ознакомиться с теорией на <Link href="https://portswigger.net/web-security/access-control" className="text-primary hover:underline">PortSwigger</Link> и выполнить следующие лабораторные работы:
                    </P>
                    <div className="grid gap-2 text-sm">
                        {[
                            { id: 1, title: 'Unprotected Admin Functionality', url: 'https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality' },
                            { id: 2, title: 'Unprotected admin functionality with unpredictable URL', url: 'https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url' },
                            { id: 3, title: 'User role controlled by request parameter', url: 'https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter' },
                            { id: 4, title: 'User role can be modified in user profile', url: 'https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile' },
                            { id: 5, title: 'User ID controlled by request parameter', url: 'https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter' },
                            { id: 6, title: 'User ID controlled by request parameter, with unpredictable user IDs', url: 'https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids' },
                            { id: 7, title: 'User ID controlled by request parameter with data leakage in redirect', url: 'https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect' },
                            { id: 8, title: 'User ID controlled by request parameter with password disclosure', url: 'https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure' },
                            { id: 9, title: 'Insecure direct object references', url: 'https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references' },
                            { id: 10, title: 'Multi-step process with no access control on one step', url: 'https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step' },
                        ].map((lab) => (
                            <Link key={lab.id} href={lab.url} target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                                <ExternalLink className="h-4 w-4 text-primary" />
                                <span>{lab.id}. {lab.title}</span>
                            </Link>
                        ))}
                    </div>

                    <div className="mt-6">
                        <H3>Задания со звездочкой (*)</H3>
                        <div className="grid gap-2 text-sm mt-2">
                            {[
                                { id: 11, title: 'URL-based access control can be circumvented', url: 'https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented' },
                                { id: 12, title: 'Method-based access control can be circumvented', url: 'https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented' },
                            ].map((lab) => (
                                <Link key={lab.id} href={lab.url} target="_blank" className="flex items-center gap-2 p-2 rounded hover:bg-muted transition-colors">
                                    <ExternalLink className="h-4 w-4 text-destructive" />
                                    <span>{lab.id}. {lab.title}</span>
                                </Link>
                            ))}
                        </div>
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
