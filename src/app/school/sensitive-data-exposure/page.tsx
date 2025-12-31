'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, ShieldAlert, Lock, Eye, Search, FileCode, CheckCircle2 } from 'lucide-react';
import Link from 'next/link';
import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function SensitiveDataExposurePage() {
    return (
        <ContentPageLayout
            title="Sensitive Data Exposure"
            subtitle="Раскрытие конфиденциальных данных"
        >
            <div className="space-y-8">
                <Card className="bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800">
                    <CardContent className="pt-4">
                        <P className="text-sm text-muted-foreground mb-0">
                            Источник:{' '}
                            <Link
                                href="https://innowise-group.atlassian.net/wiki/spaces/QD/pages/4044783726/Sensitive+Data+Exposure"
                                target="_blank"
                                className="text-primary hover:underline inline-flex items-center"
                            >
                                Confluence — Sensitive Data Exposure <ExternalLink className="ml-1 h-3 w-3" />
                            </Link>
                        </P>
                    </CardContent>
                </Card>

                {/* Theory */}
                <section>
                    <Alert>
                        <ShieldAlert className="h-4 w-4" />
                        <AlertTitle>Что такое Sensitive Data Exposure?</AlertTitle>
                        <AlertDescription>
                            Уязвимость возникает, когда приложение не защищает должным образом чувствительную информацию:
                            PII, пароли, токены, ключи API, медицинские или финансовые данные.
                            Злоумышленники могут перехватывать данные в пути (Man-in-the-Middle), красть ключи или
                            находить случайно оставленные файлы (.git, .env).
                        </AlertDescription>
                    </Alert>

                    <H2>Основные типы чувствительных данных</H2>
                    <div className="grid gap-4 md:grid-cols-2 mt-4">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Lock className="h-4 w-4 text-primary" />
                                    PII (Personal Identifiable Information)
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                ФИО, паспортные данные, номера телефонов, email, адреса проживания.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <FileCode className="h-4 w-4 text-primary" />
                                    Технические секреты
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                Логины/пароли, API ключи, токены сессий, приватные сертификаты, конфигурационные файлы (.env).
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Stages of Analysis */}
                <section>
                    <H2>Этапы анализа (Checklist)</H2>
                    <div className="space-y-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Этап 1: Определение потребности (Compliance)</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                                    <li><strong>GDPR:</strong> Регламент ЕС по защите данных.</li>
                                    <li><strong>PCI DSS:</strong> Стандарт безопасности платежных карт.</li>
                                    <li><strong>HIPAA:</strong> Защита медицинской информации.</li>
                                </ul>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Этап 2: Классификация данных</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="grid gap-4 md:grid-cols-2 text-sm">
                                    <div className="p-3 bg-muted rounded-md border text-center">
                                        <div className="font-semibold text-green-600 mb-1">Public</div>
                                        <div className="text-muted-foreground">Маркетинговая информация, новости.</div>
                                    </div>
                                    <div className="p-3 bg-muted rounded-md border text-center">
                                        <div className="font-semibold text-red-600 mb-1">Sensitive</div>
                                        <div className="text-muted-foreground">Номера карт, пароли, PII (Требует шифрования).</div>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Этап 3: Проверка механизмов защиты</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <ul className="space-y-2 text-sm text-muted-foreground">
                                    <li className="flex items-start gap-2">
                                        <CheckCircle2 className="h-4 w-4 mt-0.5 text-primary" />
                                        <span><strong>Передача:</strong> Не используется ли открытый текст (HTTP, FTP)? Зашифрован ли внутренний трафик?</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <CheckCircle2 className="h-4 w-4 mt-0.5 text-primary" />
                                        <span><strong>Алгоритмы:</strong> Нет ли устаревших алгоритмов (MD5, DES)?</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <CheckCircle2 className="h-4 w-4 mt-0.5 text-primary" />
                                        <span><strong>Ключи:</strong> Есть ли ротация ключей? Не используются ли дефолтные?</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <CheckCircle2 className="h-4 w-4 mt-0.5 text-primary" />
                                        <span><strong>Заголовки:</strong> Используется ли HSTS (Strict-Transport-Security)?</span>
                                    </li>
                                </ul>
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Tools */}
                <section>
                    <H2>Инструменты для поиска утечек</H2>
                    <div className="grid gap-4 md:grid-cols-3 mt-4">
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Search className="h-4 w-4" />
                                    Разведка (OSINT)
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                ProjectDiscovery, Google Dorks, Shodan, crt.sh, Wappalyzer.
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Terminal className="h-4 w-4" />
                                    Сканирование
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                <code>nmap</code>, <code>ffuf</code>, <code>dirsearch</code> (поиск скрытых файлов, .git, .env).
                            </CardContent>
                        </Card>
                        <Card>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-base flex items-center gap-2">
                                    <Eye className="h-4 w-4" />
                                    Специфические
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="text-sm text-muted-foreground">
                                <code>git-hack</code>, <code>postleaks</code>, <code>TruffleHog</code>.
                            </CardContent>
                        </Card>
                    </div>
                </section>

                {/* Scripts */}
                <section>
                    <H2>Полезные скрипты и Regex</H2>
                    <div className="space-y-6">
                        <div>
                            <H3>1. DevTools Script (Поиск API вызовов в JS)</H3>
                            <P className="text-sm text-muted-foreground mb-2">
                                Запустите этот скрипт в консоли браузера, чтобы найти ссылки и API ключи в загруженных скриптах.
                            </P>
                            <div className="bg-muted p-4 rounded-md overflow-x-auto text-xs font-mono">
                                <pre>{`(async function scanScripts(){
  const scripts = Array.from(document.getElementsByTagName('script'));
  const pattern = /(["'])((https?:\\/\\/|\\/)[^\\s"']+?|[a-zA-Z0-9_\\-]+=\\w+?)\\1/g;
  const matches = new Set();

  async function fetchScriptContent(src) {
    try {
      const response = await fetch(src);
      return await response.text();
    } catch (err) {
      console.error(\`Failed to fetch \${src}:\`, err);
      return '';
    }
  }

  function extractMatches(content){
    let match;
    while ((match = pattern.exec(content)) !== null) {
      matches.add(match[2]);
    }
  }

  for (const script of scripts) {
    let content = script.innerHTML;
    if (script.src) {
      content = await fetchScriptContent(script.src);
    }
    extractMatches(content);
  }

  console.log('Found matches:', Array.from(matches));
})();`}</pre>
                            </div>
                        </div>

                        <div>
                            <H3>2. Burp Suite Regex (Поиск секретов)</H3>
                            <P className="text-sm text-muted-foreground mb-2">
                                Используйте в поиске (Search) с включенным "Regular expression".
                            </P>
                            <div className="bg-muted p-4 rounded-md overflow-x-auto text-xs font-mono whitespace-pre-wrap break-all">
                                (?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id)
                            </div>
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

function Terminal({ className }: { className?: string }) {
    return (
        <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className={className}
        >
            <polyline points="4 17 10 11 4 5" />
            <line x1="12" x2="20" y1="19" y2="19" />
        </svg>
    )
}
