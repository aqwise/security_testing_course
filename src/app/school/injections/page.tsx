'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Database, Code, FileCode, AlertTriangle, CheckCircle2 } from 'lucide-react';
import Link from 'next/link';

export default function InjectionsPage() {
  return (
    <ContentPageLayout title="Курс: Инъекции">
      <div className="space-y-8">
        <section>
          <P>
            Самый большой и обьемный раздел. Мы затронем и узнаем о разных видах иньекций – SQL, Command, XSS, HTML и затронем тему XXE.
          </P>
          <P>
            <strong>Инъекции кода</strong> - уязвимости, связанные, например, с внедрением SQL, NoSQL, OS и LDAP и др., 
            возникают, когда непроверенные данные отправляются интерпретатору в составе команды или запроса. 
            Вредоносные данные могут заставить интерпретатор выполнить непредусмотренные команды или обратиться к данным 
            без прохождения соответствующей авторизации.
          </P>
        </section>

        <section>
          <H2>Типы инъекций</H2>
          <div className="grid gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5 text-primary" />
                  Cross-Site Scripting (XSS)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда приложение принимает и выполняет вредоносный JavaScript код. Например, можно украсть сессию 
                  пользователя или изменить его банковский счет, похитить сенситивную информацию и т.д.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileCode className="h-5 w-5 text-primary" />
                  HTML Injection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда приложение принимает и интерпретирует теги HTML и мы можем изменить вид страниц или сделать 
                  вредоносную ссылку и т.д. Или просто залить картинку с определенным контентом и нанести вред репутации компании.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5 text-primary" />
                  SQL Injection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда приложение принимает и выполняет команды напрямую к базе данных. Один из самых опасных видов 
                  уязвимостей. Злоумышленник может читать, записывать, вносить изменения или даже удалить данные.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-primary" />
                  Command Injection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда серверные команды (например для Linux – pwd/ls или Windows – dir/type) выполняются непосредственно 
                  из-под браузера или API. Урон от такого колоссальный, т.к. имеем доступ напрямую к серверу.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  XML External Entity (XXE)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Это уязвимость веб-безопасности, которая позволяет злоумышленнику вмешаться в обработку XML-данных приложением. 
                  Она часто позволяет злоумышленнику просматривать файлы в файловой системе сервера приложений и взаимодействовать 
                  с любыми внутренними или внешними системами. Простой пример: чтение /etc/ каталога.
                </P>
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>Основные принципы защиты</H2>
          <P>
            Безопасность программы часто связывается именно с ее безопасным поведением. Оно включает в себя, например 
            аутентификацию пользователя, проверку прав его доступа, фильтрацию входных данных. Но это само собой далеко 
            не полный список.
          </P>

          <H3>Советы по проверке защиты</H3>
          <div className="space-y-4">
            <div className="flex gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold mb-1">Проверяйте все данные от пользователя</p>
                <p className="text-sm text-muted-foreground">
                  Не работать с данными поступающими от пользователя без обработки.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold mb-1">Используйте белые списки</p>
                <p className="text-sm text-muted-foreground">
                  Не помещать в запрос управляющие структуры и идентификаторы, введенные пользователем, а заранее 
                  прописывать в скрипте список возможных вариантов.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold mb-1">Тестируйте разные типы ввода</p>
                <p className="text-sm text-muted-foreground">
                  Проверьте, как приложение обрабатывает разные типы ввода, включая простой текст и закодированный текст.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold mb-1">Проверяйте обновления</p>
                <p className="text-sm text-muted-foreground">
                  Одно лишь то, что код был обновлен, не значит, что что-то было исправлено. Новый код может содержать баги.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold mb-1">Анализируйте ответы сервера</p>
                <p className="text-sm text-muted-foreground">
                  Отмечайте риски, чтобы позже вернуться к ним с новыми силами и знаниями. Статус ответа сервера или 
                  тело ответа могут быть отличной подсказкой в поиске.
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <CheckCircle2 className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold mb-1">Будьте внимательны к URL параметрам</p>
                <p className="text-sm text-muted-foreground">
                  Будьте внимательны к передаваемым параметрам URL, которые отображаются в виде содержимого сайта. 
                  Они могут содержать возможные точки атаки.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section>
          <H2>Уроки курса</H2>
          <div className="grid gap-4">
            <Link href="/school/injections/lesson-1">
              <Card className="hover:shadow-lg transition-shadow cursor-pointer">
                <CardHeader>
                  <CardTitle>Урок 1: Введение в инъекции</CardTitle>
                  <CardDescription>
                    Основы инъекций кода, типы уязвимостей и принципы защиты
                  </CardDescription>
                </CardHeader>
              </Card>
            </Link>

            <Card className="opacity-50">
              <CardHeader>
                <CardTitle>Урок 2: SQL Injection</CardTitle>
                <CardDescription>Скоро...</CardDescription>
              </CardHeader>
            </Card>

            <Card className="opacity-50">
              <CardHeader>
                <CardTitle>Урок 3: XSS атаки</CardTitle>
                <CardDescription>Скоро...</CardDescription>
              </CardHeader>
            </Card>
          </div>
        </section>
      </div>
    </ContentPageLayout>
  );
}
