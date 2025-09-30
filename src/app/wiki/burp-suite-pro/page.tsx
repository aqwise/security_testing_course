'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import Link from 'next/link';
import Image from 'next/image';
import { cn } from '@/lib/utils';
import { FlaskConical, Settings, Globe, Shield, AlertTriangle, CheckCircle2, XCircle, Scan, Target, Bug, Server } from 'lucide-react';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export default function BurpSuiteProWikiPage() {
  return (
    <ContentPageLayout
      title="Настройка Burp Suite Pro"
      subtitle="Интегрированная платформа для аудита веб-приложений"
    >
        <H2 id="overview">Обзор</H2>
        <P>
          Burp Suite — это интегрированная платформа, предназначенная для проведения аудита веб-приложения, 
          как в ручном, так и в автоматических режимах. Содержит интуитивно понятный интерфейс со специально 
          спроектированными табами, позволяющими улучшить и ускорить процесс атаки.
        </P>
        <P>
          Сам инструмент представляет из себя проксирующий механизм, перехватывающий и обрабатывающий все 
          поступающие от браузера запросы. Имеется возможность установки сертификата Burp для анализа HTTPS соединений.
        </P>

        <Card className="my-6 border-primary/50">
            <CardHeader>
                <CardTitle className="flex items-center text-primary">
                    <Settings className="mr-2 h-5 w-5" />
                    Основной функционал
                </CardTitle>
            </CardHeader>
            <CardContent>
                <div className="grid md:grid-cols-2 gap-4">
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Proxy</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm">
                            Перехватывающий прокси-сервер HTTP(S) в режиме man-in-the-middle для анализа и модификации трафика.
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Spider/Crawler</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm">
                            Автоматический сбор информации об архитектуре веб-приложения.
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Scanner</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm">
                            Автоматический сканер уязвимостей (OWASP TOP 10). Доступен только в Professional версии.
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Intruder</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm">
                            Автоматические атаки: подбор паролей, перебор идентификаторов, фаззинг.
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Repeater</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm">
                            Модификация и повторная отправка HTTP-запросов с анализом ответов.
                        </CardContent>
                    </Card>
                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Sequencer</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm">
                            Анализ генерации случайных данных и выявление алгоритмов генерации.
                        </CardContent>
                    </Card>
                </div>
            </CardContent>
        </Card>

        <H2 id="proxy-setup">Настройка прокси</H2>
        <P>Для перехвата трафика необходимо настроить браузер для работы через прокси Burp Suite.</P>

        <H3>Google Chrome</H3>
        <P>Чтобы настроить Burp в качестве прокси Chrome:</P>
        <Ul items={[
            "Откройте настройки Google Chrome",
            "Перейдите в Advanced → «Open your computer's proxy settings»",
            "В разделе «Manual proxy setup» укажите адрес: 127.0.0.1, порт: 8080",
            "Удалите содержимое второго поля"
        ]} />

        <H3>Mozilla Firefox</H3>
        <P>Для настройки прокси в Firefox:</P>
        <Ul items={[
            "Откройте настройки Firefox",
            "Найдите Network Settings (внизу страницы) → Settings...",
            "Выберите Manual proxy configuration",
            "В поле HTTP Proxy укажите: 127.0.0.1, порт: 8080",
            "В поле HTTPS Proxy продублируйте те же настройки"
        ]} />

        <Alert className="my-6">
            <FlaskConical className="h-4 w-4" />
            <AlertDescription>
                Для быстрого переключения прокси-серверов рекомендуется использовать плагин FoxyProxy для Firefox.
            </AlertDescription>
        </Alert>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-37-59-20250930-083904.png"
                alt="Настройка прокси в Burp Suite"
                width={800}
                height={400}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H2 id="https-certificate">Установка сертификата для HTTPS</H2>
        <P>
          После настройки прокси необходимо установить SSL сертификат Burp в корневые сертификаты браузера 
          для перехвата HTTPS трафика.
        </P>

        <Card className="my-6 border-accent/50">
            <CardHeader>
                <CardTitle className="flex items-center text-accent-foreground">
                    <Shield className="mr-2 h-5 w-5" />
                    Установка сертификата
                </CardTitle>
            </CardHeader>
            <CardContent>
                <Ul items={[
                    "Убедитесь, что Burp запущен и работает",
                    "В браузере перейдите по адресу http://burp",
                    "Скачайте сертификат по ссылке «CA Certificate»",
                    "Для Firefox: Settings → Privacy and Security → Certificates → View certificates → Import",
                    "Выберите скачанный сертификат и отметьте «Trust this CA to identify websites»",
                    "Перезапустите браузер"
                ]} />
            </CardContent>
        </Card>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-38-14.png"
                alt="Скачивание сертификата Burp"
                width={600}
                height={300}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H2 id="embedded-browser">Встроенный браузер Chromium</H2>
        <P>
          В большинстве случаев для тестирования будет достаточно использования встроенного браузера Burp Suite Chromium. 
          Перехват HTTPS трафика работает из коробки, что позволяет пропустить установку сертификата.
        </P>
        <P>
          Браузер сохраняет настройки, позволяет устанавливать плагины и не отличается от обычного Chrome. 
          Однако некоторые современные веб-приложения могут блокировать трафик именно от Chromium.
        </P>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-44-13-20250930-084557.png"
                alt="Встроенный браузер Burp Suite"
                width={800}
                height={500}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H2 id="scanning-types">Типы сканирования</H2>
        <P>Burp Suite предоставляет несколько режимов сканирования для различных сценариев тестирования:</P>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4 my-6">
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Scan</CardTitle>
                    <Scan className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <p className="text-xs text-muted-foreground">
                        Стандартный вид сканирования с полной конфигурацией.
                    </p>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Live Scan</CardTitle>
                    <Target className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <p className="text-xs text-muted-foreground">
                        Автоматическое сканирование запросов из Proxy и Repeater.
                    </p>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Passive Scan</CardTitle>
                    <Globe className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <p className="text-xs text-muted-foreground">
                        Аудит запросов и ответов без изменения данных.
                    </p>
                </CardContent>
            </Card>
            <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                    <CardTitle className="text-sm font-medium text-primary">Active Scan</CardTitle>
                    <Bug className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                    <p className="text-xs text-muted-foreground">
                        Быстрый запуск через контекстное меню без настроек.
                    </p>
                </CardContent>
            </Card>
        </div>

        <H2 id="scan-preparation">Подготовка и запуск сканирования</H2>
        
        <H3>Подготовка к сканированию</H3>
        <P>При каждом запуске Burp Suite появляется окно с тремя вариантами запуска:</P>

        <Table className="my-6">
            <TableHeader>
                <TableRow>
                    <TableHead>Вариант</TableHead>
                    <TableHead>Описание</TableHead>
                </TableRow>
            </TableHeader>
            <TableBody>
                <TableRow>
                    <TableCell>Temporary project</TableCell>
                    <TableCell>Временный проект, данные не сохраняются</TableCell>
                </TableRow>
                <TableRow>
                    <TableCell>New project on disk</TableCell>
                    <TableCell>Сохранение сессии на диск</TableCell>
                </TableRow>
                <TableRow>
                    <TableCell>Open existing project</TableCell>
                    <TableCell>Открыть ранее сохраненную сессию</TableCell>
                </TableRow>
            </TableBody>
        </Table>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-52-08-20250930-085403.png"
                alt="Выбор типа проекта в Burp Suite"
                width={600}
                height={400}
                className="rounded-lg border shadow-md"
            />
        </div>

        <P>После выбора проекта открывается окно выбора конфигурации сканера:</P>

        <Ul items={[
            "Use Burp defaults — стандартная настройка сканера",
            "Use options saved with project — настройки из сохраненного проекта",
            "Load from configuration file — загрузка из конфигурационного файла"
        ]} />

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-52-35-20250930-085426.png"
                alt="Выбор конфигурации сканера"
                width={600}
                height={400}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H3>Сбор Site Map</H3>
        <P>
          Перед сканированием необходимо собрать карту сайта (Site Map). Для этого вручную пройдите по всем 
          разделам приложения, чтобы Burp мог зафиксировать все доступные URL и функции.
        </P>
        <P>После сбора Site Map добавьте приложение в "Scope" для ограничения области сканирования.</P>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-53-11-20250930-085429.png"
                alt="Добавление в Scope"
                width={700}
                height={400}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H3>Запуск сканирования</H3>
        <P>После сбора Site Map можно приступить к сканированию:</P>
        <Ul items={[
            "Во вкладке «Target» кликните ПКМ по приложению",
            "Выберите «Scan»",
            "Откроется «Scan Launcher» для настройки конфигурации"
        ]} />

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-57-36-20250930-085837.png"
                alt="Scan Launcher"
                width={800}
                height={600}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H2 id="scan-configuration">Конфигурация сканирования</H2>
        
        <H3>Scan Details</H3>
        <P>В разделе "Scan details" доступны следующие параметры:</P>

        <Card className="my-6">
            <CardHeader>
                <CardTitle>Scan Type</CardTitle>
            </CardHeader>
            <CardContent>
                <Ul items={[
                    "Crawl and audit — краулинг с последующим аудитом на уязвимости",
                    "Crawl — только краулинг без аудита",
                    "Audit selected items — аудит собранного Site Map"
                ]} />
            </CardContent>
        </Card>

        <H3>URLs to Scan</H3>
        <P>
          Доступен для "Crawl and audit" и "Crawl". Область сканирования ограничивается указанными URL-адресами.
          Важно правильно указывать пути с завершающим слешем для ограничения конкретными директориями.
        </P>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-57-47-20250930-085840.png"
                alt="Конфигурация сканирования"
                width={700}
                height={500}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H2 id="monitoring">Мониторинг сканирования</H2>
        <P>
          После запуска сканирования его прогресс можно отслеживать через вкладку "Dashboard". 
          В окне "Tasks" отображается информация о ходе выполнения, в "Issue activity" — найденные проблемы.
        </P>

        <div className="grid md:grid-cols-2 gap-6 my-6">
            <Card>
                <CardHeader>
                    <CardTitle>Dashboard</CardTitle>
                </CardHeader>
                <CardContent>
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_10-58-01-20250930-085843.png"
                        alt="Dashboard Burp Suite"
                        width={500}
                        height={300}
                        className="rounded-lg border"
                    />
                </CardContent>
            </Card>
            <Card>
                <CardHeader>
                    <CardTitle>View Details</CardTitle>
                </CardHeader>
                <CardContent>
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_10-58-09-20250930-085845.png"
                        alt="Детали сканирования"
                        width={500}
                        height={300}
                        className="rounded-lg border"
                    />
                </CardContent>
            </Card>
        </div>

        <P>
          Для просмотра уязвимостей по конкретному домену перейдите в "Target" → "Site map" и выберите 
          интересующее приложение. В окне "Issues" отобразятся найденные уязвимости.
        </P>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_10-58-09-20250930-085845.png"
                alt="Просмотр уязвимостей"
                width={800}
                height={500}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H2 id="vulnerability-analysis">Анализ найденных уязвимостей</H2>
        
        <H3>True Positive — подтверждение уязвимостей</H3>
        <P>
          Для подтверждения уязвимости необходимо выполнить такой же запрос, как сделал сканер, 
          и понять, влияет ли этот запрос на приложение. У сканеров возможны false positive срабатывания.
        </P>

        <Card className="my-6 border-green-200">
            <CardHeader>
                <CardTitle className="flex items-center text-green-700">
                    <CheckCircle2 className="mr-2 h-5 w-5" />
                    Пример: Path Traversal
                </CardTitle>
            </CardHeader>
            <CardContent>
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-07-16-20250930-093038.png"
                        alt="Path Traversal уязвимость"
                        width={700}
                        height={400}
                        className="rounded-lg border mb-4"
                    />
                </div>
                <P>Для GET-запроса: ПКМ → "Copy URL" → вставить в браузер для проверки.</P>
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-07-28-20250930-093113.png"
                        alt="Проверка Path Traversal"
                        width={600}
                        height={300}
                        className="rounded-lg border"
                    />
                </div>
            </CardContent>
        </Card>

        <Card className="my-6 border-green-200">
            <CardHeader>
                <CardTitle className="flex items-center text-green-700">
                    <CheckCircle2 className="mr-2 h-5 w-5" />
                    Пример: Cross-Site Scripting (Stored)
                </CardTitle>
            </CardHeader>
            <CardContent>
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-07-35-20250930-093237.png"
                        alt="XSS уязвимость"
                        width={700}
                        height={400}
                        className="rounded-lg border mb-4"
                    />
                </div>
                <P>Для POST-запроса:</P>
                <Ul items={[
                    "Подставить пейлоад в уязвимый input",
                    "Выполнить новый запрос → перехватить через Proxy",
                    "Изменить значение параметра на пейлоад и отправить"
                ]} />
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-07-47-20250930-093304.png"
                        alt="Перехват POST запроса"
                        width={600}
                        height={300}
                        className="rounded-lg border mb-4"
                    />
                </div>
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-07-55-20250930-093335.png"
                        alt="Результат XSS"
                        width={600}
                        height={300}
                        className="rounded-lg border"
                    />
                </div>
                <p className="text-green-700 font-semibold mb-4 leading-relaxed">Уязвимость подтверждена.</p>
            </CardContent>
        </Card>

        <H3>False Positive — ложные срабатывания</H3>
        <P>
          Не все срабатывания сканера являются реальными уязвимостями. False positive возникают, 
          когда сканер неправильно интерпретирует ответ сервера.
        </P>

        <Card className="my-6 border-red-200">
            <CardHeader>
                <CardTitle className="flex items-center text-red-700">
                    <XCircle className="mr-2 h-5 w-5" />
                    Пример: False Cross-Site Scripting
                </CardTitle>
            </CardHeader>
            <CardContent>
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-08-03-20250930-093423.png"
                        alt="False positive XSS"
                        width={700}
                        height={400}
                        className="rounded-lg border mb-4"
                    />
                </div>
                <P>
                  Сканер отправил JavaScript код в параметр "page=". Получив ответ 200 с этим кодом в теле, 
                  он посчитал это уязвимостью. На самом деле произошла ошибка сервера, и код просто отобразился как текст.
                </P>
                <div className="my-4">
                    <Image
                        src="/pics/burp-suite-pro/image_2025-09-30_11-08-10-20250930-093454.png"
                        alt="Отметка как False Positive"
                        width={600}
                        height={300}
                        className="rounded-lg border"
                    />
                </div>
                <Alert>
                    <XCircle className="h-4 w-4" />
                    <AlertDescription>
                        Отмечаем уязвимость как False Positive и не добавляем в отчет.
                    </AlertDescription>
                </Alert>
            </CardContent>
        </Card>

        <H2 id="troubleshooting">Решение проблем</H2>
        
        <H3>Перегрузка сервера</H3>
        <P>
          Иногда сервер не может обработать количество запросов от сканера. Для предотвращения проблемы:
        </P>
        <Ul items={[
            "Периодически проверяйте отклик сервера",
            "При увеличении времени отклика приостанавливайте сканирование",
            "В конфигурации Resource pool уменьшите нагрузку",
            "Настройте количество одновременных запросов и паузы между ними"
        ]} />

        <H3>Завершение сессии</H3>
        <P>
          Во время сканирования сессия может истечь, и куки станут невалидными. 
          Это требует немедленной остановки сканирования.
        </P>

        <Alert className="my-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
                <strong>Как определить завершение сессии:</strong> Следите за Event log во вкладке Dashboard. 
                Уведомления о завершении сессии содержат информацию о количестве запросов с ошибками.
            </AlertDescription>
        </Alert>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_11-08-28-20250930-093643.png"
                alt="Уведомление о завершении сессии"
                width={700}
                height={200}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H3>Изменение токена авторизации</H3>
        <P>
          Для замены токена в уже собранном Site Map используйте расширение "Add Custom Header". 
          Оно может заменить один токен на другой или автоматически добавить отсутствующий заголовок.
        </P>

        <div className="my-6">
            <Image
                src="/pics/burp-suite-pro/image_2025-09-30_11-08-33-20250930-093737.png"
                alt="Add Custom Header расширение"
                width={600}
                height={400}
                className="rounded-lg border shadow-md"
            />
        </div>

        <H3>Предотвращение истечения сессии</H3>
        <Card className="my-6 border-accent/50">
            <CardHeader>
                <CardTitle className="flex items-center text-accent-foreground">
                    <Server className="mr-2 h-5 w-5" />
                    Рекомендации
                </CardTitle>
            </CardHeader>
            <CardContent>
                <Ul items={[
                    "Запускайте сканирование сразу после сбора Site Map",
                    "Не выходите из аккаунта во время сбора Site Map",
                    "Удаляйте из Site Map запросы logout и возможно login",
                    "Тестируйте функцию входа отдельно при необходимости"
                ]} />
            </CardContent>
        </Card>

        <H2 id="conclusion">Заключение</H2>
        <P>
          Burp Suite Pro является мощным инструментом для аудита веб-приложений, предоставляющим широкие 
          возможности как для автоматического, так и ручного тестирования. Правильная настройка и понимание 
          принципов работы позволяют эффективно выявлять уязвимости и проводить качественную оценку безопасности.
        </P>
        <P>
          Помните о важности верификации найденных уязвимостей и исключении false positive срабатываний 
          для предоставления точного и полезного отчета о безопасности.
        </P>

    </ContentPageLayout>
  );
}
