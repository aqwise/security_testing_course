import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';
import Image from 'next/image';
import { getImagePath } from '@/utils/paths';



const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sourcesData = [
  { id: 1, text: "zaproxy.org/docs/desktop/start/proxies/", url: "https://www.zaproxy.org/docs/desktop/start/proxies/" },
  { id: 2, text: "zaproxy.org/docs/desktop/start/", url: "https://www.zaproxy.org/docs/desktop/start/" },
  { id: 3, text: "youtube.com/watch?v=Uin07SHkQTE", url: "https://www.youtube.com/watch?v=Uin07SHkQTE" },
  { id: 4, text: "zaproxy.org/docs/desktop/addons/client-side-integration/firefox-profile/", url: "https://www.zaproxy.org/docs/desktop/addons/client-side-integration/firefox-profile/" },
  { id: 5, text: "docs.genesys.com", url: "https://docs.genesys.com/Documentation/GWE/latest/Developer/TestwithGWMProxy" },
  { id: 6, text: "rkhal101.github.io", url: "https://rkhal101.github.io/_posts/WAVS/ZAP/zap_browser_setup" },
  { id: 7, text: "youtube.com/watch?v=louvjRFUs2o", url: "https://www.youtube.com/watch?v=louvjRFUs2o" },
  { id: 8, text: "security.docs.wso2.com", url: "https://security.docs.wso2.com/en/latest/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/" },
  { id: 9, text: "portableapps.com/node/67118", url: "https://portableapps.com/node/67118" },
  { id: 10, text: "linuxconfig.org", url: "https://linuxconfig.org/how-to-install-firefox-developer-edition-on-linux" },
  { id: 11, text: "firefox-source-docs.mozilla.org", url: "https://firefox-source-docs.mozilla.org/networking/connectivity_checking.html" },
  { id: 12, text: "developer.mozilla.org", url: "https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/settings" },
  { id: 13, text: "dev.to/harrsh", url: "https://dev.to/harrsh/how-to-setup-firefox-developer-edition-on-ubuntu-4inp" },
  { id: 14, text: "geeksforgeeks.org", url: "https://www.geeksforgeeks.org/techtips/network-tab-in-mozilla-firefox-browser/" },
  { id: 15, text: "support.mozilla.org", url: "https://support.mozilla.org/en-US/questions/826565" },
  { id: 16, text: "askubuntu.com", url: "https://askubuntu.com/questions/1493916/installing-firefox-dev-edition" },
  { id: 17, text: "security.my.salesforce-sites.com", url: "https://security.my.salesforce-sites.com/security/tools/webapp/zapbrowsersetup" },
  { id: 18, text: "github.com/zaproxy/zaproxy/issues/4954", url: "https://github.com/zaproxy/zaproxy/issues/4954" },
  { id: 19, text: "zaproxy.org/docs/desktop/addons/network/options/servercertificates/", url: "https://www.zaproxy.org/docs/desktop/addons/network/options/servercertificates/" },
  { id: 20, text: "security.stackexchange.com", url: "https://security.stackexchange.com/questions/191772/owasp-zap-how-to-use-tls-client-certificate-authentication" },
  { id: 21, text: "stackoverflow.com", url: "https://stackoverflow.com/questions/48180775/zed-attack-proxy-dynamic-certificate-wont-import-to-firefox" },
  { id: 22, text: "youtube.com/watch?v=tmk3yfOJ55w", url: "https://www.youtube.com/watch?v=tmk3yfOJ55w" },
  { id: 23, text: "github.com/arthepsy/zaproxy_ssl", url: "https://github.com/arthepsy/zaproxy_ssl" },
  { id: 24, text: "support.mozilla.org/en-US/kb/setting-certificate-authorities-firefox", url: "https://support.mozilla.org/en-US/kb/setting-certificate-authorities-firefox" },
  { id: 25, text: "zaproxy.org/faq/how-do-you-configure-zap-to-test-an-application-on-localhost/", url: "https://www.zaproxy.org/faq/how-do-you-configure-zap-to-test-an-application-on-localhost/" },
  { id: 26, text: "webshare.io/blog/firefox-proxy", url: "https://www.webshare.io/blog/firefox-proxy" },
  { id: 27, text: "alexhost.com/faq/", url: "https://alexhost.com/faq/how-to-set-up-a-proxy-server-connection-in-firefox/" },
  { id: 28, text: "support.mozilla.org/en-US/kb/connection-settings-firefox", url: "https://support.mozilla.org/en-US/kb/connection-settings-firefox" },
  { id: 29, text: "stackoverflow.com/questions/9660689/redirecting-firefox-to-a-proxy-on-localhost", url: "https://stackoverflow.com/questions/9660689/redirecting-firefox-to-a-proxy-on-localhost" },
];


export default function OwaspZapSetupPage() {
    return (
        <ContentPageLayout
            title="Настройка OWASP ZAP с Firefox Developer Edition"
            subtitle="Комплексное руководство по настройке OWASP Zed Attack Proxy (ZAP) с Firefox Developer Edition для эффективного тестирования безопасности веб-приложений."
        >
            <P>
                Ключевое преимущество использования Firefox Developer Edition заключается в его расширенных возможностях конфигурации и функциях, ориентированных на разработчиков, что делает его идеальным для рабочих процессов тестирования безопасности.
            </P>
            
            <H2>Предварительные требования и системные требования</H2>
            <P>
                Перед началом процесса настройки убедитесь, что у вас есть необходимое программное обеспечение и системные ресурсы. OWASP ZAP требует Java 17 или выше и не менее 4 ГБ ОЗУ для оптимальной производительности. Процесс конфигурации включает установку обоих приложений, настройку прокси-соединений и управление SSL-сертификатами для безопасного перехвата трафика.
            </P>
            <H3>Необходимые загрузки:</H3>
            <Ul items={[
                <>OWASP ZAP 2.16.1 или последняя версия с <Link href="https://www.zaproxy.org/download" target="_blank" rel="noopener noreferrer" className={LinkStyle}>zaproxy.org/download</Link></>,
                <>Firefox Developer Edition с <Link href="https://www.mozilla.org/firefox/developer" target="_blank" rel="noopener noreferrer" className={LinkStyle}>mozilla.org/firefox/developer</Link></>,
                "Обеспечьте достаточные системные ресурсы (минимум 4 ГБ ОЗУ, рекомендуется 8 ГБ)"
            ]} />
            
            <H2>Понимание интеграции ZAP и Firefox</H2>
            <P>
                OWASP ZAP функционирует как прокси-сервер "человек-по-середине", который перехватывает веб-трафик между вашим браузером и целевыми приложениями. Firefox Developer Edition должен быть настроен для маршрутизации всего HTTP и HTTPS трафика через локальный прокси-сервер ZAP, обычно работающий на localhost:8080.
            </P>
            
            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-183340.png')}
                    alt="Главный интерфейс приложения OWASP ZAP, показывающий экран приветствия и главный прокси, работающий на localhost:8081."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>
            
            <P>
                Интеграция обеспечивает комплексное тестирование безопасности, позволяя ZAP анализировать, изменять и проверять все веб-запросы и ответы. Эта настройка необходима для динамического тестирования безопасности приложений (DAST) и ручных рабочих процессов тестирования на проникновение.
            </P>

            <H2>Пошаговый процесс настройки</H2>

            <H3>Этап 1: Настройка OWASP ZAP</H3>
            <P><strong>1. Установка и запуск ZAP</strong></P>
            <P>После загрузки и установки OWASP ZAP запустите приложение. Конфигурация по умолчанию устанавливает локальный прокси на localhost:8080. Вы можете проверить это в строке состояния в нижней части интерфейса ZAP.</P>
            
            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-183430.png')}
                    alt="Главный графический интерфейс OWASP ZAP 2.8.0, показывающий экран приветствия и различные панели навигации."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <P><strong>2. Настройка параметров прокси ZAP</strong></P>
            <P>Перейдите в Tools > Options > Network > Local Servers/Proxies для настройки параметров прокси. Конфигурация по умолчанию обычно использует: Address: localhost (127.0.0.1), Port: 8080. Запомните точный адрес и порт, так как они понадобятся для настройки Firefox.</P>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-183538.png')}
                    alt="Конфигурация локального прокси OWASP ZAP, показывающая адрес и порт по умолчанию для интеграции с браузером."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <P><strong>3. Генерация SSL-сертификата</strong></P>
            <P>Для перехвата HTTPS-трафика сгенерируйте динамический SSL-сертификат: перейдите в Tools > Options > Network > Server Certificates, нажмите "Generate", чтобы создать новый корневой сертификат, затем "Save" и выберите запоминающееся место для файла сертификата. Этот сертификат имеет решающее значение для избежания предупреждений о сертификатах SSL/TLS при тестировании HTTPS-сайтов.</P>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-183629.png')}
                    alt="Создание SSL-сертификата в OWASP ZAP."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <H3>Этап 2: Конфигурация Firefox Developer Edition</H3>
            <P><strong>4. Доступ к настройкам сети</strong></P>
            <P>Откройте Firefox Developer Edition и перейдите в "Настройки" > "Настройки сети" > "Настроить...".</P>

            <P><strong>5. Настройка ручного прокси</strong></P>
            <P>В диалоговом окне "Параметры соединения" выберите "Ручная настройка прокси", введите `localhost` в поле "HTTP прокси" и `8080` в поле "Порт". Установите флажок "Использовать этот прокси-сервер для всех протоколов".</P>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-183715.png')}
                    alt="Диалоговое окно настроек соединения Firefox для ручной настройки прокси."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-183849.png')}
                    alt="Диалоговое окно настроек соединения Firefox для ручной настройки прокси, с подробными полями для HTTP, HTTPS и SOCKS прокси."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <P><strong>6. Включение перехвата прокси для localhost</strong></P>
            <P>Критический шаг: современные версии Firefox блокируют прокси-соединения с localhost по умолчанию. Чтобы включить проксирование трафика localhost: введите `about:config` в адресной строке Firefox, найдите `network.proxy.allow_hijacking_localhost` и установите значение `true`.</P>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-184009.png')}
                    alt="Настройка about:config в Firefox для разрешения перехвата прокси для localhost."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <H3>Этап 3: Управление сертификатами</H3>
            <P><strong>7. Импорт корневого сертификата ZAP</strong></P>
            <P>Чтобы избежать предупреждений о сертификатах на HTTPS-сайтах: откройте "Настройки" Firefox > "Приватность и защита" > "Сертификаты" > "Просмотр сертификатов". Выберите вкладку "Центры сертификации" (не "Ваши сертификаты"), нажмите "Импортировать", выберите файл сертификата ZAP и установите флажок "Доверять этому ЦС для идентификации веб-сайтов".</P>

            <H2>Тестирование и проверка</H2>
            <P><strong>Базовый тест подключения:</strong></P>
            <Ul items={[
                "HTTP-тест: перейдите на любой HTTP-сайт (например, http://httpforever.com)",
                "HTTPS-тест: перейдите на любой HTTPS-сайт (например, https://www.google.com)",
                "Проверьте трафик: проверьте вкладки Sites и History в ZAP на наличие захваченных запросов."
            ]}/>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-184214.png')}
                    alt="Рабочий процесс настройки OWASP ZAP и Firefox Developer Edition."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <H2>Устранение распространенных проблем</H2>
            <P><strong>Ошибки сертификатов на HTTPS-сайтах:</strong> Обычно это означает, что корневой сертификат ZAP не был правильно импортирован. Повторно сгенерируйте сертификат в ZAP и импортируйте его во вкладку "Центры сертификации" Firefox с включенным параметром "Доверять этому ЦС".</P>
            <P><strong>Пустая история в ZAP:</strong> Если ZAP не показывает трафик, проверьте настройки прокси в обоих приложениях. Перезапустите ZAP и Firefox, затем сначала протестируйте с простым HTTP-сайтом.</P>
            
            <H2>Заключение</H2>
            <P>Успешная настройка OWASP ZAP с Firefox Developer Edition создает мощную платформу для тестирования безопасности веб-приложений. Ключом к успеху является правильное управление сертификатами и обеспечение включения перехвата прокси для localhost. Эта конфигурация обеспечивает комплексное динамическое тестирование безопасности приложений, от автоматического сканирования уязвимостей до детальных ручных рабочих процессов тестирования на проникновение.</P>

            <figure className="my-6 text-center">
                <Image
                    src={getImagePath('pics/owasp-installation/screenshot-2025-07-03-184245.png')}
                    alt="Успешная установка OWASP ZAP."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                />
            </figure>

            <H2 id="sources">Источники</H2>
            <ol className="list-decimal list-inside space-y-2 text-sm">
                {sourcesData.map(source => (
                <li key={source.id} id={`source-${source.id}`}>
                    <Link href={source.url} target="_blank" rel="noopener noreferrer" className={LinkStyle}>{source.text}</Link>
                </li>
                ))}
            </ol>
        </ContentPageLayout>
    );
}