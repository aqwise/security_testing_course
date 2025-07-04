
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { CodeBlock } from '@/components/content/CodeBlock';
import Link from 'next/link';
import Image from 'next/image';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sourcesData = [
    { id: 1, text: "null-android-pentesting.netlify.app", url: "https://null-android-pentesting.netlify.app/src/dynamic-analysis/using-mobsf.html" },
    { id: 2, text: "infosecwriteups.com", url: "https://infosecwriteups.com/mobsf-simplifying-mobile-app-security-testing-b3103739eb76" },
    { id: 3, text: "stackoverflow.com", url: "https://stackoverflow.com/questions/62729921/how-to-run-dynamic-analysis-by-mobsf" },
    { id: 4, text: "browserstack.com", url: "https://www.browserstack.com/guide/android-emulators-for-windows" },
    { id: 5, text: "youtube.com/watch?v=wZqIpnwC62Q", url: "https://www.youtube.com/watch?v=wZqIpnwC62Q" },
    { id: 6, text: "pt.slideshare.net", url: "https://pt.slideshare.net/slideshow/appsec-pnw-android-and-ios-application-security-with-mobsf/269727387" },
    { id: 7, text: "stackoverflow.com", url: "https://stackoverflow.com/questions/78982102/failure-to-connect-mobsf-container-to-genymotion-vm-via-adb" },
    { id: 8, text: "youtube.com/watch?v=QzsNn3GhYYk", url: "https://www.youtube.com/watch?v=QzsNn3GhYYk" },
    { id: 9, text: "genymotion.com/blog", url: "https://www.genymotion.com/blog/tutorial/mobsf-genymotion-device-image/" },
    { id: 10, text: "slideshare.net", url: "https://www.slideshare.net/slideshow/mobsf-mobile-security-testing-androidios/262458671" },
    { id: 11, text: "freebuf.com", url: "https://www.freebuf.com/articles/mobile/368008.html" },
    { id: 12, text: "developer.android.com/studio", url: "https://developer.android.com/studio/run/emulator/" },
    { id: 13, text: "mobsf.github.io/docs/", url: "https://mobsf.github.io/docs/" },
    { id: 14, text: "youtube.com/watch?v=0ar8uD07Sy0", url: "https://www.youtube.com/watch?v=0ar8uD07Sy0" },
    { id: 15, text: "youtube.com/watch?v=XiPLW-TsuyU", url: "https://www.youtube.com/watch?v=XiPLW-TsuyU" },
    { id: 16, text: "developer.android.com/studio/run/emulator-commandline", url: "https://developer.android.com/studio/run/emulator-commandline" },
    { id: 17, text: "youtube.com/watch?v=4nzt1uwuwf8", url: "https://www.youtube.com/watch?v=4nzt1uwuwf8" },
    { id: 18, text: "github.com/MobSF", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF?tab=readme-ov-file" },
    { id: 19, text: "github.com/MobSF/issues/2376", url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF/issues/2376" },
    { id: 20, text: "source.android.com/docs", url: "https://source.android.com/docs/setup/test/avd" },
];


export default function MobSfSetupPage() {
    return (
        <ContentPageLayout
            title="Настройка DAST с Genymotion на Windows для MobSF"
            subtitle="Руководство по настройке Dynamic Application Security Testing (DAST) с использованием Mobile Security Framework (MobSF) и эмулятора Genymotion на операционной системе Windows."
        >
            <figure className="my-6 text-center">
                <Image
                    src="https://placehold.co/800x450.png"
                    alt="A flow diagram illustrating the typical process and architectural components of a DAST framework."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                    data-ai-hint="DAST framework diagram"
                />
                <figcaption className="mt-2 text-sm text-muted-foreground">A flow diagram illustrating the typical process and architectural components of a DAST framework.</figcaption>
            </figure>

            <H2>Обзор архитектуры системы</H2>
            <P>MobSF представляет собой автоматизированный фреймворк для анализа безопасности мобильных приложений, поддерживающий как статический, так и динамический анализ. Для динамического анализа Android-приложений MobSF использует Android Debug Bridge (ADB) для взаимодействия с эмулятором или физическим устройством<Link href="#source-1" className={LinkStyle}><sup className="align-super text-xs">1</sup></Link><Link href="#source-2" className={LinkStyle}><sup className="align-super text-xs">2</sup></Link>.</P>
            
            <figure className="my-6 text-center">
                <Image
                    src="https://placehold.co/800x450.png"
                    alt="Архитектура настройки DAST с MobSF и Genymotion"
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                    data-ai-hint="architecture diagram mobsf"
                />
                <figcaption className="mt-2 text-sm text-muted-foreground">Архитектура настройки DAST с MobSF и Genymotion</figcaption>
            </figure>

            <P>Genymotion является одним из наиболее эффективных Android-эмуляторов для тестирования безопасности, поскольку он базируется на VirtualBox и предоставляет root-доступ по умолчанию, что критично для глубокого анализа безопасности<Link href="#source-3" className={LinkStyle}><sup className="align-super text-xs">3</sup></Link><Link href="#source-4" className={LinkStyle}><sup className="align-super text-xs">4</sup></Link>.</P>
            
            <H2>Системные требования</H2>
            <P>Перед началом установки необходимо убедиться, что система соответствует минимальным требованиям для корректной работы всех компонентов.</P>
            <P><strong>Важно</strong>: MobSF поддерживает динамический анализ только для Android API уровня до 28 включительно. Более новые версии Android имеют ограничения на запись в директорию /system, что делает невозможным установку необходимых агентов MobSF<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link><Link href="#source-6" className={LinkStyle}><sup className="align-super text-xs">6</sup></Link>.</P>
            
            <H2>Этап 1: Подготовка системы Windows</H2>
            <H3>Установка Python</H3>
            <Ul items={[
                "Скачайте Python версии 3.8-3.11 с официального сайта python.org",
                "Запустите установщик с правами администратора",
                "Обязательно отметьте опцию \"Add Python to PATH\"",
                "Проверьте установку: откройте командную строку и выполните `python --version`"
            ]} />
            <H3>Установка JDK</H3>
            <Ul items={[
                "Скачайте Oracle JDK 8 или новее или используйте OpenJDK",
                "Установите JDK, следуя инструкциям установщика",
                "Настройте переменную окружения JAVA_HOME: Перейдите в Панель управления → Система → Дополнительные параметры системы, нажмите \"Переменные среды\" и добавьте новую системную переменную JAVA_HOME со значением пути к JDK"
            ]} />
            <H3>Установка Git</H3>
            <Ul items={[
                "Скачайте Git для Windows с git-scm.com",
                "Запустите установку с настройками по умолчанию",
                "Проверьте установку: `git --version`"
            ]} />
            <H3>Установка Microsoft Visual C++ Build Tools</H3>
            <Ul items={[
                "Скачайте Visual Studio Build Tools или Visual Studio Community",
                "Выберите компоненты C++ build tools во время установки",
                "Перезагрузите систему после установки"
            ]} />
            <H3>Установка OpenSSL</H3>
            <Ul items={[
                "Скачайте OpenSSL для Windows (64-bit версию) с slproweb.com",
                "Установите в стандартную директорию",
                "Добавьте путь к OpenSSL в переменную PATH"
            ]} />

            <H2>Этап 2: Установка и настройка MobSF</H2>
            <H3>Клонирование репозитория</H3>
            <P>Откройте командную строку как администратор и выполните:</P>
            <CodeBlock language="bash" code="git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git\ncd Mobile-Security-Framework-MobSF" />
            <H3>Запуск установки</H3>
            <P>Выполните автоматический скрипт установки:</P>
            <CodeBlock language="bash" code="setup.bat" />
            <P>Этот процесс может занять 10-20 минут, так как происходит загрузка всех необходимых зависимостей<Link href="#source-7" className={LinkStyle}><sup className="align-super text-xs">7</sup></Link>.</P>
            <H3>Первый запуск MobSF</H3>
            <P>После успешной установки запустите MobSF:</P>
            <CodeBlock language="bash" code="run.bat 127.0.0.1:8000" />
            <P>Откройте браузер и перейдите по адресу http://127.0.0.1:8000. Должен открыться веб-интерфейс MobSF с логином и паролем mobsf/mobsf<Link href="#source-8" className={LinkStyle}><sup className="align-super text-xs">8</sup></Link><Link href="#source-9" className={LinkStyle}><sup className="align-super text-xs">9</sup></Link>.</P>

            <H2>Этап 3: Установка Genymotion и VirtualBox</H2>
            <H3>Установка VirtualBox</H3>
            <Ul items={[
                "Скачайте VirtualBox с официального сайта Oracle",
                "Запустите установку с правами администратора",
                "Следуйте инструкциям установщика и примите временное отключение сети"
            ]}/>
            <H3>Установка Genymotion</H3>
            <Ul items={[
                "Зарегистрируйтесь на сайте genymotion.com для получения персональной лицензии",
                "Скачайте Genymotion Desktop (включая VirtualBox или без него, если уже установлен)",
                "Запустите установку и следуйте инструкциям",
                "Войдите в учетную запись при первом запуске Genymotion"
            ]} />
            <figure className="my-6 text-center">
                <Image
                    src="https://placehold.co/800x450.png"
                    alt="Genymotion Android emulator interface showing a Samsung Galaxy S8 virtual device and an Open GApps installation prompt."
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                    data-ai-hint="android emulator interface"
                />
                <figcaption className="mt-2 text-sm text-muted-foreground">Genymotion Android emulator interface showing a Samsung Galaxy S8 virtual device and an Open GApps installation prompt.</figcaption>
            </figure>
            <H3>Создание виртуального устройства</H3>
            <Ul items={[
                "Запустите Genymotion и нажмите кнопку \"+\" для добавления нового устройства",
                "Выберите Android-устройство с API 28 или ниже (рекомендуется Android 9, API 28)",
                "Настройте параметры устройства: объем RAM, разрешение экрана",
                "Дождитесь загрузки образа системы (может занять значительное время)",
                "Запустите созданное устройство для проверки работоспособности"
            ]} />

            <H2>Этап 4: Настройка ADB и подключения</H2>
            <H3>Установка Android SDK Platform Tools</H3>
            <Ul items={[
                "Скачайте Android SDK Platform Tools с developer.android.com",
                "Извлеките архив в удобную директорию (например, C:\\platform-tools)",
                "Добавьте путь к platform-tools в переменную PATH"
            ]} />
            <H3>Настройка ADB в Genymotion</H3>
            <Ul items={[
                "Откройте настройки Genymotion (Settings)",
                "Перейдите в раздел ADB",
                "Выберите \"Use custom Android SDK tools\"",
                "Укажите путь к Android SDK (директория, содержащая platform-tools)"
            ]} />
            <H3>Проверка подключения ADB</H3>
            <P>Запустите виртуальное устройство в Genymotion, запомните его IP-адрес и в командной строке выполните:</P>
            <CodeBlock language="bash" code="adb connect IP_ADDRESS:5555\nadb devices" />
            <P>Вы должны увидеть подключенное устройство в списке<Link href="#source-2" className={LinkStyle}><sup className="align-super text-xs">2</sup></Link><Link href="#source-10" className={LinkStyle}><sup className="align-super text-xs">10</sup></Link>.</P>

            <H2>Этап 5: Конфигурация MobSF для динамического анализа</H2>
            <H3>Настройка ANALYZER_IDENTIFIER</H3>
            <P>Если MobSF не может автоматически обнаружить Android-устройство, найдите файл конфигурации в `&lt;пользователь&gt;/.MobSF/config.py` и добавьте или измените строку, где IP_ADDRESS - это адрес вашего Genymotion устройства<Link href="#source-2" className={LinkStyle}><sup className="align-super text-xs">2</sup></Link><Link href="#source-11" className={LinkStyle}><sup className="align-super text-xs">11</sup></Link>:</P>
            <CodeBlock language="python" code="ANALYZER_IDENTIFIER = 'IP_ADDRESS:5555'" />
            <H3>Настройка ADB_BINARY (при необходимости)</H3>
            <P>Если MobSF не может найти ADB, добавьте в config.py:</P>
            <CodeBlock language="python" code="ADB_BINARY = 'C:\\\\platform-tools\\\\adb.exe'" />
            <H3>Включение отладки USB на виртуальном устройстве</H3>
            <Ul items={[
                "На эмуляторе Android перейдите в Настройки → О телефоне",
                "Нажмите 7 раз на номер сборки для активации режима разработчика",
                "Вернитесь в Настройки → Параметры разработчика",
                "Включите \"Отладку по USB\""
            ]} />

            <H2>Этап 6: Запуск и тестирование динамического анализа</H2>
            <figure className="my-6 text-center">
                <Image
                    src="https://placehold.co/800x450.png"
                    alt="Пошаговый процесс настройки DAST с MobSF и Genymotion"
                    width={800}
                    height={450}
                    className="mx-auto rounded-md shadow-md"
                    data-ai-hint="process diagram setup"
                />
                <figcaption className="mt-2 text-sm text-muted-foreground">Пошаговый процесс настройки DAST с MobSF и Genymotion</figcaption>
            </figure>
            <H3>Подготовка к тестированию</H3>
            <Ul items={[
                "Убедитесь, что Genymotion устройство запущено и подключено через ADB",
                "Запустите MobSF командой `run.bat 127.0.0.1:8000`",
                "Откройте веб-интерфейс MobSF в браузере"
            ]} />
            <H3>Загрузка и анализ APK</H3>
            <Ul items={[
                "Загрузите APK-файл для анализа через веб-интерфейс MobSF",
                "Дождитесь завершения статического анализа",
                "Перейдите к разделу \"Dynamic Analysis\" в боковом меню",
                "Нажмите \"Start Dynamic Analysis\""
            ]} />
            <H3>Процесс динамического анализа</H3>
            <Ul items={[
                "MobSF автоматически установит необходимые агенты на виртуальное устройство",
                "Приложение будет установлено и запущено на эмуляторе",
                "Взаимодействуйте с приложением для генерации трафика и активности",
                "MobSF будет перехватывать сетевой трафик и анализировать поведение приложения"
            ]} />

            <H2>Устранение распространенных проблем</H2>
            <H3>Ошибка "Android Runtime not found"</H3>
            <P><strong>Причина:</strong> MobSF не может обнаружить Android-устройство<Link href="#source-12" className={LinkStyle}><sup className="align-super text-xs">12</sup></Link>.</P>
            <P><strong>Решение:</strong> Проверьте, что устройство видимо через `adb devices`, настройте ANALYZER_IDENTIFIER в config.py, перезапустите MobSF.</P>
            <H3>Ошибка "VM's /system is not writable"</H3>
            <P><strong>Причина:</strong> Используется Android API выше 28 или устройство не имеет root-доступа<Link href="#source-5" className={LinkStyle}><sup className="align-super text-xs">5</sup></Link>.</P>
            <P><strong>Решение:</strong> Используйте Android 9 (API 28) или ниже, убедитесь, что эмулятор имеет root-доступ. Для Android Studio эмулятора добавьте флаг `-writable-system`.</P>
            <H3>Проблемы с подключением ADB</H3>
            <P><strong>Причина:</strong> Конфликт между различными ADB серверами<Link href="#source-13" className={LinkStyle}><sup className="align-super text-xs">13</sup></Link>.</P>
            <P><strong>Решение:</strong> Остановите все ADB процессы: `adb kill-server`, перезапустите ADB: `adb start-server`, переподключите устройство: `adb connect IP:5555`.</P>
            <H3>Ошибки установки зависимостей</H3>
            <P><strong>Причина:</strong> Отсутствие необходимых компиляторов или библиотек<Link href="#source-14" className={LinkStyle}><sup className="align-super text-xs">14</sup></Link>.</P>
            <P><strong>Решение:</strong> Установите Microsoft Visual C++ Build Tools, обновите pip: `python -m pip install --upgrade pip`, установите зависимости по одной для выявления проблемных пакетов.</P>
            
            <H2>Рекомендации по безопасности</H2>
            <H3>Сетевая безопасность</H3>
            <Ul items={[
                "Ограничьте доступ к порту 5555 только с локальной машины",
                "Не открывайте ADB порт для внешних подключений",
                "Используйте файервол для контроля сетевого трафика"
            ]} />
            <H3>Изоляция среды тестирования</H3>
            <Ul items={[
                "Используйте выделенную сеть для тестирования",
                "Изолируйте тестовое окружение от производственных систем",
                "Регулярно обновляйте все компоненты системы"
            ]} />

            <H2>Заключение</H2>
            <P>Настройка DAST с MobSF и Genymotion на Windows требует тщательной подготовки и соблюдения всех этапов установки. Правильно настроенная система позволяет проводить глубокий анализ безопасности Android-приложений, включая перехват сетевого трафика, анализ API-вызовов и выявление уязвимостей во время выполнения.</P>
            <P>Ключевые моменты для успешной настройки:</P>
            <Ul items={[
                "Использование Android API 28 или ниже для совместимости с MobSF",
                "Правильная конфигурация ADB и сетевых подключений",
                "Внимательное следование системным требованиям",
                "Тестирование каждого этапа настройки перед переходом к следующему"
            ]} />
            <P>При возникновении проблем рекомендуется обращаться к официальной документации MobSF и сообществу разработчиков для получения поддержки.</P>

            <H2 id="sources">Источники</H2>
            <ol className="list-decimal list-inside space-y-2 text-sm">
                {sourcesData.slice(0, 20).map(source => (
                    <li key={source.id} id={`source-${source.id}`}>
                        <Link href={source.url} target="_blank" rel="noopener noreferrer" className={LinkStyle}>{source.text}</Link>
                    </li>
                ))}
            </ol>
        </ContentPageLayout>
    );
}
