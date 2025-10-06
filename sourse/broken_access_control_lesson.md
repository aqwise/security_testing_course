Broken access control

![][image1]

Автор: Vladyslav Koniakhin

2

Добавьте реакцию

![][image2]Add Approve

**Что такое нарушение контроля доступа?**  
Нарушение контроля доступа — это уязвимость, которая позволяет злоумышленнику повысить свои права в приложении или получить доступ к ограниченным разделам и функциям.  
Матрица доступа, разработанная и реализованная в проекте, которая на бумаге выглядела так хорошо, может быть неправильно применена к конкретной системе, в результате чего злоумышленники быстро получают доступ к ограниченным разделам сайта или получают  
возможность изменять права на ресурсы по своему усмотрению.

**Наиболее распространенные уязвимости системы контроля доступа включают:**

1. Обход ограничений доступа путем **изменения URL-адреса**, внутреннего состояния приложения или HTML-страницы, а также использования специально разработанных API;  
2. Возможность изменения **первичного ключа для доступа к записям других пользователей**, включая просмотр или редактирование чужой учетной записи; повышение привилегий.  
3. **Выполнение операций с правами пользователя без входа в систему или с правами администратора, путем входа в систему с правами пользователя**;  
   Например есть два интерфейса для *Users*, второй для *Admin*, но на одном API. Создаем Usera с правами Admin(например добавив параметр user\_role:admin во время создания юзера). Далее, на [admin.example.com](http://admin.example.com/) мы зайти не можем, но можем все админские действия выполнять из под [user.example.com](http://user.example.com/).  
4. **Манипулирование метаданными**, например воспроизведение или подделка токенов контроля доступа **JWT**(например подбор ключа для токена) или файлов **cookie**(например перебор **cookie**), изменение скрытых полей для повышения привилегий или некорректная аннулирование JWT;  
5. **Несанкционированный доступ к API** из\-за неправильной настройки междоменного использования ресурсов (**CORS**);  
6. Доступ неавторизованных пользователей к страницам, требующим аутентификации, или доступ непривилегированных пользователей к выбранным страницам.  
7. Доступ к API без контроля привилегий для методов/запросов **POST, PUT, PATCH и DELETE**.  
8. **Просто забытые / не задокументированные API-calls**, которые мы можем обнаружить во время разведки(отличны пример **/actuator** **sping boot**), публично доступные статические файлы и тд.

**Импакт:**

1. Выполнение злоумышленником действий с правами пользователя или администратора;  
2. Использование привилегированных функций пользователем;  
3. Создание, просмотр, обновление или удаление любых записей.  
4. Последствия для бизнеса зависят от критичности приложения и защиты данных.

То есть, изменить имя админа или другого пользователя это одно, но если помимо этого мы можем загрузить файл на сервер без авторизации, то тут уже может быть все совсем по другому.

**Процесс эксплуатации**  
На самом деле существует множество способов эксплуатации и метод эксплуатации зависит от места, где находится уязвимость.  
Классический вариант \- подмена **ID, UUID** и тд. Либо возможности пользователя с одними правами, совершать действиями, которые ему не доступны. Как пример \- есть фича загрузки файлов для админа, которая не доступна для обычного пользователя. Но заменив **cookie / jwt** токен с **админского** на **обычного** юзера и отправив запрос, мы получаем статус ответ **200 ОК**. Далее проверив с админского аккаунта, действительно ли загружен файл и потвердив это, мы можем уверенно сказать, что здесь существует уязвимость.

**Способы поиска уязвимостей**

Как и в случае со всеми абсолютно приложениями – это **понять бизнес идею приложения**.  
 Рассмотрите типы авторизованных пользователей в вашей системе. Ограничен ли доступ пользователей к функциям и данным, к которым они не должны иметь доступа? Доступны ли какие-либо функции или данные для неавторизованных пользователей? Возможно ли получить доступ к частным данным или функциям путем изменения передаваемого параметра на сервер?

**Способы защиты от уязвимостей**

1. Рекомендуется запретить доступ к функциям по умолчанию.  
2. Используйте списки контроля доступа и механизмы аутентификации на основе ролей или атрибутов.

**Ниже приведены векторы атак и способы защиты от них:**  
**Insecure IDs** — большинство веб\-сайтов используют идентификаторы в той или иной форме для обозначения пользователей, ролей, контента, объектов или функций. Если злоумышленник может угадать эти идентификаторы, а предоставленные значения не проверяются на авторизацию для текущего пользователя(поменяли ID, отправили запрос, получили информацию о другом пользователе), он может использовать схему контроля доступа, чтобы узнать, к чему у него есть доступ. Веб-приложения не должны полагаться на конфиденциальность каких-либо идентификаторов для защиты.  
**Forced Browsing Past Access Control Checks** — многие сайты требуют от пользователей прохождения определенных проверок, прежде чем им будет предоставлен доступ к определенным URL-адресам. Эти проверки не должны быть обходимыми. Допустим, у вас есть учетная запись на веб\-сайте, предоставляющем доступ к конфиденциальным данным. Для получения доступа к этим данным требуется определенная проверка, например, ввод правильного имени пользователя и пароля. Однако вы заметили, что в адресной строке браузера URL-адрес содержит уникальный идентификатор страницы с конфиденциальной информацией. Используя этот идентификатор, вы можете попытаться обойти проверку доступа, например, введя его вручную в адресную строку браузера(не всегда работает) или в Burp Suite в вкладке Repeater..  
**Path Traversal** — эта атака заключается в предоставлении информации об относительном пути (например, "../../target\_dir/target\_file") в рамках запроса информации. Злоумышленники пытаются получить доступ к файлам, к которым обычно нет прямого доступа.

Предположим, у вас есть веб\-сайт, предоставляющий доступ к файлам, расположенным на сервере. Вы хотите загрузить файлы на сервер, но вам не разрешено загружать файлы в корневой каталог. Однако вы заметите, что запросы к серверу используют относительный путь к каталогу, куда вы загружаете файлы. Например, запрос может выглядеть так: [http://example.com/upload?path=uploads/myfile.jpg](http://example.com/upload?path=uploads/myfile.jpg) Вы понимаете, что, изменив относительный путь, вы можете попытаться получить доступ к другим файлам на сервере. Например, вы можете попробовать загрузить файл, используя следующий путь: [http://example.com/upload?path=../../etc/passwd.](http://example.com/upload?path=../../etc/passwd.) В этом случае, если сервер не проверяет путь к файлу, злоумышленник может загрузить файл в любой каталог на сервере, включая системные каталоги, такие как /etc/, что может привести к возможности выполнения произвольного кода на сервере или получению доступа к конфиденциальной информации.  
**File Permissions** — только файлы, предназначенные для просмотра веб\-пользователями, должны быть помечены как доступные для чтения, большинство каталогов должны быть недоступны для чтения, а минимальное количество файлов должно быть помечено как исполняемые.  
**Client Side Caching** — многие пользователи обращаются к веб\-приложениям с общедоступных компьютеров, расположенных в библиотеках, школах, аэропортах и ​​других общественных местах. Браузеры часто кэшируют веб\-страницы, и злоумышленники могут получить доступ к их кэшу и таким образом получить конфиденциальную информацию. Разработчикам необходимо использовать несколько механизмов, включая HTTP-заголовки и метатеги, чтобы гарантировать, что страницы, содержащие конфиденциальную информацию, не будут кэшироваться браузерами пользователей. Обращаем внимание на хедеры Cache, X-Cache и др.

**Как предотвратить уязвимость**

Контроль доступа эффективен только в том случае, если он реализован с помощью проверенного серверного кода или бессерверного API, где злоумышленник не может изменить проверки доступа или метаданные.

**Рекомендуется:**

1. По умолчанию запрещать доступ, за исключением открытых ресурсов;  
2. Внедрять механизмы контроля доступа и использовать их во всех приложениях, а также минимизировать междоменное использование ресурсов;  
3. Контролировать доступ к моделям с помощью права собственности на записи, а не возможности пользователей создавать, просматривать, обновлять или удалять любые записи; (То есть конкретный пользователь имеет доступ к конкретным данным, предписанным для его роли в модели доступа)  
4. Использовать доменные модели для реализации ограничений, специфичных для приложения;  
5. Отключить перечень каталогов веб\-сервера и убедиться, что метаданные файлов (такие как .git и тд.) и файлы резервных копий не находятся в корневых каталогах веб\-сервера;  
6. Регистрировать сбои контроля доступа и уведомлять администраторов в случае необходимости (например, если сбои повторяются);  
7. Ограничить частоту доступа к API и контроллерам, чтобы минимизировать ущерб от инструментов автоматизации атак(ограничение скорости);  
8. Инвалидировать токены JWT на сервере после выхода из системы.

**Какие инструменты мы используем?**  
Инструменты, обычно используемые для поиска BAC\\IDOR: Burp Suite (Proxy / Intercept / Repeater/ Addon Autorize).  
Инструкция по Autorize:

[How to use Autorize](https://authorizedentry.medium.com/how-to-use-autorize-fcd099366239)

В двух словах \- авторизируемся и получаем токен или куки с одного аккаунта, также делаем в со вторым аккаунтом в инкогнито. Вставляем их в расширение и идем по вкладкам от меньшей привелегии к большей. Данные получаем автоматически. Но важно заметить, что ручное тестирование дает больше результата и точности, но если у нас несколько ролей и большой скоуп API-calls, то это упрощает проведение анализа.

**Burp Suite Extensions**

1. Autorize — популярное расширение для поиска уязвимостей BAC. (Burp Suite Community Edition) GitHub: [GitHub \- PortSwigger/autorize: Automatic authorization enforcement detection extension for burp suite written in Jython developed by Barak Tawily in order to ease application security people work and allow them perform an automatic authorization tests](https://github.com/PortSwigger/autorize)  
    BAppStore: **Autorize**  
2. **Turbo Intruder** — благодаря хорошей скорости работы Turbo Intruder удобно использовать для поиска/эксплуатации IDOR-уязвимостей, подбора различных идентификаторов, токенов и других подобных целей. (Burp Suite Community Edition)  
   GitHub: [GitHub \- PortSwigger/turbo-intruder: Turbo Intruder is a Burp Suite extension for sending large numbers of HTTP requests and analyzing the results.](https://github.com/PortSwigger/turbo-intruder)  
    bAppStore: **Turbo Intruder**

**Домашнее задание**

Также дополнительную теорию читаем на [PortSwigger](https://portswigger.net/web-security/access-control) и выполняем следующие лабы:

1. [Unprotected Admin Functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)  
2. [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)  
3. [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)  
4. [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)  
5. [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)  
6. [User ID controlled by request parameter, with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)  
7. [User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)  
8. [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)  
9. [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)  
10. [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

И задания со **\***

11. [URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)  
12. [Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

Не все уязвимости могут встретиться на реальных проектах, не все может получиться при прохождении, но главное – понять суть на что, где и когда обращать внимание и на что мы как атакующие можем повлиять.

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAADAFBMVEVHcEwAAP9SQ6pSQ6pSQ6pSQ6paPKVSQ6pSQ6pRQ6pSQ6pSQ6tSQ6tSQ6pHR7hSQ6qAgIBSQ6pSQ6pTQ6lSQ6pSQ6tTQ6pSQ6pSRKpSQqpQQqtSQ6pTRKpSQ6pTQ6pTQKpSQ6pSQqpSQqpRQ6tSQ6pVQqpRQ6lTQ6pRQ6pSQqpNTbNSQ6pSQ6pSRKpTRKlSQ6tRQqpVRKpSQ6pVR6pSQqhVVapSQ6tSQ6pSQ6pRQahTRKpSQ6pTQ6lTRK1RRKpSQqpTRKtSQ6lSQ6tRRKtSQ6pSQ6pNQKZTRaxVRKpRQ6pbSaRSQ6pSQ6pTQ6pRRqhSQ6r///+jm9Ln5PP+/v/9/f5TRKtaTK7z8vlWR6z6+f3m5PNXSa2up9d4bb3r6fVVRqxqXrbx8Pj8+/1lWLRcTq+MgsdgUrHs6/a9t9+gl9C6td6zrNq0rtp9csB8cb9YSq1eULDj4PH39vuclM/u7fdoW7V2aby/ueCEesO3sdyAdcFiVLK2sNvl4/J/dMDPy+fc2e5uYrh7b774+PxxZbmPhcjp5/TV0epsX7fBvOGwqdjh3vCJf8Z3bLyZkM3JxOSYj8yRiMrX0+uTisrj4fGrpNayq9nKxuXOyeeGe8Pv7vdzZ7unn9TTz+nHwuPY1Oz19PqhmdHEvuLFwOKakc6HfMTn5fNfUbCCd8KpodXe3O9kVrO4stzQzOjZ1uymntPd2u7MyOaoodSVjMsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACzCjWcAAAAT3RSTlMAAb7f+f4I/foX74t5zgNhAlboKbB3QNux1EnQ7vfSI59eWYTGG2t+2aUKwUSiU2xCHroSMgZnR8svZsRQIjzAiKF0pvOcFCUPgQ7i8nIsrCk8cwAAAGFJREFUeF5jZAABfzC5EUQwwrlQIUZkPkiEEYUPFGFC4QIBI0gB2y8Gxv8MYMwAVvGbgSERyoeoYPwPVwBRAWaJgI2ACDAwqjIwvPkPchNU4P8tuEIi3IHpdEzPwYXA3gcAbfcXDnNsW3UAAAAASUVORK5CYII=>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA8AAAAPCAYAAAA71pVKAAABhElEQVR4Xl2Tu04CQRSGN2FttdDEiJcYaNT3ofHSaGKCO4UN7NLYkKjxbDTxlUwshAZ8BAt9AhNui/9/5iyMFB9z5uy5/DNziFyWRyRpS+TSPFY7lajZeqJ/8wZ+7i0uVrvjc7yzowkVCzgEz2AIvsEACNizwpXr20fN0Y50WPVLMIM99+S2yhz+MThjXBkPqaJSwRUIAqUA74D7kfnJqcXH5VkotfABMmVHnyQ7ziuYwZ5YgRGoMq+8jJeyIwILXJwWAnVds5wFi0DBvcputthZPoNuIbWVfWFxPay8bdkCP4k/7xs4ACfgGP41s49MxdCSv8B6xAowBt65itR9x6XPZH+obP5gk6szFZ6JT1U+V82vPDMl63cmdzUZlcm+W97mxLqSqnWe0W/ff8G20wmzkQQXgSx95ySTviWH79xwPCryVHaynLBzBI9NKo7xb8LYscFGZbwOSfvuNZht2cX6APqJ3mreA12nUtEoWzSyP4avxjXWAFWjhTZMmY/DKC9s8AfFX7TNalGuSwAAAABJRU5ErkJggg==>