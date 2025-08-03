
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import Link from 'next/link';
import { CodeBlock } from '@/components/content/CodeBlock';
import { YouTubePlayer } from '@/components/content/YouTubePlayer';
import { ShieldCheck, Lock, Network, Bug, ShieldAlert, KeyRound, LockKeyhole, FileLock } from 'lucide-react';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export default function ModernWebappSecurityPage() {
  return (
    <ContentPageLayout
      title="Ключевые аспекты безопасности современных веб-приложений"
      subtitle="Обзор основных уязвимостей, методов защиты и лучших практик для создания надежных и безопасных веб-приложений."
    >
      <P>
        Безопасность — это фундаментальный аспект разработки любого веб-приложения. Степень ее критичности варьируется: для одного проекта утечка данных может быть лишь неприятностью, для другого — финансовой катастрофой. Не существует универсального решения или "серебряной пули", способной мгновенно защитить систему. Эффективная безопасность — это всегда комплексный и многоуровневый процесс, требующий постоянного внимания.
      </P>

      <div className="my-8">
        <YouTubePlayer videoId="Kin8Miw4qso" />
        <p className="text-center mt-2 text-sm text-muted-foreground">
          Оригинальное видео: <Link href="https://www.youtube.com/watch?v=Kin8Miw4qso" target="_blank" rel="noopener noreferrer" className={LinkStyle}>https://www.youtube.com/watch?v=Kin8Miw4qso</Link>
        </p>
      </div>

      <Accordion type="multiple" defaultValue={['item-1', 'item-2']} className="w-full space-y-4">
        <AccordionItem value="item-1">
          <AccordionTrigger className="text-xl font-semibold"><ShieldCheck className="mr-2 h-5 w-5 text-primary" />Основы: HTTPS, Аутентификация и Авторизация</AccordionTrigger>
          <AccordionContent className="pt-4 space-y-4">
            <Card>
              <CardHeader><CardTitle>HTTPS: Защищенное соединение</CardTitle></CardHeader>
              <CardContent>
                <P>Протокол HTTPS является расширением стандартного HTTP с добавлением шифрования. Его использование — это базовый стандарт для современных сайтов.</P>
                <Ul items={[
                  "Шифрование: Защищает от атак типа 'человек посередине'.",
                  "Доверие: Браузеры помечают сайты, работающие по HTTPS, как безопасные.",
                  "SEO: Поисковые системы отдают предпочтение HTTPS-сайтам."
                ]}/>
                <P className="text-sm text-muted-foreground"><strong>Когда HTTPS может быть избыточен?</strong> Внутри изолированного кластера, где сервисы общаются в приватной сети, HTTP может быть оправдан для снижения нагрузки.</P>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Аутентификация и Авторизация</CardTitle></CardHeader>
              <CardContent>
                <Ul items={[
                  "Идентификация: Пользователь представляется системе (вводит логин).",
                  "Аутентификация: Система проверяет подлинность пользователя (сверяет пароль).",
                  "Авторизация: Система определяет, какие действия доступны аутентифицированному пользователю."
                ]}/>
                <P>Многофакторная аутентификация (MFA) повышает безопасность, требуя несколько подтверждений личности.</P>
              </CardContent>
            </Card>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="item-2">
          <AccordionTrigger className="text-xl font-semibold"><Lock className="mr-2 h-5 w-5 text-primary" />Управление паролями и доступом</AccordionTrigger>
          <AccordionContent className="pt-4 space-y-4">
            <Card>
              <CardHeader><CardTitle>Защита от подбора учетных данных</CardTitle></CardHeader>
              <CardContent>
                <P>Методы защиты от атак (брутфорс, credential stuffing):</P>
                <Ul items={[
                  "Общие сообщения об ошибках (например, 'Неверный логин или пароль').",
                  "Ограничение количества попыток входа (Rate Limiting).",
                  "Капча (CAPTCHA).",
                  "Использование OAuth (вход через доверенные сервисы)."
                ]}/>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Безопасное хранение паролей</CardTitle></CardHeader>
              <CardContent>
                <P>Никогда не хранить пароли в открытом виде. Использовать медленные, криптостойкие алгоритмы хеширования (bcrypt, Argon2) с "солью" и "перцем".</P>
                <CodeBlock language="javascript" code={`
const bcrypt = require('bcrypt');
const saltRounds = 10; // "Стоимость" хеширования

// Хеширование пароля
const password = 'mySuperPassword123';
const salt = await bcrypt.genSalt(saltRounds);
const hash = await bcrypt.hash(password, salt);

// Проверка пароля
const isMatch = await bcrypt.compare('mySuperPassword123', hash); // вернет true
                `.trim()} />
              </CardContent>
            </Card>
             <Card>
              <CardHeader><CardTitle>Принципы безопасной авторизации</CardTitle></CardHeader>
              <CardContent>
                <Ul items={[
                  "Принцип наименьших привилегий: Давать только необходимые права.",
                  "Запрет по умолчанию (Default Deny): Разрешать только явно указанные действия.",
                  "Проверка прав на каждый запрос на стороне сервера."
                ]}/>
              </CardContent>
            </Card>
          </AccordionContent>
        </AccordionItem>

        <AccordionItem value="item-3">
            <AccordionTrigger className="text-xl font-semibold"><Bug className="mr-2 h-5 w-5 text-primary" />Распространенные уязвимости и атаки</AccordionTrigger>
            <AccordionContent className="pt-4 grid md:grid-cols-2 gap-4">
              <Card>
                <CardHeader><CardTitle>IDOR (Insecure Direct Object References)</CardTitle></CardHeader>
                <CardContent>
                  <P>Перебор предсказуемых идентификаторов в URL для доступа к чужим данным. <br/><strong>Защита:</strong> Использовать UUID; всегда проверять права доступа на сервере.</P>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle>XSS (Cross-Site Scripting)</CardTitle></CardHeader>
                <CardContent>
                  <P>Внедрение вредоносного JS-кода на страницу. <br/><strong>Защита:</strong> Экранирование вывода, Content Security Policy (CSP), флаги cookie (HttpOnly, Secure).</P>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle>SQL-инъекции</CardTitle></CardHeader>
                <CardContent>
                  <P>Внедрение SQL-кода через пользовательский ввод.<br/><strong>Защита:</strong> Параметризованные запросы, принцип наименьших привилегий для пользователя БД.</P>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle>CSRF (Cross-Site Request Forgery)</CardTitle></CardHeader>
                <CardContent>
                  <P>Выполнение нежелательных запросов от имени пользователя.<br/><strong>Защита:</strong> CSRF-токены, атрибут SameSite для cookie.</P>
                </CardContent>
              </Card>
              <Card>
                <CardHeader><CardTitle>Clickjacking</CardTitle></CardHeader>
                <CardContent>
                  <P>Перехват кликов с помощью невидимого <iframe>.<br/><strong>Защита:</strong> Заголовок X-Frame-Options, CSP-директива frame-ancestors.</P>
                </CardContent>
              </Card>
            </AccordionContent>
        </AccordionItem>
        
        <AccordionItem value="item-4">
            <AccordionTrigger className="text-xl font-semibold"><ShieldAlert className="mr-2 h-5 w-5 text-primary" />Общие практики безопасности</AccordionTrigger>
            <AccordionContent className="pt-4 grid md:grid-cols-2 gap-4">
               <div className="bg-muted p-4 rounded-lg">
                  <h4 className="font-semibold text-foreground flex items-center mb-2"><KeyRound className="mr-2 h-4 w-4 text-accent-foreground"/>Валидация пользовательского ввода</h4>
                  <p className="text-sm text-muted-foreground">Никогда не доверяйте данным от клиента. Проверяйте формат и смысл всех входящих данных на бэкенде.</p>
               </div>
               <div className="bg-muted p-4 rounded-lg">
                  <h4 className="font-semibold text-foreground flex items-center mb-2"><FileLock className="mr-2 h-4 w-4 text-accent-foreground"/>Безопасная загрузка файлов</h4>
                  <p className="text-sm text-muted-foreground">Ограничивайте типы и размеры файлов, переименовывайте их при загрузке, храните на отдельном сервере.</p>
               </div>
               <div className="bg-muted p-4 rounded-lg">
                  <h4 className="font-semibold text-foreground flex items-center mb-2"><Network className="mr-2 h-4 w-4 text-accent-foreground"/>Настройка CORS и заголовков</h4>
                  <p className="text-sm text-muted-foreground">Правильно настройте CORS. Используйте пакеты типа 'helmet' для автоматического добавления заголовков безопасности.</p>
               </div>
                <div className="bg-muted p-4 rounded-lg">
                  <h4 className="font-semibold text-foreground flex items-center mb-2"><LockKeyhole className="mr-2 h-4 w-4 text-accent-foreground"/>Управление секретами и конфигурацией</h4>
                  <p className="text-sm text-muted-foreground">Не храните секреты в Git. Используйте переменные окружения. Скрывайте информацию о стеке.</p>
               </div>
            </AccordionContent>
        </AccordionItem>

      </Accordion>

      <H2 className="mt-8">Заключение</H2>
      <P>Безопасность — это не разовый проект, а непрерывный процесс, требующий бдительности на всех этапах жизненного цикла приложения. Поощрение "этичных хакеров" через Bug Bounty программы является эффективным способом выявить слабые места до того, как ими воспользуются злоумышленники.</P>

    </ContentPageLayout>
  );
}
