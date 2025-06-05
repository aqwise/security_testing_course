
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export function AuthnAttacksSection() {
  return (
    <section id="authn-attacks" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            A. Атака на Механизмы Аутентификации
          </h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">
            Уязвимости в проверке личности пользователя могут привести к полному захвату учетной записи. Рассмотрим основные векторы атак.
          </p>
        </div>
        <div className="max-w-4xl mx-auto space-y-8">
          <Card className="shadow-md">
            <CardHeader>
              <CardTitle className="text-2xl font-semibold text-foreground/90">Перебор Учетных Данных</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-accent-foreground">Перебор Паролей (Brute Force) и Имен Пользователей (Enumeration)</h4>
                <p className="text-sm text-muted-foreground">
                  Систематический подбор пароля для известного логина или определение действительных логинов. Инструменты: <Link href="https://github.com/vanhauser-thc/thc-hydra" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Hydra</Link>, <Link href="https://portswigger.net/burp/documentation/desktop/tools/intruder" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Intruder</Link>.
                </p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-accent-foreground">Атака Распылением Паролей (Password Spraying)</h4>
                <p className="text-sm text-muted-foreground">Попытка входа с одним/несколькими частыми паролями для большого списка пользователей. Менее "шумная" атака.</p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-accent-foreground">Защита от Перебора</h4>
                <p className="text-sm text-muted-foreground">Механизмы: блокировка учетных записей, rate limiting, <Link href="https://www.google.com/recaptcha/about/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>CAPTCHA</Link>. Важны сложные пароли и MFA.</p>
              </div>
            </CardContent>
          </Card>

          <Card className="shadow-md">
            <CardHeader>
              <CardTitle className="text-2xl font-semibold text-foreground/90">Уязвимости Логики Аутентификации</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-accent-foreground">Небезопасное Восстановление Пароля</h4>
                <p className="text-sm text-muted-foreground">Предсказуемые токены, передача токена в URL, недостаточная проверка, <Link href="https://portswigger.net/web-security/host-header/password-reset-poisoning" target="_blank" rel="noopener noreferrer" className={LinkStyle}>password reset poisoning</Link>.</p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-accent-foreground">Обход Многофакторной Аутентификации (MFA/2FA)</h4>
                <p className="text-sm text-muted-foreground">Слабая генерация кодов, нет ограничения попыток, уязвимости логики проверки, обход шага 2FA.</p>
              </div>
               <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-accent-foreground">Уязвимости "Запомнить меня"</h4>
                <p className="text-sm text-muted-foreground">Анализ стойкости и предсказуемости токенов в cookies "remember me".</p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
