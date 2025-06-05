
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

const sqlInjectionTableHeaders = ["Тип SQLi", "Индикатор Обнаружения", "Ключевая Техника Эксплуатации", "Инструменты"];
const sqlInjectionTableRows = [
  ["Error-based (In-band)", "Сообщения об ошибках БД в ответе", "Извлечение данных из текста ошибки", <>Ручной/<Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp</Link>, <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link></>],
  ["UNION-based (In-band)", "Данные из других таблиц добавляются к ответу", "UNION SELECT для объединения запросов", <>Ручной/<Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp</Link>, <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link></>],
  ["Boolean-based (Blind)", "Разница в ответе приложения (True/False)", "Условная логика (AND 1=1/AND 1=2)", <>Ручной/<Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp</Link>, <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link></>],
  ["Time-based (Blind)", "Задержка времени ответа сервера", "Условная задержка (WAITFOR, SLEEP)", <>Ручной/<Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp</Link>, <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link></>],
  ["Out-of-Band (OOB) (Blind)", "Внешнее сетевое взаимодействие (DNS, HTTP)", "Инициирование OOB-канала", <><Link href="https://portswigger.net/burp/documentation/collaborator" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Collaborator</Link>, <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link></>],
];

export function SqlInjectionSection() {
  return (
    <section id="sqli" className="py-16 md:py-24 bg-card">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">A. SQL-инъекции (SQLi)</h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">SQL-инъекции позволяют атакующему вмешиваться в запросы к базе данных. Это одна из самых опасных веб-уязвимостей.</p>
        </div>
        <div className="max-w-4xl mx-auto space-y-8">
          <Card>
            <CardHeader>
              <CardTitle className="text-2xl font-semibold text-foreground/90">Обнаружение SQLi</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">На основе ошибок (Error-based)</h4>
                <p className="text-sm text-muted-foreground">Приложение возвращает ошибки БД, раскрывая структуру запроса. <Link href="https://portswigger.net/web-security/sql-injection/examining-the-database" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатория PortSwigger (Error-based)</Link>.</p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">На основе логики (Boolean-based)</h4>
                <p className="text-sm text-muted-foreground">Ответ приложения меняется в зависимости от истинности внедренного условия. <Link href="https://portswigger.net/web-security/sql-injection/blind/lab-boolean-based" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатория PortSwigger (Boolean-based)</Link>.</p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">На основе времени (Time-based)</h4>
                <p className="text-sm text-muted-foreground">Внедрение команды, вызывающей задержку, и измерение времени ответа. <Link href="https://portswigger.net/web-security/sql-injection/blind/lab-time-based" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатории PortSwigger (Time-based)</Link>.</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-2xl font-semibold text-foreground/90">Техники Эксплуатации SQLi</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">UNION-атаки</h4>
                <p className="text-sm text-muted-foreground">Использование UNION для объединения результатов и извлечения данных из других таблиц. <Link href="https://portswigger.net/web-security/sql-injection/union-attacks" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатории PortSwigger (UNION)</Link>.</p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">Эксплуатация Blind SQLi</h4>
                <p className="text-sm text-muted-foreground">Посимвольное извлечение информации с использованием условных запросов (Boolean-based или Time-based).</p>
              </div>
              <div className="bg-background/70 p-4 rounded-lg border">
                <h4 className="font-semibold text-primary">Out-of-Band (OOB) SQLi</h4>
                <p className="text-sm text-muted-foreground">Инициирование внешнего сетевого взаимодействия (DNS, HTTP) с сервера БД для эксфильтрации данных. <Link href="https://portswigger.net/web-security/sql-injection/out-of-band" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Лаборатории PortSwigger (OOB)</Link>.</p>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader>
                <CardTitle className="text-2xl font-semibold text-foreground/90">Автоматизация с sqlmap</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="bg-background/70 p-4 rounded-lg border">
                    <p className="text-sm text-muted-foreground">Знакомство с <Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link> для автоматизации. Опции: -u, --data, --cookie, --dbs, --tables, --columns, --dump, --current-user, --current-db.</p>
                </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
                <CardTitle className="text-2xl font-semibold text-foreground/90">Предотвращение SQLi</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="bg-background/70 p-4 rounded-lg border">
                    <p className="text-sm text-muted-foreground">Методы: параметризованные запросы (Prepared Statements), хранимые процедуры (с осторожностью), валидация по "белому списку", экранирование (менее надежно). <Link href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP SQLi Prevention Cheat Sheet</Link>.</p>
                </div>
            </CardContent>
          </Card>

          <div className="mt-8 overflow-x-auto">
            <h3 className="text-xl font-semibold text-foreground/90 mb-3 text-center">Типы SQL-инъекций и Методы</h3>
            <div className="shadow-md rounded-lg">
              <table className="min-w-full divide-y divide-border bg-card">
                <thead className="bg-muted/50">
                  <tr>
                    {sqlInjectionTableHeaders.map(header => (
                      <th key={header} scope="col" className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        {header}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-card divide-y divide-border">
                  {sqlInjectionTableRows.map((row, rowIndex) => (
                    <tr key={rowIndex} className="hover:bg-muted/30">
                      {row.map((cell, cellIndex) => (
                        <td key={cellIndex} className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                          {cell}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
