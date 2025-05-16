import { ContentPageLayout, P, Ul, H2, H3, TableComponent } from '@/components/content/ContentPageLayout';
import { ServerIcon, Database, Terminal, FileCode, UploadCloud } from 'lucide-react';

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
    ["Error-based (In-band)", "Сообщения об ошибках БД", "Извлечение данных из текста ошибки", "Ручной/Burp, sqlmap"],
    ["UNION-based (In-band)", "Данные из других таблиц в ответе", "UNION SELECT", "Ручной/Burp, sqlmap"],
    ["Boolean-based (Blind)", "Разница в ответе (True/False)", "Условная логика", "Ручной/Burp, sqlmap"],
    ["Time-based (Blind)", "Задержка времени ответа", "Условная задержка (WAITFOR, SLEEP)", "Ручной/Burp, sqlmap"],
    ["Out-of-Band (OOB) (Blind)", "Внешнее сетевое взаимодействие", "Инициирование OOB-канала", "Burp Collaborator, sqlmap"],
  ];

  return (
    <ContentPageLayout
      title="Модуль IV: Атака на Серверные Уязвимости"
    >
      <H2><Database className="inline-block mr-2 h-6 w-6 text-primary" />A. SQL-инъекции (SQLi)</H2>
      <P>SQL-инъекции позволяют атакующему вмешиваться в запросы, которые приложение отправляет своей базе данных.</P>
      <H3>Обнаружение SQLi:</H3>
      <Ul items={[
        "На основе ошибок (Error-based)",
        "На основе логики (Boolean-based)",
        "На основе времени (Time-based)"
      ]} />
      <H3>Техники Эксплуатации:</H3>
      <Ul items={[
        "UNION-атаки",
        "Эксплуатация Blind SQLi",
        "Out-of-Band (OOB) SQLi"
      ]} />
      <H3>Автоматизация с sqlmap:</H3>
      <P>Рассмотрение основных опций sqlmap для обнаружения и эксплуатации SQLi.</P>
      <H3>Предотвращение:</H3>
      <P>Параметризованные запросы (Prepared Statements), валидация ввода, экранирование.</P>
      
      <H3>Таблица: Типы SQL-инъекций</H3>
      <SimpleTable headers={sqlInjectionTableHeaders} rows={sqlInjectionTableRows} />

      <H2><Terminal className="inline-block mr-2 h-6 w-6 text-primary" />B. Внедрение Команд ОС (OS Command Injection)</H2>
      <P>Эта уязвимость позволяет выполнять произвольные команды ОС на сервере.</P>
      <H3>Механизм Атаки:</H3>
      <P>Использование метасимволов командной оболочки (;, |, &&, `) для внедрения команд.</P>
      <H3>Слепое Внедрение Команд (Blind Command Injection):</H3>
      <Ul items={[
        "Временные Задержки (sleep)",
        "Перенаправление Вывода",
        "Out-of-Band (OOB) Взаимодействие (nslookup, curl)"
      ]} />
      <H3>Предотвращение:</H3>
      <P>Избегать вызова системных команд с пользовательским вводом, использовать встроенные функции, строгую валидацию, минимальные привилегии.</P>

      <H2><FileCode className="inline-block mr-2 h-6 w-6 text-primary" />C. Обход Пути и Включение Файлов (Path Traversal & LFI/RFI)</H2>
      <P>Позволяют читать файлы за пределами корневого каталога или включать содержимое локальных/удаленных файлов.</P>
      <Ul items={[
        "Обход Пути (Path Traversal): Манипуляция параметрами с ../.",
        "Локальное Включение Файлов (LFI): Включение локального файла. Чтение исходного кода, логов.",
        "Удаленное Включение Файлов (RFI): Включение файла с удаленного URL. Может привести к RCE."
      ]} />
      <H3>Техники Обхода Фильтров:</H3>
      <Ul items={[
        "Кодирование (URL-кодирование)",
        "Различные Представления ../",
        "Null Byte (%00) (в старых версиях PHP)",
        "Эксплуатация с PHP Wrappers (php://filter)"
      ]} />
      <H3>Предотвращение:</H3>
      <P>Строгая валидация, "белый список" файлов, хранение идентификаторов в БД, отключение allow_url_include/fopen.</P>

      <H2><UploadCloud className="inline-block mr-2 h-6 w-6 text-primary" />D. Уязвимости Загрузки Файлов</H2>
      <P>Небезопасная реализация функции загрузки файлов может привести к выполнению кода на сервере. (Дальнейшее содержание этой секции не предоставлено в исходном тексте для этой страницы, но она обозначена).</P>
      
    </ContentPageLayout>
  );
}
