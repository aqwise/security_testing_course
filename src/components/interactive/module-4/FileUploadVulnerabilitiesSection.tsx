
import Link from 'next/link';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

export function FileUploadVulnerabilitiesSection() {
  return (
    <section id="file-upload" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">D. Уязвимости Загрузки Файлов</h2>
          <p className="mt-2 max-w-3xl mx-auto text-lg text-muted-foreground">
            Небезопасная реализация функции загрузки файлов может привести к выполнению кода на сервере. <Link href="https://portswigger.net/web-security/file-upload" target="_blank" rel="noopener noreferrer" className={LinkStyle}>PortSwigger - File Upload Vulns</Link>.
          </p>
          <p className="mt-4 text-md text-muted-foreground/80 italic">
            (Примечание: Подробное содержание для этого раздела не было предоставлено в исходном тексте. Здесь будет добавлена информация о механизмах атаки, методах обхода фильтров (тип файла, content-type, расширение), техниках эксплуатации и предотвращения.)
          </p>
        </div>
        {/* Содержимое раздела будет добавлено здесь, когда будет предоставлено */}
      </div>
    </section>
  );
}
