
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const LinkStyle = "text-primary hover:text-primary/80 hover:underline";
const IconStyle = "mr-2 text-primary text-xl";
const SubIconStyle = "mr-2 text-primary text-lg"; // Slightly smaller for sub-items

export function SoftwareSection() {
  return (
    <section id="software" className="py-16 md:py-24 bg-background">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">
            <span className={IconStyle}>🔧</span>C. Программное Обеспечение
          </h2>
        </div>
        <div className="max-w-3xl mx-auto space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-xl font-semibold text-primary">
                <span className={IconStyle}>📀</span>Операционная система (ОС)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-2">
                <strong>Рекомендуется:</strong> Linux-дистрибутив типа <Link href="https://www.kali.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Kali Linux</Link> (с предустановленными инструментами). Другие (Debian, Ubuntu, Arch c <Link href="https://blackarch.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>BlackArch</Link>) тоже подходят. Важно владение командной строкой.
              </p>
              <p className="text-muted-foreground">
                <strong>Возможно:</strong> Windows или macOS (потребуется ручная установка инструментов, возможно <Link href="https://learn.microsoft.com/windows/wsl/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>WSL</Link>).
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-xl font-semibold text-primary">
                <span className={IconStyle}>📦</span>Виртуализация/Контейнеризация
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground mb-2">
                <strong><Link href="https://www.docker.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Docker</Link>:</strong> Крайне рекомендуется для запуска уязвимых приложений (OWASP Juice Shop, DVWA).
              </p>
              <p className="text-muted-foreground">
                <strong>ПО для виртуализации (Опционально):</strong> <Link href="https://www.vmware.com/products/workstation-player.html" target="_blank" rel="noopener noreferrer" className={LinkStyle}>VMware Workstation/Player</Link> или <Link href="https://www.virtualbox.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>VirtualBox</Link> для запуска ОС или VM.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-xl font-semibold text-primary">
                <span className={IconStyle}>🛠️</span>Основные Инструменты Безопасности
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>🔍</span><Link href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Burp Suite</Link>:</h4>
                <ul className="list-disc list-inside text-sm text-muted-foreground pl-7 mt-1 space-y-1">
                  <li>Community Edition (Бесплатная): Необходимый минимум. <Link href="https://portswigger.net/burp/communitydownload" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Скачать</Link>.</li>
                  <li>Professional Edition (Платная): Значительные преимущества, но не обязательна для основ.</li>
                  <li>Требует JRE 1.7+.</li>
                </ul>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>🛡️</span><Link href="https://www.zaproxy.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>OWASP ZAP (Zed Attack Proxy)</Link>:</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1">Бесплатная, open-source альтернатива Burp Suite.</p>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>📡</span><Link href="https://nmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Nmap</Link>:</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1">Сканер сетей и портов.</p>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>💉</span><Link href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>sqlmap</Link>:</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1">Автоматизация SQL-инъекций.</p>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>📁</span>Перебор директорий/файлов:</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1"><Link href="https://github.com/OJ/gobuster" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Gobuster</Link> / <Link href="https://tools.kali.org/information-gathering/dirb" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Dirb</Link> (может быть заменен Gobuster/ffuf).</p>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>🗝️</span><Link href="https://github.com/vanhauser-thc/thc-hydra" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Hydra (THC-Hydra)</Link>:</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1">Перебор паролей к сетевым службам.</p>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>📚</span>Словари (Wordlists):</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1">Рекомендуется <Link href="https://github.com/danielmiessler/SecLists" target="_blank" rel="noopener noreferrer" className={LinkStyle}>SecLists</Link>. Часто в /usr/share/wordlists в Kali.</p>
              </div>
              <div className="bg-muted p-4 rounded-lg border">
                <h4 className="font-medium text-foreground/90 flex items-center"><span className={SubIconStyle}>🌿</span><Link href="https://git-scm.com/" target="_blank" rel="noopener noreferrer" className={LinkStyle}>Git</Link>:</h4>
                <p className="text-sm text-muted-foreground pl-7 mt-1">Система контроля версий для клонирования репозиториев.</p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
