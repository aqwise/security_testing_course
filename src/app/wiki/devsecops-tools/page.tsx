import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';
import { Microscope, ShieldCheck, KeyRound, Network, Blend, Container, Bug, BrainCircuit, Youtube } from 'lucide-react';
import type { ReactNode } from 'react';

interface Tool {
    name: string;
    description: string;
    links: { url: string; text: string; note?: string }[];
    note?: string;
}

interface Section {
    id: string;
    title: string;
    icon: ReactNode;
    tools: Tool[];
}

const sections: Section[] = [
    {
        id: "sast",
        icon: <Microscope className="h-8 w-8 text-primary" />,
        title: "1. Статический анализ (SAST)",
        tools: [
            {
                name: "CodeQL",
                description: "Мощный семантический анализатор кода от GitHub.",
                links: [
                    { url: "https://security.github.com/code-scanning/codeql/", text: "Официальный сайт" },
                    { url: "https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-codeql", text: "Документация" },
                    { url: "https://github.com/github/codeql", text: "Репозиторий (запросы)" }
                ]
            },
            {
                name: "Semgrep",
                description: "Быстрый и гибкий open-source анализатор для множества языков.",
                links: [
                    { url: "https://semgrep.dev/", text: "Официальный сайт" },
                    { url: "https://semgrep.dev/docs/", text: "Документация" },
                    { url: "https://github.com/returntocorp/semgrep", text: "Репозиторий" }
                ]
            },
            {
                name: "Bandit",
                description: "Инструмент для поиска проблем безопасности в коде на Python.",
                links: [
                    { url: "https://github.com/PyCQA/bandit", text: "Репозиторий (PyCQA)" },
                    { url: "https://bandit.readthedocs.io/en/latest/", text: "Документация" }
                ]
            },
            {
                name: "MobSF",
                description: "Автоматизированный инструмент для анализа безопасности мобильных приложений (Android/iOS).",
                links: [
                    { url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF", text: "Официальный сайт/Репозиторий" },
                    { url: "https://mobsf.github.io/docs/#/", text: "Документация" }
                ]
            },
            {
                name: "DRAN",
                description: "Фреймворк для написания собственных проверок на основе потоков данных.",
                links: [],
                note: "Примечание: Прямой официальный источник найти сложно. Для кастомных правил часто используют движки CodeQL или Semgrep."
            }
        ]
    },
    {
        id: "sca",
        icon: <ShieldCheck className="h-8 w-8 text-primary" />,
        title: "2. Анализ состава ПО (SCA)",
        tools: [
            {
                name: "SBOM",
                description: "Стандарт для перечня компонентов ПО (Software Bill of Materials).",
                links: [
                    { url: "https://www.cisa.gov/sbom", text: "Информация от CISA" },
                    { url: "https://cyclonedx.org/", text: "Стандарт CycloneDX" },
                    { url: "https://spdx.dev/", text: "Стандарт SPDX" }
                ]
            },
            {
                name: "Dependabot",
                description: "Инструмент GitHub для автоматического обнаружения и обновления уязвимых зависимостей.",
                links: [{ url: "https://github.com/dependabot", text: "Официальная страница" }]
            },
            {
                name: "PBOM",
                description: "Концепция отслеживания компонентов на всех этапах CI/CD (Pipeline Bill of Materials).",
                links: []
            }
        ]
    },
    {
        id: "secret-scanning",
        icon: <KeyRound className="h-8 w-8 text-primary" />,
        title: "3. Поиск секретов",
        tools: [
            {
                name: "GitHub Secret Scanning",
                description: "Встроенная функция GitHub для поиска секретов в репозиториях.",
                links: [{ url: "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning", text: "Официальная страница" }]
            },
            {
                name: "Gitleaks",
                description: "Популярный open-source инструмент для поиска секретов в Git-репозиториях.",
                links: [{ url: "https://github.com/gitleaks/gitleaks", text: "Репозиторий" }]
            },
            {
                name: "TruffleHog",
                description: "Ищет секреты в истории коммитов, проверяя их на валидность.",
                links: [{ url: "https://github.com/trufflesecurity/trufflehog", text: "Репозиторий" }]
            }
        ]
    },
    {
        id: "dast",
        icon: <Network className="h-8 w-8 text-primary" />,
        title: "4. Динамический анализ (DAST)",
        tools: [
            {
                name: "OWASP ZAP",
                description: "Популярный open-source DAST-сканер (Zed Attack Proxy).",
                links: [
                    { url: "https://www.zaproxy.org/", text: "Официальный сайт" },
                    { url: "https://www.zaproxy.org/documentation/", text: "Документация" }
                ]
            },
            {
                name: "Swagger/OpenAPI для DAST",
                description: "Использование спецификаций API для автоматизации и повышения полноты DAST-сканирования.",
                links: [{ url: "https://www.openapis.org/", text: "Спецификация OpenAPI" }]
            }
        ]
    },
    {
        id: "iast",
        icon: <Blend className="h-8 w-8 text-primary" />,
        title: "5. Интерактивный анализ (IAST)",
        tools: [
            {
                name: "Концепция IAST",
                description: "Гибридное тестирование \"серого ящика\", комбинирующее SAST и DAST с помощью инструментации кода.",
                links: [{ url: "https://owasp.org/www-community/Source_Code_Analysis_Tools#tab-Interactive_Application_Security_Testing_(IAST)", text: "Статья OWASP" }],
                note: "Примечание: Многие IAST-решения являются коммерческими (Contrast Security, Veracode, Synopsys)."
            }
        ]
    },
    {
        id: "container-security",
        icon: <Container className="h-8 w-8 text-primary" />,
        title: "6. Безопасность контейнеров",
        tools: [
            {
                name: "Trivy",
                description: "Универсальный сканер уязвимостей для образов контейнеров, файловых систем и Git-репозиториев.",
                links: [
                    { url: "https://github.com/aquasecurity/trivy", text: "Репозиторий" },
                    { url: "https://aquasecurity.github.io/trivy/", text: "Документация" }
                ]
            },
            {
                name: "Docker Bench for Security",
                description: "Скрипт для проверки хоста Docker на соответствие лучшим практикам безопасности.",
                links: [{ url: "https://github.com/docker/docker-bench-security", text: "Репозиторий" }]
            }
        ]
    },
    {
        id: "fuzzing",
        icon: <Bug className="h-8 w-8 text-primary" />,
        title: "7. Фазинг (Fuzzing)",
        tools: [
            {
                name: "OSS-Fuzz",
                description: "Платформа от Google для непрерывного фазинга open-source проектов.",
                links: [{ url: "https://github.com/google/oss-fuzz", text: "Репозиторий" }]
            },
            {
                name: "AFL (American Fuzzy Lop)",
                description: "Один из самых известных и эффективных фаззеров.",
                links: [
                    { url: "https://github.com/AFLplusplus/AFLplusplus", text: "Актуальный форк (AFL++)" },
                    { url: "https://lcamtuf.coredump.cx/afl/", text: "Оригинальный AFL (не поддерживается)", note: "text-slate-500" }
                ]
            }
        ]
    },
    {
        id: "ai-ml",
        icon: <BrainCircuit className="h-8 w-8 text-primary" />,
        title: "8. AI/ML в безопасности",
        tools: [
            {
                name: "MITRE ATLAS",
                description: "База знаний о тактиках и техниках атак на системы машинного обучения.",
                links: [{ url: "https://atlas.mitre.org/", text: "Официальный сайт" }]
            },
            {
                name: "Потенциал LLM",
                description: "Обсуждение использования моделей типа ChatGPT для анализа и генерации безопасного кода.",
                links: [{ url: "https://github.blog/2022-09-14-github-copilot-and-code-security-a-research-study/", text: "Пример исследования от GitHub" }]
            }
        ]
    }
];

export default function DevSecOpsToolsPage() {
    const linkClasses = "block text-primary hover:text-primary/80 transition-colors duration-200";

    return (
        <div className="container mx-auto px-4 py-8 md:py-12">
            <header className="text-center mb-10 md:mb-16">
                <h1 className="text-4xl md:text-5xl font-bold text-foreground">SafeCode 2023 Meetup #2: Обзорная прогулка по инструментам AppSec</h1>
                <p className="mt-4 text-lg text-muted-foreground">Систематизированный обзор инструментов и методологий безопасной разработки, основанный на материалах митапа.</p>
                <div className="mt-4 flex justify-center items-center gap-2">
                    <Youtube className="h-5 w-5 text-red-500" />
                    <Link href="https://www.youtube.com/watch?v=_B8AxFKV2vk&t=3708s" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                        Смотреть оригинальное видео
                    </Link>
                </div>
            </header>

            <main className="space-y-12">
                {sections.map(section => (
                    <section key={section.id} id={section.id}>
                        <h2 className="text-3xl font-bold text-foreground border-b-2 border-border pb-3 mb-8 flex items-center gap-3">
                            {section.icon}
                            {section.title}
                        </h2>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {section.tools.map(tool => (
                                <Card key={tool.name} className="bg-card flex flex-col hover:shadow-lg hover:-translate-y-1 transition-all duration-200">
                                    <CardHeader>
                                        <CardTitle>{tool.name}</CardTitle>
                                    </CardHeader>
                                    <CardContent className="flex-grow flex flex-col">
                                        <p className="text-muted-foreground mb-4 flex-grow">{tool.description}</p>
                                        <div className="mt-auto space-y-2">
                                            {tool.links.map(link => (
                                                <Link key={link.url} href={link.url} target="_blank" rel="noopener noreferrer" className={`${linkClasses} ${link.note || ''}`}>
                                                    {link.text}
                                                </Link>
                                            ))}
                                        </div>
                                        {tool.note && <p className="text-xs text-muted-foreground/70 italic mt-auto pt-4">{tool.note}</p>}
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    </section>
                ))}
            </main>

            <footer className="text-center text-muted-foreground/80 mt-16 pt-8 border-t border-border">
                <p>&copy; 2024 Обзор инструментов DevSecOps. Информация собрана и систематизирована.</p>
            </footer>
        </div>
    );
}
