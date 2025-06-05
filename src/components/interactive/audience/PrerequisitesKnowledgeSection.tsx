
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function PrerequisitesKnowledgeSection() {
  return (
    <section id="prerequisites" className="py-16 md:py-24">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-bold tracking-tight text-foreground">
              Предполагаемые знания
            </h2>
            <p className="mt-2 text-lg text-muted-foreground">
              Для комфортного освоения материала желательно иметь следующие базовые знания:
            </p>
          </div>
          <Card className="bg-card p-8 rounded-xl shadow-lg border">
            <CardContent className="pt-0">
              <ul className="list-disc list-inside space-y-3 text-foreground/80">
                <li>Принципы работы сетей: TCP/IP, DNS, HTTP.</li>
                <li>Веб-технологии: HTML, JavaScript.</li>
                <li>Опыт работы с операционными системами, в частности, с командной строкой Linux.</li>
                <li>Глубокие знания программирования не обязательны, но знакомство с Python или JavaScript будет полезным.</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
