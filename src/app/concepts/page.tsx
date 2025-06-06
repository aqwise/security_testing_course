import { ContentPageLayout, P, Ul, H3 } from '@/components/content/ContentPageLayout';
import { Lightbulb, Shield, ShieldCheck, Users } from 'lucide-react';
import Link from 'next/link';

export default function ConceptsPage() {
  return (
    <ContentPageLayout
      title="II. Уточнение Концепции 'Предотвращения'"
      subtitle="в Контексте Команд Red, Blue и Purple"
    >
      <P>
        В сфере кибербезопасности часто используются термины "Red Team", "Blue Team" и "Purple Team" для описания различных функций и подходов к обеспечению безопасности организации. Хотя конечной целью всех этих команд является повышение уровня защищенности и снижение рисков, их вклад в "предотвращение" (prevention) атак различается по своей природе. Важно понимать, что предотвращение – это комплексный результат, достигаемый совместными усилиями, а не исключительная задача какой-то одной команды.
      </P>

      <div className="space-y-8 mt-8">
        <div className="flex items-start p-4 border-l-4 border-red-500 bg-red-500/10 rounded-r-md">
          <Users className="h-8 w-8 text-red-500 mr-4 mt-1 flex-shrink-0" />
          <div>
            <H3>Red Team (Атакующая сторона / Offensive Operations):</H3>
            <P>
              <strong>Функция:</strong> Основная задача Red Team – имитировать действия реальных злоумышленников для выявления уязвимостей в системах защиты организации, тестирования эффективности средств обнаружения и реагирования, а также оценки общей готовности к атакам.28 Они используют методы этичного хакинга, проводят тесты на проникновение и эмулируют тактики, техники и процедуры (TTPs) известных атакующих групп.
            </P>
            <P>
              <strong>Вклад в предотвращение:</strong> Red Team напрямую не предотвращает атаки во время своих операций; их цель – успешно их провести в контролируемой среде. Однако, их деятельность имеет решающее значение для обеспечения предотвращения. Обнаруживая и эксплуатируя уязвимости до того, как это сделают реальные злоумышленники, Red Team предоставляет критически важную информацию. Эти данные позволяют организации принять превентивные меры: установить патчи, исправить ошибки конфигурации, внести архитектурные изменения, внедрить или усилить средства контроля безопасности. Таким образом, Red Team выявляет, что необходимо предотвращать.
            </P>
          </div>
        </div>

        <div className="flex items-start p-4 border-l-4 border-blue-500 bg-blue-500/10 rounded-r-md">
          <Shield className="h-8 w-8 text-blue-500 mr-4 mt-1 flex-shrink-0" />
          <div>
            <H3>Blue Team (Защищающая сторона / Defensive Operations):</H3>
            <P>
              <strong>Функция:</strong> Blue Team отвечает за проектирование, внедрение, эксплуатацию и мониторинг средств защиты организации.28 В их задачи входит настройка и управление межсетевыми экранами (Firewalls), системами обнаружения и предотвращения вторжений (IDS/IPS), системами управления информацией и событиями безопасности (SIEM), средствами защиты конечных точек (Endpoint Protection), системами контроля доступа, а также реагирование на инциденты безопасности.
            </P>
            <P>
              <strong>Вклад в предотвращение:</strong> Blue Team находится на переднем крае предотвращения атак. Именно они внедряют и поддерживают технические и административные меры, направленные на блокирование вредоносной активности. Кроме того, они отвечают за обнаружение атак, которым удалось обойти превентивные меры, и за реагирование на них. Анализ инцидентов позволяет Blue Team извлекать уроки и улучшать существующие стратегии и средства предотвращения. Они реализуют как предотвращать атаки.
            </P>
          </div>
        </div>
        
        <div className="flex items-start p-4 border-l-4 border-purple-500 bg-purple-500/10 rounded-r-md">
          <ShieldCheck className="h-8 w-8 text-purple-500 mr-4 mt-1 flex-shrink-0" />
          <div>
            <H3>Purple Team (Коллаборация):</H3>
            <P>
              <strong>Функция:</strong> Purple Team – это не столько отдельная команда, сколько функциональный подход, направленный на максимальное усиление взаимодействия и обмена знаниями между Red Team и Blue Team.30 Цель – оптимизировать защитные возможности организации. Учения Purple Team часто включают выполнение Red Team конкретных сценариев атак, в то время как Blue Team пытается их обнаружить и отразить, при этом обе стороны поддерживают открытую коммуникацию и обмениваются информацией в режиме, близком к реальному времени.
            </P>
            <P>
              <strong>Вклад в предотвращение:</strong> Purple Teaming напрямую способствует улучшению предотвращения за счет оптимизации всего цикла безопасности. Улучшая способность Blue Team обнаруживать и реагировать на техники Red Team, этот подход проверяет и повышает эффективность существующих превентивных и детективных контролей. Он гарантирует, что выводы Red Team эффективно преобразуются в конкретные, действенные улучшения для Blue Team, что ведет к созданию более надежной и эффективной общей стратегии предотвращения. Purple Team оптимизирует цикл предотвращения и обнаружения.
            </P>
          </div>
        </div>
      </div>

      <div className="mt-10 p-6 bg-secondary/50 rounded-lg shadow">
        <div className="flex items-center text-primary mb-3">
          <Lightbulb className="h-6 w-6 mr-2" />
          <h4 className="text-xl font-semibold">Заключение</h4>
        </div>
        <P>
          Предотвращение кибератак – это не статическое состояние, а непрерывный процесс, являющийся результатом синергии между атакующими и защитными функциями. Red Team выявляет слабые места, Blue Team строит и поддерживает защиту, а Purple Team обеспечивает их эффективное взаимодействие, постоянно совершенствуя общую стратегию предотвращения угроз.
        </P>
      </div>
    </ContentPageLayout>
  );
}
