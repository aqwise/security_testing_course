'use client';

import * as React from 'react';
import { ContentPageLayout, P, H2, H3 } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, Shield, CheckCircle2, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

const quizQuestions = [
  { 
    question: "Что такое инъекция кода?", 
    answers: [
      "Метод защиты приложения", 
      "Уязвимость, позволяющая внедрять и выполнять непредусмотренный код",
      "Способ оптимизации запросов",
      "Техника кеширования данных"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Какой тип инъекции позволяет выполнить JavaScript код в браузере пользователя?", 
    answers: ["SQL Injection", "XSS (Cross-Site Scripting)", "Command Injection", "XXE"], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Что является основной причиной возникновения инъекций?", 
    answers: [
      "Медленная работа сервера",
      "Отсутствие валидации и фильтрации пользовательского ввода",
      "Использование старых браузеров",
      "Плохая производительность базы данных"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Какой тип инъекции является наиболее опасным для базы данных?", 
    answers: ["HTML Injection", "XSS", "SQL Injection", "CSS Injection"], 
    correctAnswerIndex: 2 
  },
  { 
    question: "Что может сделать злоумышленник при успешной Command Injection?", 
    answers: [
      "Изменить цвет сайта",
      "Выполнить системные команды на сервере",
      "Замедлить работу браузера",
      "Отключить JavaScript"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Что такое XXE атака?", 
    answers: [
      "Атака на CSS стили",
      "Внедрение внешней XML сущности",
      "Кража cookies",
      "DDoS атака"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Какой первый шаг в защите от инъекций?", 
    answers: [
      "Использование HTTPS",
      "Валидация и санитизация пользовательского ввода",
      "Установка антивируса",
      "Использование CDN"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Что означает 'белый список' в контексте защиты от инъекций?", 
    answers: [
      "Список заблокированных IP адресов",
      "Список разрешенных значений для ввода",
      "Список администраторов",
      "Список уязвимостей"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Почему важно проверять закодированный ввод (например, URL-encoding)?", 
    answers: [
      "Для улучшения производительности",
      "Злоумышленники могут обойти фильтры используя кодирование",
      "Это требование стандарта",
      "Для совместимости с браузерами"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Что может указывать на возможную SQL инъекцию?", 
    answers: [
      "Быстрая загрузка страницы",
      "Ошибка базы данных в ответе сервера",
      "Красивый дизайн сайта",
      "Наличие SSL сертификата"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Какой HTTP статус код обычно возвращается при ошибке сервера?", 
    answers: ["200", "404", "500", "301"], 
    correctAnswerIndex: 2 
  },
  { 
    question: "Что НЕ является признаком безопасного кода?", 
    answers: [
      "Использование параметризованных запросов",
      "Прямая конкатенация пользовательского ввода в SQL запрос",
      "Валидация входных данных",
      "Использование prepared statements"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Какую информацию может похитить XSS атака?", 
    answers: [
      "Только email пользователя",
      "Cookies, токены сессии, личные данные",
      "Только пароль",
      "Номер телефона"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Что означает санитизация данных?", 
    answers: [
      "Удаление всех данных",
      "Очистка данных от потенциально опасных символов и кода",
      "Шифрование данных",
      "Архивация данных"
    ], 
    correctAnswerIndex: 1 
  },
  { 
    question: "Почему обновление кода не гарантирует исправление уязвимостей?", 
    answers: [
      "Обновления всегда безопасны",
      "Новый код может содержать новые баги и уязвимости",
      "Обновления не меняют код",
      "Это миф"
    ], 
    correctAnswerIndex: 1 
  }
];

interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
  onAnswer: (questionIndex: number, answerIndex: number) => void;
  selectedAnswer: number | null;
  showResult: boolean;
  questionIndex: number;
}

function QuizItem({ question, answers, correctAnswerIndex, onAnswer, selectedAnswer, showResult, questionIndex }: QuizItemProps) {
  return (
    <Card className="mb-4">
      <CardHeader>
        <CardTitle className="text-lg">{question}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {answers.map((answer, index) => {
            const isSelected = selectedAnswer === index;
            const isCorrect = index === correctAnswerIndex;
            const showCorrect = showResult && isCorrect;
            const showIncorrect = showResult && isSelected && !isCorrect;

            return (
              <button
                key={index}
                onClick={() => onAnswer(questionIndex, index)}
                disabled={showResult}
                className={cn(
                  "w-full text-left p-3 rounded-lg border transition-colors",
                  isSelected && !showResult && "bg-primary/10 border-primary",
                  showCorrect && "bg-green-100 border-green-500 dark:bg-green-900/20",
                  showIncorrect && "bg-red-100 border-red-500 dark:bg-red-900/20",
                  !showResult && "hover:bg-muted"
                )}
              >
                <div className="flex items-center justify-between">
                  <span>{answer}</span>
                  {showResult && (
                    <span>
                      {isCorrect ? (
                        <CheckCircle2 className="h-5 w-5 text-green-600" />
                      ) : isSelected ? (
                        <XCircle className="h-5 w-5 text-red-600" />
                      ) : null}
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

export default function InjectionLesson1Page() {
  const [quizAnswers, setQuizAnswers] = React.useState<(number | null)[]>(new Array(quizQuestions.length).fill(null));
  const [showResults, setShowResults] = React.useState<boolean[]>(new Array(quizQuestions.length).fill(false));

  const handleAnswer = (questionIndex: number, answerIndex: number) => {
    const newAnswers = [...quizAnswers];
    newAnswers[questionIndex] = answerIndex;
    setQuizAnswers(newAnswers);

    const newShowResults = [...showResults];
    newShowResults[questionIndex] = true;
    setShowResults(newShowResults);
  };

  const correctAnswersCount = quizAnswers.filter((answer, index) => answer === quizQuestions[index].correctAnswerIndex).length;
  const totalQuestions = quizQuestions.length;

  return (
    <ContentPageLayout title="Урок 1: Введение в инъекции">
      <div className="space-y-8">
        <section>
          <P>
            Самый большой и обьемный раздел. Мы затронем и узнаем о разных видах иньекций – <strong>SQL</strong>, <strong>Command</strong>, <strong>XSS</strong>, <strong>HTML</strong> и затронем тему <strong>XXE</strong>.
          </P>
        </section>

        <section>
          <H2>Что такое инъекции кода?</H2>
          <P>
            <strong>Инъекции кода</strong> - уязвимости, связанные, например, с внедрением <strong>SQL</strong>, <strong>NoSQL</strong>, <strong>OS</strong> и <strong>LDAP</strong> и др., 
            возникают, когда непроверенные данные отправляются интерпретатору в составе команды или запроса. 
            Вредоносные данные могут заставить интерпретатор выполнить непредусмотренные команды или обратиться к данным 
            без прохождения соответствующей авторизации.
          </P>
          <P>
            Инъекции кода всегда являлись одной из самых значимых и распространенных уязвимостей Web-приложений, 
            а именно мы выучим теорию, узнаем виды каждой из них, почему появляются и как обнаруживать следующие:
          </P>
        </section>

        <section>
          <H2>Типы инъекций, которые мы будем изучать</H2>
          
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-primary">1.</span>
                  Cross-Site Scripting (XSS)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда приложение принимает и выполняет вредоносный <strong>JavaScript</strong> код. 
                  Например, мы можем украсть сессию пользователя или изменить его банковский счет, 
                  похитить сенситивную информацию и т.д.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-primary">2.</span>
                  HTML Injection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда приложение принимает и интерпретирует теги HTML и мы можем изменить вид страниц 
                  или сделать вредоносную ссылку и т.d. Или просто залить картинку с определенным контентом 
                  и нанести вред репутации компании.
                </P>
              </CardContent>
            </Card>

            <Card className="border-red-200 bg-red-50 dark:bg-red-950/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-red-600">3.</span>
                  <AlertTriangle className="h-6 w-6 text-red-600" />
                  SQL Injection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда приложение принимает и выполняет команды напрямую к базе данных. 
                  <strong className="text-red-600"> Один из самых опасных видов уязвимостей.</strong> 
                  Злоумышленник может читать, записывать, вносить изменения или даже удалить данные.
                </P>
              </CardContent>
            </Card>

            <Card className="border-orange-200 bg-orange-50 dark:bg-orange-950/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-orange-600">4.</span>
                  Command Injection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда серверные команды (например для <strong>Linux – pwd/ls</strong> или <strong>Windows – dir/type</strong>) 
                  выполняются непосредственно из-под браузера или API. 
                  <strong className="text-orange-600"> Урон от такого колоссальный</strong>, т.к. имеем доступ напрямую к серверу.
                </P>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <span className="text-2xl font-bold text-primary">5.</span>
                  Внедрение внешней сущности XML (XXE)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Это уязвимость веб-безопасности, которая позволяет злоумышленнику вмешаться в обработку XML-данных приложением. 
                  Она часто позволяет злоумышленнику просматривать файлы в файловой системе сервера приложений и взаимодействовать 
                  с любыми внутренними или внешними системами. Простой пример: чтение <code>/etc/</code> каталога.
                </P>
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>Основные принципы защиты приложения от подобных уязвимостей</H2>
          <P>
            Безопасность программы часто связывается именно с ее безопасным поведением. Оно включает в себя, например 
            аутентификацию пользователя, проверку прав его доступа, фильтрацию входных данных. Но это само собой далеко 
            не полный список. Далее будет перечислен небольшой список где отмечены некоторые полезные проверки, но помните что 
            это далеко не все и для каждой уязвимости и иногда просто может быть уникальным.
          </P>
        </section>

        <section>
          <H2>Советы по проверке защиты</H2>
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="h-5 w-5 text-primary flex-shrink-0" />
                  1. Проверяем все данные поступающие от пользователя
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Не работать с данными поступающими от пользователя без обработки.
                </P>
                <div className="mt-3 p-3 bg-primary/10 rounded-lg border border-primary/20">
                  <p className="text-sm font-semibold text-primary">
                    ✓ Проверяем все данные поступающие от пользователя.
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="h-5 w-5 text-primary flex-shrink-0" />
                  2. Используйте белые списки и избегайте прямых вставок
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Не помещать в запрос управляющие структуры и идентификаторы, введенные пользователем, 
                  а заранее прописывать в скрипте список возможных вариантов, и выбирать только из них.
                </P>
                <div className="mt-3 p-3 bg-primary/10 rounded-lg border border-primary/20">
                  <p className="text-sm font-semibold text-primary">
                    ✓ Проверяем что нет возможности вводить спецсимволы, куски кода и тп вещи.
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="h-5 w-5 text-primary flex-shrink-0" />
                  3. Тестируйте различные типы ввода
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Когда вы тестируете сайт, проверьте, как он обрабатывает разные типы ввода, 
                  включая простой текст и закодированный текст.
                </P>
                <div className="mt-3 p-3 bg-primary/10 rounded-lg border border-primary/20">
                  <p className="text-sm font-semibold text-primary">
                    ✓ Замечайте случаи, когда сайты принимают URI-закодированные значения, такие, как %2F и рендерят их декодированные значения, в этом случае /.
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="h-5 w-5 text-primary flex-shrink-0" />
                  4. Проверяйте код после обновлений
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Одно лишь то, что код был обновлен, не значит, что что-то было исправлено.
                </P>
                <div className="mt-3 p-3 bg-primary/10 rounded-lg border border-primary/20">
                  <p className="text-sm font-semibold text-primary">
                    ✓ Проверяйте. Когда выкатывают обновление, это так же значит, что новый код может содержать баги.
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="h-5 w-5 text-primary flex-shrink-0" />
                  5. Продолжайте исследование при подозрениях
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Кроме того, если вы чувствуете, что что-то не так, продолжайте копать!
                </P>
                <div className="mt-3 p-3 bg-primary/10 rounded-lg border border-primary/20">
                  <p className="text-sm font-semibold text-primary">
                    ✓ Отмечайте риски, чтобы позже вернуться к ним с новыми силами и знаниями. 
                    Например статус ответа сервера или само тело ответа могут быть отличной подсказкой в поиске, но об этом позже.
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="h-5 w-5 text-primary flex-shrink-0" />
                  6. Внимательность к URL параметрам
                </CardTitle>
              </CardHeader>
              <CardContent>
                <P>
                  Будьте внимательны к передаваемым параметрам URL, которые отображаются в виде содержимого сайта. 
                  Они могут содержать возможные точки атаки, позволяющие хакерам обманывать свои жертвы и заставлять 
                  их выполнять вредные действия.
                </P>
                <div className="mt-3 p-3 bg-primary/10 rounded-lg border border-primary/20">
                  <p className="text-sm font-semibold text-primary">
                    ✓ Будьте внимательны к возможностям манипулирования параметрами URL и тому, как они отображаются на сайте.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </section>

        <section>
          <H2>Проверка знаний</H2>
          <P>Пройдите тест, чтобы проверить понимание материала:</P>
          
          <div className="mb-6">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-medium">
                Прогресс: {quizAnswers.filter(a => a !== null).length} из {totalQuestions}
              </span>
              {quizAnswers.filter(a => a !== null).length === totalQuestions && (
                <span className="text-sm font-medium">
                  Правильных ответов: {correctAnswersCount} из {totalQuestions} 
                  ({Math.round((correctAnswersCount / totalQuestions) * 100)}%)
                </span>
              )}
            </div>
          </div>

          {quizQuestions.map((quiz, index) => (
            <QuizItem
              key={index}
              questionIndex={index}
              question={`${index + 1}. ${quiz.question}`}
              answers={quiz.answers}
              correctAnswerIndex={quiz.correctAnswerIndex}
              onAnswer={handleAnswer}
              selectedAnswer={quizAnswers[index]}
              showResult={showResults[index]}
            />
          ))}
        </section>

        <section>
          <H2>Заключение</H2>
          <P>
            В этом уроке мы изучили основы инъекций кода, рассмотрели основные типы уязвимостей и принципы защиты. 
            В следующих уроках мы детально разберем каждый тип инъекций с практическими примерами и лабораторными работами.
          </P>
          <P>
            Помните: безопасность - это непрерывный процесс, требующий постоянного обучения и внимания к деталям.
          </P>
        </section>
      </div>
    </ContentPageLayout>
  );
}
