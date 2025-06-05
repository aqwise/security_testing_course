import { TextToSpeechDemo } from '@/components/interactive/tts/TextToSpeechDemo';
import { Separator } from '@/components/ui/separator';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export default function TTSDemoPage() {
  return (
    <div className="container mx-auto py-8 px-4 md:px-6 lg:px-8">
      <TextToSpeechDemo />
      <Separator className="my-12" />
      <Card className="mt-8">
        <CardHeader>
          <CardTitle>О технологии</CardTitle>
          <CardDescription>Информация о механизме озвучки текста в этом примере.</CardDescription>
        </CardHeader>
        <CardContent className="text-muted-foreground space-y-2">
          <p>Этот пример демонстрирует использование Web Speech API, встроенного в ваш браузер, для синтеза речи. Он работает полностью на стороне клиента.</p>
          <p>Модель Gemini или другие серверные AI-модели не используются для генерации аудио в данной демонстрации.</p>
          <p>Доступность голосов и их качество зависят от операционной системы и браузера пользователя.</p>
        </CardContent>
      </Card>
    </div>
  );
}
