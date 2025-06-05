
'use client';

import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Play, StopCircle, Volume2 } from 'lucide-react'; // StopCircle is a good icon for stop

export function TextToSpeechDemo() {
  const [textToSpeak, setTextToSpeak] = React.useState<string>('Привет! Это демонстрация озвучки текста.');
  const [isSpeaking, setIsSpeaking] = React.useState<boolean>(false);
  const [availableVoices, setAvailableVoices] = React.useState<SpeechSynthesisVoice[]>([]);
  const [selectedVoiceURI, setSelectedVoiceURI] = React.useState<string | undefined>();
  const utteranceRef = React.useRef<SpeechSynthesisUtterance | null>(null);

  React.useEffect(() => {
    const synth = window.speechSynthesis;
    const loadVoices = () => {
      const voices = synth.getVoices().sort((a, b) => a.name.localeCompare(b.name));
      setAvailableVoices(voices);
      
      if (voices.length > 0) {
        const defaultRussianVoice = voices.find(voice => voice.lang.toLowerCase().startsWith('ru'));
        if (defaultRussianVoice) {
          setSelectedVoiceURI(defaultRussianVoice.voiceURI);
        } else {
          setSelectedVoiceURI(voices[0].voiceURI);
        }
      }
    };

    if (typeof window !== 'undefined' && synth) {
        // Voices are loaded asynchronously
        if (synth.onvoiceschanged !== undefined) {
          synth.onvoiceschanged = loadVoices;
        }
        loadVoices(); // Initial attempt
    }
    

    return () => {
      if (synth) {
        synth.cancel();
         if (synth.onvoiceschanged !== undefined) {
            synth.onvoiceschanged = null;
        }
      }
    };
  }, []);

  const handleSpeak = () => {
    if (!textToSpeak.trim()) {
      alert('Пожалуйста, введите текст для озвучки.');
      return;
    }
    if (typeof window !== 'undefined' && window.speechSynthesis) {
      const synth = window.speechSynthesis;
      // Cancel any ongoing speech before starting new
      synth.cancel();

      const newUtterance = new SpeechSynthesisUtterance(textToSpeak);
      utteranceRef.current = newUtterance;

      const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
      if (selectedVoice) {
        newUtterance.voice = selectedVoice;
        newUtterance.lang = selectedVoice.lang;
      } else {
        newUtterance.lang = 'ru-RU'; // Fallback language
      }
      
      newUtterance.onstart = () => setIsSpeaking(true);
      newUtterance.onend = () => setIsSpeaking(false);
      newUtterance.onerror = (event) => {
        console.error('Ошибка синтеза речи:', event.error, event);
        setIsSpeaking(false);
        if (event.error !== 'interrupted' && event.error !== 'canceled') {
          alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
        }
      };
      
      synth.speak(newUtterance);
    } else {
      alert('Ваш браузер не поддерживает Web Speech API.');
    }
  };

  const handleStop = () => {
    if (typeof window !== 'undefined' && window.speechSynthesis) {
      window.speechSynthesis.cancel();
      setIsSpeaking(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4 sm:p-6 md:p-8 space-y-6 bg-card text-card-foreground rounded-lg shadow-lg">
      <div className="text-center">
        <Volume2 className="mx-auto h-12 w-12 text-primary mb-4" />
        <h2 className="text-2xl font-semibold text-primary">Демонстрация Озвучки Текста</h2>
        <p className="text-muted-foreground mt-2">
          Введите текст, выберите голос и нажмите "Озвучить". Эта функция использует Web Speech API вашего браузера.
        </p>
      </div>
      <div className="space-y-2">
        <Label htmlFor="text-to-speak" className="font-medium">Текст для озвучки:</Label>
        <Textarea
          id="text-to-speak"
          value={textToSpeak}
          onChange={(e) => setTextToSpeak(e.target.value)}
          placeholder="Введите текст здесь..."
          rows={5}
          className="border-input focus:ring-primary focus:border-primary"
        />
      </div>
      {availableVoices.length > 0 && (
        <div className="space-y-2">
          <Label htmlFor="voice-select" className="font-medium">Выберите голос:</Label>
          <Select
            value={selectedVoiceURI}
            onValueChange={setSelectedVoiceURI}
          >
            <SelectTrigger id="voice-select" className="w-full border-input focus:ring-primary focus:border-primary">
              <SelectValue placeholder="Выберите голос..." />
            </SelectTrigger>
            <SelectContent>
              {availableVoices.map((voice) => (
                <SelectItem key={voice.voiceURI} value={voice.voiceURI}>
                  {voice.name} ({voice.lang}) {voice.default && "- По умолчанию"}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
      <div className="flex flex-col sm:flex-row gap-4">
        <Button onClick={handleSpeak} disabled={isSpeaking || !textToSpeak.trim()} className="w-full">
          <Play className="mr-2 h-4 w-4" /> Озвучить
        </Button>
        <Button onClick={handleStop} disabled={!isSpeaking} variant="destructive" className="w-full">
          <StopCircle className="mr-2 h-4 w-4" /> Стоп
        </Button>
      </div>
       {isSpeaking && <p className="text-sm text-center text-accent-foreground animate-pulse">Воспроизведение...</p>}
    </div>
  );
}
