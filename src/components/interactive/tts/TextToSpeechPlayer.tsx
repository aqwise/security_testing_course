
'use client';

import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Play, Pause, StopCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TextToSpeechPlayerProps {
  textToSpeak: string;
  className?: string;
}

export function TextToSpeechPlayer({ textToSpeak, className }: TextToSpeechPlayerProps) {
  const [isSpeaking, setIsSpeaking] = React.useState<boolean>(false);
  const [isPaused, setIsPaused] = React.useState<boolean>(false);
  const [availableVoices, setAvailableVoices] = React.useState<SpeechSynthesisVoice[]>([]);
  const [selectedVoiceURI, setSelectedVoiceURI] = React.useState<string | undefined>();
  const [playbackRate, setPlaybackRate] = React.useState<number>(1);
  const utteranceRef = React.useRef<SpeechSynthesisUtterance | null>(null);
  const synthRef = React.useRef<SpeechSynthesis | null>(null);

  React.useEffect(() => {
    if (typeof window !== 'undefined' && window.speechSynthesis) {
      synthRef.current = window.speechSynthesis;
      const loadVoices = () => {
        if (!synthRef.current) return;
        const voices = synthRef.current.getVoices().sort((a, b) => a.name.localeCompare(b.name));
        setAvailableVoices(voices);
        
        if (voices.length > 0) {
          const defaultRussianVoice = voices.find(voice => voice.lang.toLowerCase().startsWith('ru'));
          if (defaultRussianVoice) {
            setSelectedVoiceURI(defaultRussianVoice.voiceURI);
          } else {
            const firstVoice = voices.find(v => v.lang.toLowerCase().startsWith('en')) || voices[0];
            if (firstVoice) {
              setSelectedVoiceURI(firstVoice.voiceURI);
            }
          }
        }
      };

      if (synthRef.current.onvoiceschanged !== undefined) {
        synthRef.current.onvoiceschanged = loadVoices;
      }
      loadVoices(); 

      return () => {
        if (synthRef.current) {
          synthRef.current.cancel();
          if (synthRef.current.onvoiceschanged !== undefined) {
            synthRef.current.onvoiceschanged = null;
          }
        }
      };
    }
  }, []);

  const handlePlayPause = () => {
    if (!textToSpeak?.trim()) {
      alert('Нет текста для озвучки.');
      return;
    }
    if (!synthRef.current) {
      alert('Ваш браузер не поддерживает Web Speech API.');
      return;
    }

    if (isSpeaking) {
      if (isPaused) {
        synthRef.current.resume();
        setIsPaused(false);
      } else {
        synthRef.current.pause();
        setIsPaused(true);
      }
    } else {
      synthRef.current.cancel(); 
      
      const newUtterance = new SpeechSynthesisUtterance(textToSpeak);
      utteranceRef.current = newUtterance;

      const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
      if (selectedVoice) {
        newUtterance.voice = selectedVoice;
        newUtterance.lang = selectedVoice.lang;
      } else {
        newUtterance.lang = 'ru-RU'; 
      }
      
      newUtterance.rate = playbackRate;

      newUtterance.onstart = () => {
        setIsSpeaking(true);
        setIsPaused(false);
      };
      newUtterance.onend = () => {
        setIsSpeaking(false);
        setIsPaused(false);
      };
      newUtterance.onpause = () => {
        setIsPaused(true);
        setIsSpeaking(true); 
      };
      newUtterance.onresume = () => {
        setIsPaused(false);
        setIsSpeaking(true);
      };
      newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
        console.error('Ошибка синтеза речи:', { 
          errorCode: event.error, 
          message: event.error, 
          text: event.utterance?.text?.substring(0, 100) + (event.utterance?.text?.length > 100 ? '...' : ''),
          voiceName: event.utterance?.voice?.name,
          voiceLang: event.utterance?.voice?.lang,
          selectedVoiceURI: selectedVoiceURI,
          eventObject: event 
        });
        setIsSpeaking(false);
        setIsPaused(false);
        alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
      };
      
      synthRef.current.speak(newUtterance);
    }
  };

  const handleStop = () => {
    if (synthRef.current) {
      synthRef.current.cancel();
      setIsSpeaking(false);
      setIsPaused(false);
    }
  };

  const handleRateChange = (value: string) => {
    const rate = parseFloat(value);
    setPlaybackRate(rate);
    if (utteranceRef.current && synthRef.current && synthRef.current.speaking && !synthRef.current.paused) {
      synthRef.current.cancel(); 
      
      const newUtterance = new SpeechSynthesisUtterance(textToSpeak);
      utteranceRef.current = newUtterance;

      const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
      if (selectedVoice) {
        newUtterance.voice = selectedVoice;
        newUtterance.lang = selectedVoice.lang;
      } else {
        newUtterance.lang = 'ru-RU';
      }
      newUtterance.rate = rate; 

      newUtterance.onstart = () => {
        setIsSpeaking(true);
        setIsPaused(false);
      };
      newUtterance.onend = () => {
        setIsSpeaking(false);
        setIsPaused(false);
      };
      newUtterance.onpause = () => {
        setIsPaused(true);
        setIsSpeaking(true);
      };
      newUtterance.onresume = () => {
        setIsPaused(false);
        setIsSpeaking(true);
      };
      newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
        console.error('Ошибка синтеза речи при смене скорости:', { 
          errorCode: event.error, 
          message: event.error,
          text: event.utterance?.text?.substring(0, 100) + (event.utterance?.text?.length > 100 ? '...' : ''),
          voiceName: event.utterance?.voice?.name,
          eventObject: event 
        });
        setIsSpeaking(false);
        setIsPaused(false);
        alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
      };
      synthRef.current.speak(newUtterance);
    }
  };
  
  const rateOptions = [
    { value: '0.5', label: '0.5x' },
    { value: '0.75', label: '0.75x' },
    { value: '1', label: '1x (Норм.)' },
    { value: '1.25', label: '1.25x' },
    { value: '1.5', label: '1.5x' },
    { value: '1.75', label: '1.75x' },
    { value: '2', label: '2x' },
  ];

  return (
    <div className={cn("p-4 sm:p-6 space-y-4 bg-card text-card-foreground rounded-lg shadow-md border", className)}>
      <div className="flex flex-col sm:flex-row gap-4 items-center">
        <Button onClick={handlePlayPause} disabled={!textToSpeak?.trim()} className="w-full sm:w-auto" size="sm">
          {isSpeaking && !isPaused ? <Pause className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
          {isSpeaking && !isPaused ? 'Пауза' : isPaused ? 'Продолжить' : 'Озвучить'}
        </Button>
        <Button onClick={handleStop} disabled={!isSpeaking} variant="outline" className="w-full sm:w-auto" size="sm">
          <StopCircle className="mr-2 h-4 w-4" /> Стоп
        </Button>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {availableVoices.length > 0 && (
          <div className="space-y-1">
            <Label htmlFor="voice-select-player-page" className="text-xs font-medium">Голос:</Label>
            <Select
              value={selectedVoiceURI}
              onValueChange={setSelectedVoiceURI}
            >
              <SelectTrigger id="voice-select-player-page" className="w-full h-9 text-sm">
                <SelectValue placeholder="Выберите голос..." />
              </SelectTrigger>
              <SelectContent>
                {availableVoices.map((voice) => (
                  <SelectItem key={voice.voiceURI} value={voice.voiceURI} className="text-sm">
                    {voice.name} ({voice.lang}) {voice.default && "- По умолч."}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
        <div className="space-y-1">
          <Label htmlFor="rate-select-player-page" className="text-xs font-medium">Скорость:</Label>
           <Select
            value={playbackRate.toString()}
            onValueChange={handleRateChange}
          >
            <SelectTrigger id="rate-select-player-page" className="w-full h-9 text-sm">
              <SelectValue placeholder="Выберите скорость..." />
            </SelectTrigger>
            <SelectContent>
              {rateOptions.map((option) => (
                <SelectItem key={option.value} value={option.value} className="text-sm">
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
       {isSpeaking && <p className="text-xs text-center text-primary animate-pulse">Воспроизведение...</p>}
       {!textToSpeak?.trim() && availableVoices.length > 0 && (
        <p className="text-xs text-center text-muted-foreground">Нет текста для озвучки. Текст извлекается из содержимого статьи.</p>
       )}
    </div>
  );
}

  