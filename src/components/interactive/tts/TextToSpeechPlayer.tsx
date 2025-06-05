
'use client';

import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Play, Pause, StopCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TextToSpeechPlayerProps {
  initialTextToSpeak: string;
  className?: string;
}

interface TextToSpeechPlayerRef {
  play: (text: string) => void;
  stop: () => void;
}

export const TextToSpeechPlayer = React.forwardRef<TextToSpeechPlayerRef, TextToSpeechPlayerProps>(
  ({ initialTextToSpeak, className }, ref) => {
    const [isSpeaking, setIsSpeaking] = React.useState<boolean>(false);
    const [isPaused, setIsPaused] = React.useState<boolean>(false);
    const [availableVoices, setAvailableVoices] = React.useState<SpeechSynthesisVoice[]>([]);
    const [selectedVoiceURI, setSelectedVoiceURI] = React.useState<string | undefined>();
    const [playbackRate, setPlaybackRate] = React.useState<number>(1);
    
    const utteranceRef = React.useRef<SpeechSynthesisUtterance | null>(null);
    const synthRef = React.useRef<SpeechSynthesis | null>(null);
    const currentTextToSpeakRef = React.useRef<string>(initialTextToSpeak);

    React.useEffect(() => {
      currentTextToSpeakRef.current = initialTextToSpeak;
    }, [initialTextToSpeak]);

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
            console.log("TTS Player: Unmounting, cancelling speech.");
            synthRef.current.cancel();
            if (synthRef.current.onvoiceschanged !== undefined) {
              synthRef.current.onvoiceschanged = null;
            }
          }
        };
      }
    }, []);

    const commonOnErrorHandler = (event: SpeechSynthesisErrorEvent, context: string = "general") => {
      if (event.error === 'interrupted') {
        console.warn(`Синтез речи прерван (контекст: ${context}, ожидаемо): ${event.error}`);
        // setIsSpeaking(false); // Should be handled by onend or explicit stop
        // setIsPaused(false);
        return; 
      }

      console.error(`Ошибка синтеза речи (контекст: ${context}). Код ошибки: ${event.error}`);
      console.error('Дополнительные детали ошибки:', {
        charIndex: event.charIndex,
        elapsedTime: event.elapsedTime,
        textSample: event.utterance?.text?.substring(event.charIndex > 10 ? event.charIndex - 10 : 0, event.charIndex + 40),
        voiceName: event.utterance?.voice?.name,
        voiceLang: event.utterance?.voice?.lang,
        selectedVoiceURI: selectedVoiceURI,
      });
      setIsSpeaking(false);
      setIsPaused(false);
      alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
    };

    const _speakText = (text: string) => {
      if (!text.trim()) {
        console.log("TTS Player: Attempted to speak empty text.");
        alert('Нет текста для озвучки.');
        return;
      }
      if (!synthRef.current) {
        alert('Ваш браузер не поддерживает Web Speech API.');
        return;
      }

      console.log("TTS Player: _speakText called with:", text.substring(0, 50) + "...");
      
      // Cancel any ongoing speech before starting new
      synthRef.current.cancel(); 
      // Allow time for cancel to propagate, this is a common workaround
      setTimeout(() => {
        if (!synthRef.current) return; // Check again after timeout

        const newUtterance = new SpeechSynthesisUtterance(text);
        utteranceRef.current = newUtterance;

        const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
        if (selectedVoice) {
          newUtterance.voice = selectedVoice;
          newUtterance.lang = selectedVoice.lang;
          console.log("TTS Player: Using voice:", selectedVoice.name);
        } else {
          newUtterance.lang = 'ru-RU'; 
          console.log("TTS Player: Using fallback language ru-RU");
        }
        
        newUtterance.rate = playbackRate;

        newUtterance.onstart = () => {
          console.log("TTS Player: Speech started.");
          setIsSpeaking(true);
          setIsPaused(false);
        };
        newUtterance.onend = () => {
          console.log("TTS Player: Speech ended.");
          setIsSpeaking(false);
          setIsPaused(false);
          utteranceRef.current = null; 
        };
        newUtterance.onpause = () => {
          console.log("TTS Player: Speech paused.");
          setIsPaused(true);
          // isSpeaking remains true
        };
        newUtterance.onresume = () => {
          console.log("TTS Player: Speech resumed.");
          setIsPaused(false);
          // isSpeaking remains true
        };
        newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => commonOnErrorHandler(event, "utterance event");
        
        synthRef.current.speak(newUtterance);
      }, 50); // Small delay for cancel to take effect
    };

    const handlePlayPauseClick = () => {
      console.log("TTS Player: Play/Pause button clicked. isSpeaking:", isSpeaking, "isPaused:", isPaused);
      if (!synthRef.current) return;

      if (isSpeaking) {
        if (isPaused) {
          console.log("TTS Player: Resuming speech.");
          synthRef.current.resume();
        } else {
          console.log("TTS Player: Pausing speech.");
          synthRef.current.pause();
        }
      } else {
        // Start speaking with currentTextToSpeakRef (either initial or last played paragraph)
        console.log("TTS Player: Starting speech with current ref text:", currentTextToSpeakRef.current.substring(0,50)+"...");
        _speakText(currentTextToSpeakRef.current);
      }
    };

    const handleStopClick = () => {
      console.log("TTS Player: Stop button clicked.");
      if (synthRef.current) {
        synthRef.current.cancel(); 
        setIsSpeaking(false);
        setIsPaused(false);
        utteranceRef.current = null;
      }
    };
    
    React.useImperativeHandle(ref, () => ({
      play: (text: string) => {
        console.log("TTS Player: Imperative play called for text:", text.substring(0,50)+"...");
        currentTextToSpeakRef.current = text;
        _speakText(text);
      },
      stop: () => {
        console.log("TTS Player: Imperative stop called.");
        handleStopClick();
      }
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      console.log("TTS Player: Rate changed to", rate);
      setPlaybackRate(rate);
      // If currently speaking, stop and restart with new rate for the current utterance
      if (synthRef.current && synthRef.current.speaking && utteranceRef.current) {
        const currentText = utteranceRef.current.text;
        // Optimistically update rate on current utterance if possible, though spec says it's read-only after speak
        // utteranceRef.current.rate = rate; // This might not work reliably
        // More robust: cancel and respeak
        console.log("TTS Player: Respeaking with new rate.");
        _speakText(currentText); // This will cancel and create a new utterance with the new rate
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
          <Button 
            onClick={handlePlayPauseClick} 
            disabled={!currentTextToSpeakRef.current?.trim()} 
            className="w-full sm:w-auto" 
            size="sm"
            aria-label={isSpeaking && !isPaused ? "Пауза" : isPaused ? "Продолжить" : "Озвучить"}
          >
            {isSpeaking && !isPaused ? <Pause className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
            {isSpeaking && !isPaused ? 'Пауза' : isPaused ? 'Продолжить' : 'Озвучить'}
          </Button>
          <Button 
            onClick={handleStopClick} 
            disabled={!isSpeaking} 
            variant="outline" 
            className="w-full sm:w-auto" 
            size="sm"
            aria-label="Стоп"
          >
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
                disabled={isSpeaking && !isPaused}
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
              disabled={isSpeaking && !isPaused && !utteranceRef.current} // Allow changing rate if paused
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
         {!currentTextToSpeakRef.current?.trim() && availableVoices.length > 0 && (
          <p className="text-xs text-center text-muted-foreground">Нет текста для озвучки. Текст извлекается из содержимого статьи.</p>
         )}
      </div>
    );
  }
);

TextToSpeechPlayer.displayName = 'TextToSpeechPlayer';

    