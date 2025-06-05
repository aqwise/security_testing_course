
'use client';

import * as React from 'react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Play, StopCircle } from 'lucide-react';
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
    const [isPaused, setIsPaused] = React.useState<boolean>(false); // Kept for internal consistency if speech is paused by browser
    const [availableVoices, setAvailableVoices] = React.useState<SpeechSynthesisVoice[]>([]);
    const [selectedVoiceURI, setSelectedVoiceURI] = React.useState<string | undefined>();
    const [playbackRate, setPlaybackRate] = React.useState<number>(1);
    
    const utteranceRef = React.useRef<SpeechSynthesisUtterance | null>(null);
    const synthRef = React.useRef<SpeechSynthesis | null>(null);
    const currentTextToSpeakRef = React.useRef<string>(initialTextToSpeak);

    React.useEffect(() => {
      currentTextToSpeakRef.current = initialTextToSpeak;
      console.log("TTS Player: initialTextToSpeak updated:", initialTextToSpeak?.substring(0,50)+"...");
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
              const firstEnglishVoice = voices.find(v => v.lang.toLowerCase().startsWith('en'));
              if (firstEnglishVoice) {
                setSelectedVoiceURI(firstEnglishVoice.voiceURI);
              } else if (voices[0]) {
                setSelectedVoiceURI(voices[0].voiceURI);
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

    const _speakText = (text: string) => {
      if (!text?.trim()) {
        console.log("TTS Player: Attempted to speak empty or undefined text. Aborting.");
        setIsSpeaking(false);
        setIsPaused(false);
        return;
      }
      if (!synthRef.current) {
        alert('Ваш браузер не поддерживает Web Speech API.');
        return;
      }

      console.log("TTS Player: _speakText. Current synth state - speaking:", synthRef.current.speaking, "pending:", synthRef.current.pending, "paused:", synthRef.current.paused);
      console.log("TTS Player: _speakText preparing to speak:", text.substring(0, 50) + "...");
      
      synthRef.current.cancel(); 
      
      setTimeout(() => {
        if (!synthRef.current) {
          console.log("TTS Player: synthRef became null in setTimeout for speak.");
          return;
        }

        const newUtterance = new SpeechSynthesisUtterance(text);
        utteranceRef.current = newUtterance;

        const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
        if (selectedVoice) {
          newUtterance.voice = selectedVoice;
          newUtterance.lang = selectedVoice.lang;
        } else {
          const ruVoice = availableVoices.find(v => v.lang.toLowerCase().startsWith('ru'));
          if (ruVoice) {
            newUtterance.voice = ruVoice;
            newUtterance.lang = ruVoice.lang;
          } else {
            newUtterance.lang = 'ru-RU'; 
          }
        }
        
        newUtterance.rate = playbackRate;

        newUtterance.onstart = () => {
          console.log("TTS Player: Speech started for utterance:", newUtterance.text.substring(0,30)+"...");
          setIsSpeaking(true);
          setIsPaused(false);
        };
        newUtterance.onend = () => {
          console.log("TTS Player: Speech ended for utterance:", newUtterance.text.substring(0,30)+"...");
          // Only reset state if this specific utterance ended and wasn't immediately replaced
          if (utteranceRef.current === newUtterance) {
            setIsSpeaking(false);
            setIsPaused(false);
            utteranceRef.current = null; 
          }
        };
        newUtterance.onpause = () => {
          console.log("TTS Player: Speech paused by browser/OS.");
          setIsPaused(true);
          setIsSpeaking(true); 
        };
        newUtterance.onresume = () => {
          console.log("TTS Player: Speech resumed by browser/OS.");
          setIsPaused(false);
        };
        newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
            if (event.error === 'interrupted' || event.error === 'canceled') {
                console.warn(`Синтез речи прерван/отменен (контекст: utterance event, ожидаемо): ${event.error}`);
                // Reset state if this utterance was the one active
                if (utteranceRef.current === event.utterance) {
                    setIsSpeaking(false);
                    setIsPaused(false);
                    utteranceRef.current = null;
                }
                return;
            }
            console.error(`Ошибка синтеза речи. Код ошибки: ${event.error}`);
            console.error('Дополнительные детали ошибки:', {
                charIndex: event.charIndex,
                elapsedTime: event.elapsedTime,
                textSample: event.utterance?.text?.substring(event.charIndex > 10 ? event.charIndex - 10 : 0, event.charIndex + 40),
                voiceName: event.utterance?.voice?.name,
                voiceLang: event.utterance?.voice?.lang,
                selectedVoiceURI: selectedVoiceURI,
            });
            if (utteranceRef.current === event.utterance) {
                setIsSpeaking(false);
                setIsPaused(false);
                utteranceRef.current = null;
            }
            alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
        };
        
        console.log("TTS Player: Calling synth.speak() for:", newUtterance.text.substring(0,50)+"...");
        synthRef.current.speak(newUtterance);
      }, 100); // Increased timeout to 100ms
    };

    const handleStopExplicitly = () => {
      console.log("TTS Player: Explicit Stop button clicked or stop() called.");
      if (synthRef.current) {
        synthRef.current.cancel(); 
        setIsSpeaking(false);
        setIsPaused(false);
        utteranceRef.current = null;
      }
    };
    
    const handlePlayStopToggleClick = () => {
      console.log("TTS Player: Play/Stop toggle button clicked. isSpeaking:", isSpeaking);
      if (!synthRef.current) return;

      if (isSpeaking) { 
        handleStopExplicitly();
      } else { 
        console.log("TTS Player: Starting speech from main button with current ref text:", currentTextToSpeakRef.current?.substring(0,50)+"...");
        _speakText(currentTextToSpeakRef.current);
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
        handleStopExplicitly();
      }
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      setPlaybackRate(rate);
      if (synthRef.current && utteranceRef.current && (synthRef.current.speaking || synthRef.current.paused)) {
        // If currently speaking or paused, stop and restart with the new rate
        // Grab the text from the current utterance
        const currentUtteranceText = utteranceRef.current.text;
        console.log("TTS Player: Rate changed. Respeaking text:", currentUtteranceText.substring(0,50)+"...");
        _speakText(currentUtteranceText); 
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
            onClick={handlePlayStopToggleClick} 
            disabled={!currentTextToSpeakRef.current?.trim()} 
            className="w-full sm:w-auto" 
            size="sm"
            aria-label={isSpeaking ? "Стоп" : "Озвучить"}
          >
            {isSpeaking ? <StopCircle className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
            {isSpeaking ? 'Стоп' : 'Озвучить'}
          </Button>
          <Button 
            onClick={handleStopExplicitly} 
            disabled={!isSpeaking && !isPaused} // Also enable if paused
            variant="outline" 
            className="w-full sm:w-auto" 
            size="sm"
            aria-label="Стоп (доп.)"
          >
            <StopCircle className="mr-2 h-4 w-4" /> Стоп (доп.)
          </Button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {availableVoices.length > 0 && (
            <div className="space-y-1">
              <Label htmlFor="voice-select-player-page" className="text-xs font-medium">Голос:</Label>
              <Select
                value={selectedVoiceURI}
                onValueChange={setSelectedVoiceURI}
                // Allow changing voice even if speaking, it will apply on next play or if rate changes
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
         {!currentTextToSpeakRef.current?.trim() && availableVoices.length > 0 && (
          <p className="text-xs text-center text-muted-foreground">Нет текста для озвучки. Текст извлекается из содержимого статьи.</p>
         )}
      </div>
    );
  }
);

TextToSpeechPlayer.displayName = 'TextToSpeechPlayer';
    