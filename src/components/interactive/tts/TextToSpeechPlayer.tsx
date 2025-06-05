
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
  isSpeaking: () => boolean;
  currentTextToSpeakRef?: React.MutableRefObject<string>; 
}

export const TextToSpeechPlayer = React.forwardRef<TextToSpeechPlayerRef, TextToSpeechPlayerProps>(
  ({ initialTextToSpeak, className }, ref) => {
    const [isSpeakingState, setIsSpeakingState] = React.useState<boolean>(false);
    const [availableVoices, setAvailableVoices] = React.useState<SpeechSynthesisVoice[]>([]);
    const [selectedVoiceURI, setSelectedVoiceURI] = React.useState<string | undefined>();
    const [playbackRate, setPlaybackRate] = React.useState<number>(1);
    
    const utteranceRef = React.useRef<SpeechSynthesisUtterance | null>(null);
    const synthRef = React.useRef<SpeechSynthesis | null>(null);
    const currentTextToSpeakRef = React.useRef<string>(initialTextToSpeak);

    React.useEffect(() => {
      currentTextToSpeakRef.current = initialTextToSpeak;
      console.log("TTS Player: initialTextToSpeak updated in player:", initialTextToSpeak?.substring(0,50)+"...");
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
        setIsSpeakingState(false);
        return;
      }
      if (!synthRef.current) {
        alert('Ваш браузер не поддерживает Web Speech API.');
        return;
      }

      console.log("TTS Player: _speakText. Current synth state - speaking:", synthRef.current.speaking, "pending:", synthRef.current.pending, "paused:", synthRef.current.paused);
      console.log("TTS Player: _speakText preparing to speak:", text.substring(0, 50) + "...");
      
      // Ensure any previous speech is fully cancelled before starting new.
      if (synthRef.current.speaking || synthRef.current.pending) {
          console.log("TTS Player: Cancelling active/pending speech before new one.");
          synthRef.current.cancel();
      }
      
      // Short delay to allow cancel to process fully on all browsers/OS
      setTimeout(() => {
        if (!synthRef.current) {
          console.log("TTS Player: synthRef became null in setTimeout for speak.");
          return;
        }

        const newUtterance = new SpeechSynthesisUtterance(text);
        utteranceRef.current = newUtterance; // Store reference to the current utterance

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
          setIsSpeakingState(true);
        };
        newUtterance.onend = () => {
          console.log("TTS Player: Speech ended for utterance:", newUtterance.text.substring(0,30)+"...");
          // Only clear if this is the utterance that ended
          if (utteranceRef.current === newUtterance) {
            setIsSpeakingState(false);
            utteranceRef.current = null; 
          }
        };
        
        newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
            if (event.error === 'interrupted' || event.error === 'canceled') {
                console.warn(`Синтез речи прерван/отменен (контекст: utterance event, ожидаемо): ${event.error}`);
            } else {
                console.error(`Ошибка синтеза речи. Код ошибки: ${event.error}`);
                console.error('Дополнительные детали ошибки:', {
                    charIndex: event.charIndex,
                    elapsedTime: event.elapsedTime,
                    textSample: event.utterance?.text?.substring(event.charIndex > 10 ? event.charIndex - 10 : 0, event.charIndex + 40),
                    voiceName: event.utterance?.voice?.name,
                    voiceLang: event.utterance?.voice?.lang,
                    selectedVoiceURI: selectedVoiceURI,
                });
                alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
            }
            // Only clear if this is the utterance that errored
            if (utteranceRef.current === event.utterance) {
                setIsSpeakingState(false);
                utteranceRef.current = null;
            }
        };
        
        console.log("TTS Player: Calling synth.speak() for:", newUtterance.text.substring(0,50)+"...");
        synthRef.current.speak(newUtterance);
      }, 100); // Increased delay
    };

    const handleStopExplicitly = () => {
      console.log("TTS Player: Explicit Stop button clicked or stop() called.");
      if (synthRef.current) {
        synthRef.current.cancel(); 
        setIsSpeakingState(false);
        utteranceRef.current = null; // Clear the ref since we've stopped it.
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
      },
      isSpeaking: () => isSpeakingState,
      currentTextToSpeakRef: currentTextToSpeakRef
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      setPlaybackRate(rate);
      if (synthRef.current && utteranceRef.current && (synthRef.current.speaking || synthRef.current.paused)) {
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
         {isSpeakingState && <p className="text-xs text-center text-primary animate-pulse">Воспроизведение...</p>}
         {!currentTextToSpeakRef.current?.trim() && availableVoices.length > 0 && !isSpeakingState && (
          <p className="text-xs text-center text-muted-foreground">Нет текста для озвучки. Кликните на иконку ▶️ у абзаца.</p>
         )}
      </div>
    );
  }
);

TextToSpeechPlayer.displayName = 'TextToSpeechPlayer';
    

    

    