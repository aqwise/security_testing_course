
'use client';

import * as React from 'react';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';

interface TextToSpeechPlayerProps {
  initialTextToSpeak: string; // Although not directly used for a main play button now
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
      // This ref holds the text that *should* be spoken if a global play action were initiated.
      // Since play is now per-paragraph, this might be less relevant unless a "play all" is added back.
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
            if (utteranceRef.current) {
              utteranceRef.current.onstart = null;
              utteranceRef.current.onend = null;
              utteranceRef.current.onerror = null;
            }
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
        console.warn("TTS Player: _speakText - Attempted to speak empty or undefined text. Aborting.");
        setIsSpeakingState(false);
        return;
      }
      if (!synthRef.current) {
        alert('Ваш браузер не поддерживает Web Speech API.');
        setIsSpeakingState(false);
        return;
      }
      
      console.log("TTS Player: _speakText preparing to speak:", text.substring(0, 50) + "...");

      // Cancel any ongoing or pending speech and clean up old utterance
      if (synthRef.current.speaking || synthRef.current.pending) {
        console.log("TTS Player: _speakText - Cancelling active/pending speech.");
        if (utteranceRef.current) {
          utteranceRef.current.onstart = null;
          utteranceRef.current.onend = null;
          utteranceRef.current.onerror = null;
        }
        synthRef.current.cancel();
      }
      utteranceRef.current = null; // Ensure ref is clear before timeout
      setIsSpeakingState(false); // Assume stopped until new utterance starts

      // Delay to allow the browser to process the cancel() call
      setTimeout(() => {
        if (!synthRef.current || !currentTextToSpeakRef.current) { // Re-check synth and if text is still valid
            console.warn("TTS Player: Synth or currentTextToSpeakRef became null/empty in speak setTimeout. Aborting.");
            setIsSpeakingState(false); // Ensure state is correct
            return;
        }
        
        // Use the most up-to-date text from the ref, which was set by the 'play' command
        const textToActuallySpeak = currentTextToSpeakRef.current;
        if (!textToActuallySpeak.trim()) {
            console.warn("TTS Player: textToActuallySpeak is empty in speak setTimeout. Aborting.");
            setIsSpeakingState(false);
            return;
        }

        const newUtterance = new SpeechSynthesisUtterance(textToActuallySpeak);
        utteranceRef.current = newUtterance; // This is now the active utterance

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
          if (utteranceRef.current === newUtterance) {
            console.log("TTS Player: Speech started for current utterance:", newUtterance.text.substring(0,30)+"...");
            setIsSpeakingState(true);
          } else {
             console.log("TTS Player: onstart event for a STALE utterance. Current is:", utteranceRef.current?.text.substring(0,30));
          }
        };

        newUtterance.onend = () => {
          if (utteranceRef.current === newUtterance) {
            console.log("TTS Player: Speech ended for current utterance:", newUtterance.text.substring(0,30)+"...");
            setIsSpeakingState(false);
            utteranceRef.current = null;
          } else {
            console.log("TTS Player: onend event for a STALE utterance. Current is:", utteranceRef.current?.text.substring(0,30));
          }
        };

        newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
          if (utteranceRef.current === event.utterance) {
            console.error(`TTS Player: Speech error for current utterance. Code: ${event.error}`, {
              charIndex: event.charIndex,
              elapsedTime: event.elapsedTime,
              textSample: event.utterance?.text?.substring(event.charIndex > 10 ? event.charIndex - 10 : 0, event.charIndex + 40),
            });
            if (event.error !== 'interrupted' && event.error !== 'canceled') {
              alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
            }
            setIsSpeakingState(false);
            utteranceRef.current = null;
          } else {
             console.warn("TTS Player: onerror event for a STALE utterance. Current is:", utteranceRef.current?.text.substring(0,30), "Error code:", event.error);
          }
        };
        
        console.log("TTS Player: Calling synth.speak() for current utterance:", newUtterance.text.substring(0,50)+"...");
        synthRef.current.speak(newUtterance);
      }, 200); // Increased delay for cancel to process
    };

    const handleStopExplicitly = () => {
      console.log("TTS Player: Explicit Stop (handleStopExplicitly).");
      if (synthRef.current) {
        if (utteranceRef.current) {
          utteranceRef.current.onstart = null;
          utteranceRef.current.onend = null;
          utteranceRef.current.onerror = null;
          console.log("TTS Player: Detached listeners from utterance being stopped.");
        }
        synthRef.current.cancel();
        setIsSpeakingState(false);
        utteranceRef.current = null;
        console.log("TTS Player: Speech cancelled, state set to not speaking, utteranceRef cleared.");
      }
    };

    React.useImperativeHandle(ref, () => ({
      play: (text: string) => {
        console.log("TTS Player: Imperative play called with text:", text.substring(0,50)+"...");
        currentTextToSpeakRef.current = text; // Set the text that should be spoken
        _speakText(text);
      },
      stop: () => {
        handleStopExplicitly();
      },
      isSpeaking: () => isSpeakingState,
      currentTextToSpeakRef: currentTextToSpeakRef
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      setPlaybackRate(rate);
      if (isSpeakingState && currentTextToSpeakRef.current) {
        console.log("TTS Player: Rate changed while speaking. Respeaking.");
        _speakText(currentTextToSpeakRef.current);
      }
    };
    
    const handleVoiceChange = (newVoiceURI: string) => {
      setSelectedVoiceURI(newVoiceURI);
      if (isSpeakingState && currentTextToSpeakRef.current) {
        console.log("TTS Player: Voice changed while speaking. Respeaking.");
         _speakText(currentTextToSpeakRef.current);
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
          {availableVoices.length > 0 && (
            <div className="space-y-1">
              <Label htmlFor="voice-select-player-page" className="text-xs font-medium">Голос:</Label>
              <Select
                value={selectedVoiceURI}
                onValueChange={handleVoiceChange}
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
         {/* Removed "Нет текста для озвучки" message as it might be confusing now */}
      </div>
    );
  }
);

TextToSpeechPlayer.displayName = 'TextToSpeechPlayer';
    