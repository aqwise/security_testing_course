
'use client';

import * as React from 'react';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';
// import { Button } from '@/components/ui/button'; // Removed as main button is gone
// import { Play, StopCircle } from 'lucide-react'; // Removed as main button is gone

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
    }, [initialTextToSpeak]);

    React.useEffect(() => {
      if (typeof window !== 'undefined' && window.speechSynthesis) {
        synthRef.current = window.speechSynthesis;
        const loadVoices = () => {
          if (!synthRef.current) return;
          const voices = synthRef.current.getVoices().sort((a, b) => a.name.localeCompare(b.name));
          setAvailableVoices(voices);
          
          if (voices.length > 0) {
            let defaultVoice = voices.find(voice => voice.lang.toLowerCase().startsWith('ru') && voice.default);
            if (!defaultVoice) defaultVoice = voices.find(voice => voice.lang.toLowerCase().startsWith('ru'));
            if (!defaultVoice) defaultVoice = voices.find(voice => voice.lang.toLowerCase().includes('cyrillic'));
            if (!defaultVoice) defaultVoice = voices.find(voice => voice.lang.toLowerCase().startsWith('en') && voice.default);
            if (!defaultVoice) defaultVoice = voices.find(voice => voice.default);
            if (!defaultVoice) defaultVoice = voices[0];
            
            if (defaultVoice) {
              setSelectedVoiceURI(defaultVoice.voiceURI);
              console.log(`TTS Player: Default voice selected: ${defaultVoice.name} (${defaultVoice.lang})`);
            } else {
               console.warn("TTS Player: No suitable default voice found.");
            }
          }
        };

        if (synthRef.current.onvoiceschanged !== undefined) {
          synthRef.current.onvoiceschanged = loadVoices;
        }
        loadVoices(); // Initial attempt

        // Cleanup
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

    const _speakText = () => { // Removed 'text' parameter
      if (!currentTextToSpeakRef.current || !currentTextToSpeakRef.current.trim()) {
        console.warn("TTS Player: _speakText - currentTextToSpeakRef is empty. Aborting.");
        setIsSpeakingState(false);
        return;
      }

      if (!synthRef.current) {
        alert('Ваш браузер не поддерживает Web Speech API.');
        setIsSpeakingState(false);
        return;
      }
      
      console.log(`TTS Player: _speakText preparing to speak from ref: ${currentTextToSpeakRef.current.substring(0, 50)}...`);

      if (synthRef.current.speaking || synthRef.current.pending) {
        console.log("TTS Player: _speakText - Cancelling active/pending speech.");
        if (utteranceRef.current) {
          utteranceRef.current.onstart = null;
          utteranceRef.current.onend = null;
          utteranceRef.current.onerror = null;
          console.log("TTS Player: Detached listeners from utterance being stopped in _speakText's cancel branch.");
        }
        synthRef.current.cancel();
      }
      utteranceRef.current = null;
      setIsSpeakingState(false); 

      setTimeout(() => {
        if (!synthRef.current || !currentTextToSpeakRef.current || !currentTextToSpeakRef.current.trim()) {
            console.warn("TTS Player: Synth or currentTextToSpeakRef became null/empty in speak setTimeout. Aborting.");
            setIsSpeakingState(false);
            return;
        }
        
        const textToActuallySpeak = currentTextToSpeakRef.current;
        const newUtterance = new SpeechSynthesisUtterance(textToActuallySpeak);
        utteranceRef.current = newUtterance; 

        const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
        if (selectedVoice) {
          newUtterance.voice = selectedVoice;
          newUtterance.lang = selectedVoice.lang;
        } else {
          const ruVoice = availableVoices.find(v => v.lang.toLowerCase().startsWith('ru'));
          if (ruVoice) newUtterance.voice = ruVoice;
          newUtterance.lang = ruVoice ? ruVoice.lang : 'ru-RU';
        }
        newUtterance.rate = playbackRate;

        console.log(`TTS Player: Attempting to speak... Text: ${textToActuallySpeak.substring(0,30)}..., Voice: ${newUtterance.voice?.name}, Lang: ${newUtterance.lang}, Rate: ${newUtterance.rate}`);
        console.log(`TTS Player: Before speak() call - synth.speaking: ${synthRef.current.speaking}, synth.pending: ${synthRef.current.pending}`);


        newUtterance.onstart = () => {
          if (utteranceRef.current === newUtterance) {
            console.log("TTS Player: Speech started for current utterance:", newUtterance.text.substring(0,30)+"...");
            setIsSpeakingState(true);
          } else {
             console.warn("TTS Player: onstart event for a STALE utterance. Current is:", utteranceRef.current?.text.substring(0,30), "This utterance:", newUtterance.text.substring(0,30));
          }
        };

        newUtterance.onend = () => {
          if (utteranceRef.current === newUtterance) {
            console.log("TTS Player: Speech ended for current utterance:", newUtterance.text.substring(0,30)+"...");
            setIsSpeakingState(false);
            utteranceRef.current = null;
          } else {
            console.warn("TTS Player: onend event for a STALE utterance. Current is:", utteranceRef.current?.text.substring(0,30), "This utterance:", newUtterance.text.substring(0,30));
          }
        };

        newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
          if (utteranceRef.current === event.utterance) {
            console.error(`TTS Player: Speech error for current utterance. Code: ${event.error}`, {
              charIndex: event.charIndex,
              elapsedTime: event.elapsedTime,
              textSample: event.utterance?.text?.substring(event.charIndex > 10 ? event.charIndex - 10 : 0, event.charIndex + 40),
              voice: event.utterance?.voice?.name,
            });
            if (event.error !== 'interrupted' && event.error !== 'canceled' && event.error !== 'not-allowed') {
              alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
            }
            setIsSpeakingState(false);
            utteranceRef.current = null;
          } else {
             console.warn("TTS Player: onerror event for a STALE utterance. Error code:", event.error, "Current is:", utteranceRef.current?.text.substring(0,30), "This utterance:", event.utterance?.text.substring(0,30));
          }
        };
        
        synthRef.current.speak(newUtterance);
        
        setTimeout(() => {
            if(synthRef.current) {
                console.log(`TTS Player: After speak() call (100ms delay) - synth.speaking: ${synthRef.current.speaking}, synth.pending: ${synthRef.current.pending}`);
                if (!synthRef.current.speaking && !synthRef.current.pending && textToActuallySpeak.length > 0) {
                    // If it's not speaking and not pending, and we tried to speak non-empty text, it's a silent fail.
                    console.warn("TTS Player: synth.speak() was called, but synth is not speaking or pending. This might indicate a silent failure or very short text.");
                     // Don't setIsSpeakingState(false) here as onend/onerror should handle it
                }
            }
        }, 100);

      }, 250); 
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
        synthRef.current.cancel(); // This should trigger onend or onerror with 'canceled'
        setIsSpeakingState(false);
        utteranceRef.current = null; // Clear ref after cancelling
        console.log("TTS Player: Speech explicitly cancelled, state set to not speaking, utteranceRef cleared.");
      }
    };

    React.useImperativeHandle(ref, () => ({
      play: (text: string) => {
        console.log(`TTS Player: Imperative play called with text: ${text.substring(0, 50)}...`);
        if (!text || !text.trim()) {
          console.warn("TTS Player: Play called with empty text. Aborting.");
          handleStopExplicitly();
          return;
        }
        currentTextToSpeakRef.current = text;
        _speakText(); // Call _speakText without parameter
      },
      stop: () => {
        handleStopExplicitly();
      },
      isSpeaking: () => {
        // More reliable check might involve synth.speaking directly if state updates are tricky
        return synthRef.current?.speaking || isSpeakingState;
      },
      currentTextToSpeakRef: currentTextToSpeakRef
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      setPlaybackRate(rate);
      if (isSpeakingState && currentTextToSpeakRef.current && currentTextToSpeakRef.current.trim()) {
        console.log("TTS Player: Rate changed while speaking. Respeaking.");
        _speakText();
      }
    };
    
    const handleVoiceChange = (newVoiceURI: string) => {
      setSelectedVoiceURI(newVoiceURI);
      if (isSpeakingState && currentTextToSpeakRef.current && currentTextToSpeakRef.current.trim()) {
        console.log("TTS Player: Voice changed while speaking. Respeaking.");
         _speakText();
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
      </div>
    );
  }
);

TextToSpeechPlayer.displayName = 'TextToSpeechPlayer';
    
