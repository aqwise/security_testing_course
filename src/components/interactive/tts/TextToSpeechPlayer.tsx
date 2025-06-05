
'use client';

import * as React from 'react';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
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
    const speakTimeoutRef = React.useRef<NodeJS.Timeout | null>(null);

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
            if (!defaultVoice && voices.length > 0) defaultVoice = voices[0];
            
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
        loadVoices(); 

        return () => {
          if (speakTimeoutRef.current) {
            clearTimeout(speakTimeoutRef.current);
          }
          if (synthRef.current) {
            if (utteranceRef.current) {
              utteranceRef.current.onstart = null;
              utteranceRef.current.onend = null;
              utteranceRef.current.onerror = null;
              utteranceRef.current.onpause = null;
              utteranceRef.current.onresume = null;
              utteranceRef.current.onmark = null;
              utteranceRef.current.onboundary = null;
            }
            synthRef.current.cancel();
            if (synthRef.current.onvoiceschanged !== undefined) {
              synthRef.current.onvoiceschanged = null;
            }
          }
        };
      }
    }, []);

    const _speakText = () => {
      console.log(`TTS Player: _speakText called. Current speaking state: ${isSpeakingState}`);
      if (speakTimeoutRef.current) {
        clearTimeout(speakTimeoutRef.current);
        console.log("TTS Player: Cleared existing speak timeout in _speakText.");
        speakTimeoutRef.current = null;
      }

      if (synthRef.current) {
        if (utteranceRef.current && utteranceRef.current !== null) {
            utteranceRef.current.onstart = null;
            utteranceRef.current.onend = null;
            utteranceRef.current.onerror = null;
            utteranceRef.current.onpause = null;
            utteranceRef.current.onresume = null;
            utteranceRef.current.onmark = null;
            utteranceRef.current.onboundary = null;
            console.log("TTS Player: Detached listeners from PREVIOUS utterance in _speakText.");
        }
        console.log("TTS Player: Calling synth.cancel() at the start of _speakText.");
        synthRef.current.cancel(); 
      }
      setIsSpeakingState(false); 
      utteranceRef.current = null; 

      console.log(`TTS Player: _speakText preparing to speak from ref: ${currentTextToSpeakRef.current.substring(0, 50)}...`);

      if (!synthRef.current || !currentTextToSpeakRef.current || !currentTextToSpeakRef.current.trim()) {
          console.warn("TTS Player: Synth or currentTextToSpeakRef became null/empty before creating utterance. Aborting.");
          setIsSpeakingState(false);
          return;
      }
      
      const textToActuallySpeak = currentTextToSpeakRef.current;
      const newUtterance = new SpeechSynthesisUtterance(textToActuallySpeak);
      utteranceRef.current = newUtterance; // Assign to ref immediately

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
      newUtterance.volume = 1; // Explicitly set volume
      newUtterance.pitch = 1;  // Explicitly set pitch

      console.log(`TTS Player: Attempting to speak... Text: ${textToActuallySpeak.substring(0,30)}..., Voice: ${newUtterance.voice?.name}, Lang: ${newUtterance.lang}, Rate: ${newUtterance.rate}, Volume: ${newUtterance.volume}`);
        
      newUtterance.onstart = () => {
        console.log("TTS Player: EVENT onstart fired. Utterance text:", newUtterance.text.substring(0,30)+"...");
        if (utteranceRef.current === newUtterance) {
          setIsSpeakingState(true);
        } else {
           console.warn("TTS Player: onstart event for a STALE utterance.");
        }
      };

      newUtterance.onend = () => {
        console.log("TTS Player: EVENT onend fired. Utterance text:", newUtterance.text.substring(0,30)+"...");
        if (utteranceRef.current === newUtterance) {
          setIsSpeakingState(false);
          utteranceRef.current = null;
        } else {
          console.warn("TTS Player: onend event for a STALE utterance.");
        }
      };

      newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
        console.error(`TTS Player: EVENT onerror fired. Error: ${event.error}, Utterance text:`, event.utterance?.text?.substring(0,30)+"...");
        if (utteranceRef.current === event.utterance) {
          if (event.error !== 'interrupted' && event.error !== 'canceled' && event.error !== 'not-allowed') {
            alert(`Ошибка озвучки: ${event.error}. Попробуйте другой голос или текст.`);
          }
          setIsSpeakingState(false);
          utteranceRef.current = null;
        } else {
           console.warn("TTS Player: onerror event for a STALE utterance. Error code:", event.error);
        }
      };
      
      newUtterance.onpause = (event: SpeechSynthesisEvent) => { 
          console.log("TTS Player: EVENT onpause fired. Utterance text:", (event.utterance as SpeechSynthesisUtterance)?.text?.substring(0,30)+"...");
          if (utteranceRef.current === event.utterance) setIsSpeakingState(false);
      };
      newUtterance.onresume = (event: SpeechSynthesisEvent) => {
          console.log("TTS Player: EVENT onresume fired. Utterance text:", (event.utterance as SpeechSynthesisUtterance)?.text?.substring(0,30)+"...");
          if (utteranceRef.current === event.utterance) setIsSpeakingState(true);
      };
      newUtterance.onmark = (event: SpeechSynthesisEvent) => { 
          console.log("TTS Player: EVENT onmark fired. Name:", event.name, "Utterance text:", (event.utterance as SpeechSynthesisUtterance)?.text?.substring(0,30)+"...");
      };
      newUtterance.onboundary = (event: SpeechSynthesisEvent) => {
          console.log("TTS Player: EVENT onboundary fired. Name:", event.name, "CharIndex:", event.charIndex, "Utterance text:", (event.utterance as SpeechSynthesisUtterance)?.text?.substring(0,30)+"...");
      };
      
      console.log("TTS Player: Utterance object before speak:", utteranceRef.current);

      speakTimeoutRef.current = setTimeout(() => {
        speakTimeoutRef.current = null; 
        if(synthRef.current && utteranceRef.current) { // Check utteranceRef.current here
            console.log(`TTS Player: Before speak() call - synth.speaking: ${synthRef.current.speaking}, synth.pending: ${synthRef.current.pending}, synth.paused: ${synthRef.current.paused}`);
            synthRef.current.speak(utteranceRef.current); // Speak the utterance from the ref
            
            setTimeout(() => {
                if(synthRef.current) {
                    console.log(`TTS Player: After speak() call (100ms delay) - synth.speaking: ${synthRef.current.speaking}, synth.pending: ${synthRef.current.pending}, synth.paused: ${synthRef.current.paused}`);
                    if (!synthRef.current.speaking && !synthRef.current.pending && utteranceRef.current && utteranceRef.current.text.length > 0 && utteranceRef.current === newUtterance) {
                        console.warn("TTS Player: synth.speak() was called for current utterance, but synth is not speaking or pending. This might indicate a silent failure or an extremely short utterance that finished before the check.");
                    }
                }
            }, 100);
        } else {
          console.warn("TTS Player: synthRef or utteranceRef became null in speak setTimeout. Aborting speak.");
          setIsSpeakingState(false);
        }
      }, 250); 
    };

    const handleStopExplicitly = () => {
      console.log("TTS Player: Explicit Stop (handleStopExplicitly).");
      if (speakTimeoutRef.current) {
        clearTimeout(speakTimeoutRef.current);
        speakTimeoutRef.current = null;
        console.log("TTS Player: Cleared pending speak timeout during explicit stop.");
      }
      if (synthRef.current) {
        if (utteranceRef.current && utteranceRef.current !== null) {
          utteranceRef.current.onstart = null;
          utteranceRef.current.onend = null;
          utteranceRef.current.onerror = null;
          utteranceRef.current.onpause = null;
          utteranceRef.current.onresume = null;
          utteranceRef.current.onmark = null;
          utteranceRef.current.onboundary = null;
          console.log("TTS Player: Detached listeners from utterance being stopped explicitly.");
        }
        synthRef.current.cancel(); 
        setIsSpeakingState(false);
        utteranceRef.current = null; 
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
        _speakText();
      },
      stop: () => {
        handleStopExplicitly();
      },
      isSpeaking: () => {
        return synthRef.current?.speaking || isSpeakingState;
      },
      currentTextToSpeakRef: currentTextToSpeakRef
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      setPlaybackRate(rate);
      if ((synthRef.current?.speaking || synthRef.current?.paused) && currentTextToSpeakRef.current && currentTextToSpeakRef.current.trim()) {
        console.log("TTS Player: Rate changed while speaking/paused. Respeaking.");
        _speakText();
      }
    };
    
    const handleVoiceChange = (newVoiceURI: string) => {
      setSelectedVoiceURI(newVoiceURI);
      if ((synthRef.current?.speaking || synthRef.current?.paused) && currentTextToSpeakRef.current && currentTextToSpeakRef.current.trim()) {
        console.log("TTS Player: Voice changed while speaking/paused. Respeaking.");
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
    
