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
        console.log("TTS Player: Web Speech API initialized", {
          speechSynthesis: window.speechSynthesis,
          speaking: window.speechSynthesis.speaking,
          pending: window.speechSynthesis.pending,
          paused: window.speechSynthesis.paused
        });
          const loadVoices = () => {
          if (!synthRef.current) {
            console.warn("TTS Player: synthRef became null in loadVoices");
            return;
          }
          const allVoices = synthRef.current.getVoices();
          console.log("TTS Player: Raw voices from API:", allVoices.length);          // Filter to include Russian voices, related Cyrillic languages, and Google voices
          const russianVoices = allVoices.filter(voice => {
            const lang = voice.lang.toLowerCase();
            const name = voice.name.toLowerCase();
            return lang.startsWith('ru') || // Russian (ru, ru-RU, etc.)
                   lang.startsWith('be') || // Belarusian
                   lang.startsWith('bg') || // Bulgarian  
                   lang.startsWith('mk') || // Macedonian
                   lang.startsWith('sr') || // Serbian
                   lang.startsWith('uk') || // Ukrainian                   lang.includes('cyrillic') ||
                   name.includes('russian') ||
                   name.includes('россий') ||
                   name.includes('русск') ||
                   name.includes('google'); // Include Google voices
          }).sort((a, b) => {
            // Prioritize Russian voices first, then Google voices, then alphabetically
            const aIsRussian = a.lang.toLowerCase().startsWith('ru') || a.name.toLowerCase().includes('russian');
            const bIsRussian = b.lang.toLowerCase().startsWith('ru') || b.name.toLowerCase().includes('russian');
            const aIsGoogle = a.name.toLowerCase().includes('google');
            const bIsGoogle = b.name.toLowerCase().includes('google');
            
            if (aIsRussian && !bIsRussian) return -1;
            if (!aIsRussian && bIsRussian) return 1;
            if (aIsGoogle && !bIsGoogle) return -1;
            if (!aIsGoogle && bIsGoogle) return 1;
            return a.name.localeCompare(b.name);
          });
            setAvailableVoices(russianVoices);
          console.log(`TTS Player: Loaded ${russianVoices.length} Russian/Cyrillic/Google voices`);
            if (russianVoices.length > 0) {
            // Prefer Russian voices, then Google voices, then default voices, then any available
            let defaultVoice = russianVoices.find(voice => voice.lang.toLowerCase().startsWith('ru') && voice.default);
            if (!defaultVoice) defaultVoice = russianVoices.find(voice => voice.lang.toLowerCase().startsWith('ru'));
            if (!defaultVoice) defaultVoice = russianVoices.find(voice => voice.name.toLowerCase().includes('google'));
            if (!defaultVoice) defaultVoice = russianVoices.find(voice => voice.default);
            if (!defaultVoice) defaultVoice = russianVoices[0];
            
            setSelectedVoiceURI(defaultVoice.voiceURI);
            console.log(`TTS Player: Selected voice: ${defaultVoice.name} (${defaultVoice.lang})`);          } else {
            console.warn("TTS Player: No Russian, Cyrillic, or Google voices available");
          }
        };        // Set up voice loading with multiple strategies
        if (synthRef.current.onvoiceschanged !== undefined) {
          synthRef.current.onvoiceschanged = () => {
            console.log("TTS Player: onvoiceschanged event fired");
            loadVoices();
          };
          console.log("TTS Player: Set onvoiceschanged listener");
        }
        
        // Strategy 1: Try to load voices immediately
        const initialVoices = synthRef.current.getVoices();
        console.log("TTS Player: Initial voices check:", initialVoices.length);
        if (initialVoices.length > 0) {
            loadVoices();
        } else {
          console.log("TTS Player: No voices available immediately, trying multiple fallback strategies...");
          
          // Strategy 2: Wait a bit and try again - some browsers need time
          setTimeout(() => {
            console.log("TTS Player: Delayed voices check after 100ms");
            const delayedVoices = synthRef.current?.getVoices() || [];
            if (delayedVoices.length > 0) {
              loadVoices();
            } else {
              console.log("TTS Player: Still no voices after 100ms, trying 500ms...");
              // Strategy 3: Wait longer
              setTimeout(() => {
                console.log("TTS Player: Delayed voices check after 500ms");
                const furtherDelayedVoices = synthRef.current?.getVoices() || [];
                if (furtherDelayedVoices.length > 0) {
                  loadVoices();
                } else {
                  console.warn("TTS Player: No voices available after 500ms delay");
                }
              }, 400);
            }
          }, 100);
        }

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

    const _clearPreviousUtterance = () => {
      if (utteranceRef.current) {
        utteranceRef.current.onstart = null;
        utteranceRef.current.onend = null;
        utteranceRef.current.onerror = null;
        utteranceRef.current.onpause = null;
        utteranceRef.current.onresume = null;
        utteranceRef.current.onmark = null;
        utteranceRef.current.onboundary = null;
        console.log("TTS Player: Detached listeners from PREVIOUS utterance in _clearPreviousUtterance.");
      }
      utteranceRef.current = null;
    };
      const _speakText = () => {
      if (speakTimeoutRef.current) {
        clearTimeout(speakTimeoutRef.current);
        speakTimeoutRef.current = null;
      }

      if (synthRef.current) {
          _clearPreviousUtterance();
          synthRef.current.cancel();
      } else {
        console.error("TTS Player: synthRef is null in _speakText");
        setIsSpeakingState(false);
        return;
      }
      setIsSpeakingState(false);

      if (!synthRef.current || !currentTextToSpeakRef.current || !currentTextToSpeakRef.current.trim()) {
          console.warn("TTS Player: No text to speak");
          setIsSpeakingState(false);
          return;
      }
      
      const textToActuallySpeak = currentTextToSpeakRef.current;
      const newUtterance = new SpeechSynthesisUtterance(textToActuallySpeak);
      
      console.log("TTS Player: Created new utterance:", {
        text: textToActuallySpeak.substring(0, 50) + "...",
        textLength: textToActuallySpeak.length
      });
      
      const selectedVoice = availableVoices.find(v => v.voiceURI === selectedVoiceURI);
      if (selectedVoice) {
        newUtterance.voice = selectedVoice;
        newUtterance.lang = selectedVoice.lang; // Ensure language matches the voice
        console.log(`TTS Player: Attempting to speak... Text: "${textToActuallySpeak.substring(0,30)}...", Voice: ${newUtterance.voice?.name}, Lang: ${newUtterance.lang}, Rate: ${playbackRate}`);      } else {
        console.warn(`TTS Player: Selected voice URI '${selectedVoiceURI}' not found in available voices`);
        // Fallback to any Russian, Cyrillic, or Google voice
        const russianVoice = availableVoices.find(v => v.lang.toLowerCase().startsWith('ru'));
        const googleVoice = availableVoices.find(v => v.name.toLowerCase().includes('google'));
        const cyrillicVoice = availableVoices.find(v => 
          v.lang.toLowerCase().startsWith('be') || 
          v.lang.toLowerCase().startsWith('bg') || 
          v.lang.toLowerCase().startsWith('uk') ||
          v.lang.toLowerCase().includes('cyrillic')
        );
        
        if (russianVoice) {
            newUtterance.lang = russianVoice.lang;
            console.log(`TTS Player: Using Russian fallback voice with lang '${russianVoice.lang}'. Text: "${textToActuallySpeak.substring(0,30)}..."`);
        } else if (googleVoice) {
            newUtterance.lang = googleVoice.lang;
            console.log(`TTS Player: Using Google fallback voice with lang '${googleVoice.lang}'. Text: "${textToActuallySpeak.substring(0,30)}..."`);
        } else if (cyrillicVoice) {
            newUtterance.lang = cyrillicVoice.lang;
            console.log(`TTS Player: Using Cyrillic fallback voice with lang '${cyrillicVoice.lang}'. Text: "${textToActuallySpeak.substring(0,30)}..."`);
        } else {
            newUtterance.lang = 'ru-RU'; // Final fallback
            console.log(`TTS Player: No Russian/Cyrillic/Google voices found, using 'ru-RU' as final fallback. Text: "${textToActuallySpeak.substring(0,30)}..."`);
        }
      }

      newUtterance.rate = playbackRate;
      newUtterance.volume = 1; 
      newUtterance.pitch = 1; 

      utteranceRef.current = newUtterance; 
      console.log("TTS Player: Utterance object before speak:", {
        text: newUtterance.text?.substring(0, 30) + "...",
        voice: newUtterance.voice?.name,
        lang: newUtterance.lang,
        rate: newUtterance.rate,
        volume: newUtterance.volume,
        pitch: newUtterance.pitch
      }); 

      newUtterance.onstart = (event: SpeechSynthesisEvent) => {
        console.log("TTS Player: EVENT onstart fired. Utterance text:", (event.utterance as SpeechSynthesisUtterance)?.text?.substring(0,30)+"...");
        if (utteranceRef.current === event.utterance) {
          setIsSpeakingState(true);
        } else {
           console.warn("TTS Player: onstart event for a STALE utterance.");
        }
      };

      newUtterance.onend = (event: SpeechSynthesisEvent) => {
        console.log("TTS Player: EVENT onend fired. Utterance text:", (event.utterance as SpeechSynthesisUtterance)?.text?.substring(0,30)+"...");
        if (utteranceRef.current === event.utterance) {
          setIsSpeakingState(false);
          _clearPreviousUtterance();
        } else {
          console.warn("TTS Player: onend event for a STALE utterance.");
        }
      };

      newUtterance.onerror = (event: SpeechSynthesisErrorEvent) => {
        console.error(`TTS Player: EVENT onerror fired. Error: ${event.error}, Utterance charIndex: ${event.charIndex}, Utterance text:`, event.utterance?.text?.substring(0,30)+"...");
        if (utteranceRef.current === event.utterance) {
          if (event.error !== 'interrupted' && event.error !== 'canceled' && event.error !== 'not-allowed') {
            console.error(`Detailed speech error: type=${event.type}, error=${event.error}, charIndex=${event.charIndex}, elapsedTime=${event.elapsedTime}, name=${event.name}`);
          }
          setIsSpeakingState(false);
          _clearPreviousUtterance();
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
      
      speakTimeoutRef.current = setTimeout(() => {
        speakTimeoutRef.current = null; 
        if(synthRef.current && utteranceRef.current) { 
            console.log(`TTS Player: Before speak() call - synth.speaking: ${synthRef.current.speaking}, synth.pending: ${synthRef.current.pending}, synth.paused: ${synthRef.current.paused}`);
            console.log("TTS Player: Attempting to call synthRef.current.speak()");
            
            try {
              synthRef.current.speak(utteranceRef.current); 
              console.log("TTS Player: speak() call completed successfully");
            } catch (error) {
              console.error("TTS Player: Error calling speak():", error);
              setIsSpeakingState(false);
              return;
            }
            
            setTimeout(() => {
                if(synthRef.current) {
                    console.log(`TTS Player: After speak() call (100ms delay) - synth.speaking: ${synthRef.current.speaking}, synth.pending: ${synthRef.current.pending}, synth.paused: ${synthRef.current.paused}`);
                    if (!synthRef.current.speaking && !synthRef.current.pending && utteranceRef.current && utteranceRef.current.text.length > 0 && utteranceRef.current === newUtterance) {
                        console.warn("TTS Player: synth.speak() was called for current utterance, but synth is not speaking or pending. This might indicate a silent failure or an extremely short utterance that finished before the check.");
                        console.warn("TTS Player: Utterance details:", {
                          text: utteranceRef.current.text.substring(0, 100),
                          voice: utteranceRef.current.voice?.name,
                          lang: utteranceRef.current.lang,
                          rate: utteranceRef.current.rate
                        });
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
        _clearPreviousUtterance();
        synthRef.current.cancel(); 
        setIsSpeakingState(false);
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
        const speaking = synthRef.current?.speaking;
        const pending = synthRef.current?.pending;
        console.log(`TTS Player: isSpeaking() check: synth.speaking=${speaking}, synth.pending=${pending}, isSpeakingState=${isSpeakingState}`);
        if (speaking) return true; 
        return isSpeakingState; 
      },
      currentTextToSpeakRef: currentTextToSpeakRef
    }));

    const handleRateChange = (value: string) => {
      const rate = parseFloat(value);
      setPlaybackRate(rate);
      if ((synthRef.current?.speaking || synthRef.current?.paused || isSpeakingState) && currentTextToSpeakRef.current && currentTextToSpeakRef.current.trim()) {
        console.log("TTS Player: Rate changed while speaking/paused. Respeaking.");
        _speakText();
      }
    };
    
    const handleVoiceChange = (newVoiceURI: string) => {
      setSelectedVoiceURI(newVoiceURI);
      if ((synthRef.current?.speaking || synthRef.current?.paused || isSpeakingState) && currentTextToSpeakRef.current && currentTextToSpeakRef.current.trim()) {
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
    ];    return (
      <div className={cn("p-4 sm:p-6 space-y-4 bg-card text-card-foreground rounded-lg shadow-md border", className)}>        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
          {availableVoices.length > 0 ? (
            <div className="space-y-1">
              <Label htmlFor="voice-select-player-page" className="text-xs font-medium">
                Голос ({availableVoices.length} доступно):
              </Label>
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
          ) : (
            <div className="space-y-1">
              <Label className="text-xs font-medium text-muted-foreground">
                Голоса загружаются...
              </Label>
              <div className="text-xs text-muted-foreground bg-muted/30 p-2 rounded">
                Ожидание загрузки голосов браузера
              </div>
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
         {isSpeakingState && (
           <div className="text-center">
             <p className="text-xs text-primary animate-pulse font-medium">
               🔊 Воспроизведение...
             </p>
             <p className="text-xs text-muted-foreground mt-1">
               Нажмите на любой абзац для остановки или смены фрагмента
             </p>
           </div>
         )}
      </div>
    );
  }
);

TextToSpeechPlayer.displayName = 'TextToSpeechPlayer';

