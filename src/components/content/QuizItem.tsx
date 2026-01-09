"use client";

import * as React from "react";
import { Card } from "@/components/ui/card";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { CheckCircle2, XCircle, ExternalLink, Lightbulb } from "lucide-react";

export interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
  explanation?: string;
  link?: {
    label: string;
    url: string;
  };
}

function shuffleArray<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

export function QuizItem({ question, answers, correctAnswerIndex, explanation, link }: QuizItemProps) {
  const [selected, setSelected] = React.useState<number | null>(null);
  const [checked, setChecked] = React.useState(false);

  // Shuffle answers once on mount
  const { shuffledAnswers, shuffledCorrectIndex } = React.useMemo(() => {
    const indices = answers.map((_, i) => i);
    const shuffledIndices = shuffleArray(indices);
    return {
      shuffledAnswers: shuffledIndices.map(i => answers[i]),
      shuffledCorrectIndex: shuffledIndices.indexOf(correctAnswerIndex)
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [question]); // Only reshuffle when question changes

  const isCorrect = checked && selected === shuffledCorrectIndex;
  const isIncorrect = checked && selected !== null && selected !== shuffledCorrectIndex;

  return (
    <Card className="p-4 mb-4">
      <div className="mb-3 font-medium">{question}</div>
      <RadioGroup
        value={selected !== null ? String(selected) : undefined}
        onValueChange={(v) => {
          setSelected(Number(v));
          setChecked(false);
        }}
        className="space-y-2"
      >
        {shuffledAnswers.map((ans, idx) => (
          <div key={idx} className="flex items-start space-x-2">
            <RadioGroupItem id={`q-${question}-${idx}`} value={String(idx)} className="mt-0.5" />
            <Label htmlFor={`q-${question}-${idx}`} className="leading-relaxed">{ans}</Label>
          </div>
        ))}
      </RadioGroup>
      <div className="mt-3 flex items-center gap-3">
        <Button size="sm" onClick={() => setChecked(true)} disabled={selected === null}>
          Проверить
        </Button>
        {isCorrect && (
          <span className="text-green-600 flex items-center gap-1">
            <CheckCircle2 className="h-4 w-4" /> Верно
          </span>
        )}
        {isIncorrect && (
          <span className="text-red-600 flex items-center gap-1">
            <XCircle className="h-4 w-4" /> Неверно
          </span>
        )}
      </div>

      {isCorrect && (explanation || link) && (
        <div className="mt-4 p-4 bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-lg">
          {explanation && (
            <div className="flex gap-2 mb-2">
              <Lightbulb className="h-5 w-5 text-green-600 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-green-800 dark:text-green-200">{explanation}</p>
            </div>
          )}
          {link && (
            <a
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-primary hover:underline mt-2"
            >
              <ExternalLink className="h-4 w-4" />
              {link.label}
            </a>
          )}
        </div>
      )}
    </Card>
  );
}

export default QuizItem;
