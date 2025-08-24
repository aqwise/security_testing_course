"use client";

import * as React from "react";
import { Card } from "@/components/ui/card";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { CheckCircle2, XCircle } from "lucide-react";

export interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
}

export function QuizItem({ question, answers, correctAnswerIndex }: QuizItemProps) {
  const [selected, setSelected] = React.useState<number | null>(null);
  const [checked, setChecked] = React.useState(false);

  const isCorrect = checked && selected === correctAnswerIndex;
  const isIncorrect = checked && selected !== null && selected !== correctAnswerIndex;

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
        {answers.map((ans, idx) => (
          <div key={idx} className="flex items-center space-x-2">
            <RadioGroupItem id={`q-${question}-${idx}`} value={String(idx)} />
            <Label htmlFor={`q-${question}-${idx}`}>{ans}</Label>
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
    </Card>
  );
}

export default QuizItem;

