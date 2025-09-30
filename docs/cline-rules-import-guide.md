# Cline Rules Import Guide - Security Testing Course

## Overview
This guide provides the necessary Cline rules and templates for importing and managing the Security Testing Course structure. These rules ensure consistent content creation, proper formatting, and adherence to established patterns.

## Core Cline Rules

### 1. Lesson Creation Rule

```yaml
name: "security-course-lesson"
description: "Create a new security testing course lesson"
pattern: "src/app/guidelines/module-{module}/lesson-{lesson}/page.tsx"
template: |
  'use client';

  import * as React from 'react';
  import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
  import { CodeBlock } from '@/components/content/CodeBlock';
  import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
  import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
  import Link from 'next/link';
  import { cn } from '@/lib/utils';
  import { FlaskConical, CheckCircle2, XCircle, ScrollText, BookOpen, KeyRound, ShieldAlert, Fingerprint, Target } from 'lucide-react';

  const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

  const sourcesData = [
    { id: 1, text: "Source 1", url: "https://example.com" },
    // Add more sources as needed
  ];

  const quizQuestions = [
    { 
      question: "Sample question?", 
      answers: ["Option A", "Option B", "Option C", "Option D"], 
      correctAnswerIndex: 0 
    },
    // Add more questions as needed
  ];

  interface QuizItemProps {
    question: string;
    answers: string[];
    correctAnswerIndex: number;
  }

  const QuizItem: React.FC<QuizItemProps> = ({ question, answers, correctAnswerIndex }) => {
    const [selectedAnswer, setSelectedAnswer] = React.useState<number | null>(null);

    const handleAnswerClick = (index: number) => {
      setSelectedAnswer(index);
    };

    const isAnswered = selectedAnswer !== null;

    return (
      <div className="mb-6 p-4 border rounded-lg bg-card shadow-sm">
        <p className="font-semibold text-foreground mb-3">{question}</p>
        <ul className="space-y-2">
          {answers.map((answer, index) => {
            const isCorrect = index === correctAnswerIndex;
            const isSelected = selectedAnswer === index;
            
            let itemClass = "cursor-pointer p-2 rounded-md transition-colors duration-200 border border-transparent";
            if (isAnswered) {
              if (isCorrect) {
                itemClass = cn(itemClass, "bg-green-100 dark:bg-green-900/30 border-green-500 text-green-800 dark:text-green-300 font-medium");
              } else if (isSelected) {
                itemClass = cn(itemClass, "bg-red-100 dark:bg-red-900/30 border-red-500 text-red-800 dark:text-red-300");
              } else {
                 itemClass = cn(itemClass, "text-muted-foreground");
              }
            } else {
              itemClass = cn(itemClass, "hover:bg-accent hover:text-accent-foreground");
            }

            return (
              <li
                key={index}
                onClick={() => !isAnswered && handleAnswerClick(index)}
                className={itemClass}
              >
                <span className="mr-2">{String.fromCharCode(97 + index)})</span>{answer}
                {isAnswered && isSelected && !isCorrect && (
                    <span className="text-xs ml-2 text-red-600 dark:text-red-400">(Неверно)</span>
                )}
                 {isAnswered && isCorrect && (
                    <span className="text-xs ml-2 text-green-700 dark:text-green-400 font-bold">(Правильный ответ)</span>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    );
  };

  export default function Module{module}Lesson{lesson}Page() {
    return (
      <ContentPageLayout
        title="Урок {lesson}: {LessonTitle}"
        subtitle="Модуль {module}: {ModuleTitle}"
      >
          <H2 id="theory">Теория</H2>
          <P>{TheoryContent}</P>
          
          <H2 id="demo">Демонстрация</H2>
          <Card className="my-6 border-accent/50">
              <CardHeader>
                  <CardTitle className="flex items-center text-accent-foreground">
                      <BookOpen className="mr-2 h-5 w-5" />
                      {DemoTitle}
                  </CardTitle>
                  <CardDescription>{DemoDescription}</CardDescription>
              </CardHeader>
              <CardContent>
                  <P><strong>Сценарий:</strong> {DemoScenario}</P>
                  <P><strong>Атака:</strong> {DemoAttack}</P>
                  <P><strong>Уязвимость:</strong> {DemoVulnerability}</P>
                  <P><strong>Защита:</strong> {DemoProtection}</P>
              </CardContent>
          </Card>

          <H2 id="practice">Практика</H2>
          <P>{PracticeDescription}</P>

          <H2 id="quiz">Тест</H2>
          <Card>
              <CardHeader>
                  <CardTitle>Тест по теме "{LessonTitle}"</CardTitle>
                  <CardDescription>Проверьте свои знания, выбрав правильный вариант ответа.</CardDescription>
              </CardHeader>
              <CardContent>
                  {quizQuestions.map((q, index) => (
                      <QuizItem key={index} {...q} />
                  ))}
              </CardContent>
          </Card>

          <H2 id="sources">Источники</H2>
          <ol className="list-decimal list-inside space-y-2 text-sm">
              {sourcesData.map(source => (
                  <li key={source.id} id={`source-${source.id}`}>
                      {source.url ? (
                          <Link href={source.url} target="_blank" rel="noopener noreferrer" className={LinkStyle}>{source.text}</Link>
                      ) : (
                          source.text
                      )}
                  </li>
              ))}
          </ol>

      </ContentPageLayout>
    );
  }
variables:
  - module: "Module number (1-4)"
  - lesson: "Lesson number within module"
  - LessonTitle: "Lesson title in Russian"
  - ModuleTitle: "Module title in Russian"
  - TheoryContent: "Theoretical content"
  - DemoTitle: "Demonstration case title"
  - DemoDescription: "Brief description of demo"
  - DemoScenario: "Attack scenario description"
  - DemoAttack: "Attack method description"
  - DemoVulnerability: "Vulnerability explanation"
  - DemoProtection: "Protection measures"
  - PracticeDescription: "Practice exercise description"
```

### 2. Navigation Update Rule

```yaml
name: "security-course-navigation"
description: "Update navigation when adding new content"
file: "src/constants/navigation.ts"
rule: |
  When adding new lessons or content:
  1. Always update the navigationLinks array
  2. Use appropriate Lucide React icons
  3. Maintain hierarchical structure
  4. Follow existing naming conventions
  5. Ensure href paths match actual file locations

pattern: |
  {
    href: '/guidelines/module-{n}/lesson-{n}',
    label: 'Урок {n}: {Title}',
    icon: {IconName}
  }
```

### 3. Content Validation Rules

```yaml
name: "security-course-validation"
description: "Validation rules for course content"
rules:
  - "All content must be in Russian language"
  - "External links must include target='_blank' and rel='noopener noreferrer'"
  - "Images must have descriptive alt text"
  - "Quiz questions must have exactly 4 answer options"
  - "All sections must use proper heading hierarchy (H2 -> H3)"
  - "Source references must be numbered and linked"
  - "Card components should use appropriate border colors"
  - "Icons should be from Lucide React library"
```

### 4. Asset Management Rules

```yaml
name: "security-course-assets"
description: "Rules for managing course assets"
image_paths:
  - "public/pics/{topic-category}/"
  - "Naming: descriptive-kebab-case.{ext}"
  - "Preferred formats: WebP, PNG, JPG"
source_materials:
  - "Location: sourse/ directory"
  - "Types: .md, .docx, .pdf files"
  - "Naming: descriptive titles in original language"
```

## Migration Templates

### Template for Chapter Import

```typescript
// Template for importing text chapters
export default function Chapter{n}Page() {
  return (
    <ContentPageLayout
      title="Глава {n}: {ChapterTitle}"
      subtitle="Основы тестирования веб-приложений на проникновение"
    >
      <H2 id="introduction">Введение</H2>
      <P>{IntroductionText}</P>
      
      <H2 id="content">Содержание</H2>
      {/* Chapter content sections */}
      
      <H2 id="summary">Заключение</H2>
      <P>{SummaryText}</P>
      
      <H2 id="sources">Источники</H2>
      {/* Reference list */}
    </ContentPageLayout>
  );
}
```

### Template for Wiki Page Import

```typescript
// Template for importing wiki pages
export default function Wiki{Topic}Page() {
  return (
    <ContentPageLayout
      title="{WikiTitle}"
      subtitle="Настройка и конфигурация инструментов"
    >
      <H2 id="overview">Обзор</H2>
      <P>{OverviewText}</P>
      
      <H2 id="installation">Установка</H2>
      {/* Installation steps */}
      
      <H2 id="configuration">Конфигурация</H2>
      {/* Configuration details */}
      
      <H2 id="usage">Использование</H2>
      {/* Usage examples */}
      
      <H2 id="troubleshooting">Решение проблем</H2>
      {/* Troubleshooting guide */}
    </ContentPageLayout>
  );
}
```

## Import Workflow

### Step 1: Preparation
1. Analyze existing content structure
2. Identify content type (lesson, chapter, wiki)
3. Prepare source materials in `sourse/` directory
4. Gather required images and assets

### Step 2: Content Creation
1. Use appropriate template based on content type
2. Apply Cline rules for consistent structure
3. Implement required sections (theory, demo, practice, quiz)
4. Add interactive components where needed

### Step 3: Integration
1. Update navigation in `src/constants/navigation.ts`
2. Add cross-references and links
3. Include source materials and references
4. Test component rendering and functionality

### Step 4: Validation
1. Run TypeScript type checking: `npm run typecheck`
2. Verify all links are functional
3. Check responsive design on different screen sizes
4. Validate quiz functionality and correct answers

## Content Standards Enforcement

### Mandatory Sections for Lessons
```typescript
const mandatorySections = [
  "theory",    // H2 id="theory"
  "demo",      // H2 id="demo" 
  "practice",  // H2 id="practice"
  "quiz",      // H2 id="quiz"
  "sources"    // H2 id="sources"
];
```

### Component Usage Standards
```typescript
// Typography standards
const typographyRules = {
  mainHeadings: "H2 with id attribute",
  subHeadings: "H3 for subsections",
  paragraphs: "P component for consistent spacing",
  lists: "Ul component with items array",
  externalLinks: "Link with security attributes"
};

// Interactive elements standards
const interactiveRules = {
  cards: "Card with appropriate border colors",
  quizzes: "QuizItem component with state management",
  codeBlocks: "CodeBlock component for syntax highlighting",
  tables: "Table components from UI library"
};
```

### Data Structure Standards
```typescript
// Source data structure
interface SourceData {
  id: number;
  text: string;
  url?: string; // Optional for external links
}

// Quiz question structure
interface QuizQuestion {
  question: string;
  answers: string[]; // Exactly 4 options
  correctAnswerIndex: number; // 0-3
}

// Navigation link structure
interface NavLink {
  href: string;
  label: string;
  icon?: LucideIcon;
  children?: NavLink[];
}
```

## Automation Scripts

### Content Generator Script
```bash
#!/bin/bash
# generate-lesson.sh
# Usage: ./generate-lesson.sh <module> <lesson> <title>

MODULE=$1
LESSON=$2
TITLE=$3

# Create directory structure
mkdir -p "src/app/guidelines/module-${MODULE}/lesson-${LESSON}"

# Generate page from template
cat > "src/app/guidelines/module-${MODULE}/lesson-${LESSON}/page.tsx" << EOF
// Generated lesson content using Cline rules
// Module: ${MODULE}, Lesson: ${LESSON}, Title: ${TITLE}
EOF

echo "Generated lesson structure for Module ${MODULE}, Lesson ${LESSON}"
```

### Navigation Updater Script
```javascript
// update-navigation.js
// Script to automatically update navigation when adding new content

const fs = require('fs');
const path = require('path');

function updateNavigation(module, lesson, title, icon = 'BookOpen') {
  const navPath = 'src/constants/navigation.ts';
  const navContent = fs.readFileSync(navPath, 'utf8');
  
  // Logic to insert new navigation item
  // Maintains hierarchical structure and proper formatting
  
  fs.writeFileSync(navPath, updatedContent);
  console.log(`Navigation updated for Module ${module}, Lesson ${lesson}`);
}
```

## Quality Assurance Checklist

### Pre-Import Validation
- [ ] Source materials properly organized in `sourse/` directory
- [ ] Images optimized and placed in appropriate `public/pics/` subdirectory
- [ ] Content translated to Russian if needed
- [ ] Quiz questions prepared with correct answers

### Post-Import Validation
- [ ] TypeScript compilation successful
- [ ] Navigation properly updated and functional
- [ ] All internal links work correctly
- [ ] External links open in new tabs with security attributes
- [ ] Responsive design works on mobile and desktop
- [ ] Quiz interactions function properly
- [ ] Source references are properly formatted and linked

### Performance Validation
- [ ] Images are properly optimized
- [ ] No console errors in browser
- [ ] Fast page load times
- [ ] Proper Next.js optimization applied

---

**Document Version**: 1.0  
**Compatible with**: Next.js 15.2.3, TypeScript, Tailwind CSS  
**Last Updated**: December 30, 2025  
**Usage**: Import existing content using Cline AI with consistent structure and formatting
