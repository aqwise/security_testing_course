# Security Testing Course - Comprehensive Structure Documentation

## Overview
This document provides comprehensive documentation of the Security Testing Course structure, designed to facilitate future importing and rule-based content management with Cline.

**Project Type**: Next.js 15.2.3 Web Application  
**Content Language**: Russian  
**Target Audience**: Security Testing Professionals  
**Course Structure**: Modular approach with interactive elements  

## Project Architecture

### Core Technologies
- **Framework**: Next.js 15.2.3 with TypeScript
- **UI Framework**: Tailwind CSS + Radix UI components
- **AI Integration**: Google AI Genkit for content generation
- **Development**: Turbopack for fast development builds
- **Port**: Development server runs on port 9002

### Directory Structure

```
security_testing_course/
├── docs/                           # Documentation directory
│   └── blueprint.md               # Project blueprint
├── public/                        # Static assets
│   ├── interactive-chapters/      # Interactive HTML content
│   ├── lessons/                   # Static lesson files
│   └── pics/                      # Image assets
│       ├── mobsf-setup/          # MobSF configuration images
│       └── owasp-installation/   # OWASP ZAP setup images
├── sourse/                        # Source materials (typo in original)
│   ├── links.md                  # PortSwigger lab links
│   ├── *.docx                    # Word documents
│   ├── *.md                      # Markdown source files
│   └── *.pdf                     # PDF materials
├── src/                          # Application source code
│   ├── ai/                       # AI integration components
│   ├── app/                      # Next.js app directory
│   ├── components/               # React components
│   ├── constants/                # Configuration constants
│   ├── hooks/                    # Custom React hooks
│   ├── lib/                      # Utility libraries
│   └── utils/                    # Utility functions
└── tools/                        # Development tools
```

## Content Organization

### Module Structure
The course is organized into 4 main modules with hierarchical navigation:

#### Module I: Основы (Foundations)
- **Purpose**: Basic security testing setup and fundamental concepts
- **Lessons**: 
  1. Лаборатория (Laboratory Setup)
  2. DVWA (Damn Vulnerable Web Application)
  3. Juice Shop (OWASP Juice Shop)
  4. SQL-инъекции (SQL Injections)

#### Module II: Разведка (Reconnaissance)
- **Purpose**: Information gathering and reconnaissance techniques
- **Lessons**:
  1. Механизмы Защиты (Defense Mechanisms)

#### Module III: Аутентификация и сессии (Authentication & Sessions)
- **Purpose**: Authentication and session management attacks
- **Lessons**:
  1. Атака на Аутентификацию (Authentication Attacks)
  2. Атака на Сессии (Session Attacks)
  3. Атаки на Контроль Доступа (Access Control Attacks)

#### Module IV: Серверные Уязвимости (Server-side Vulnerabilities)
- **Purpose**: Server-side vulnerability exploitation
- **Lessons**:
  1. Атака на хранилища данных (Data Storage Attacks)

### Additional Content Sections

#### Text Chapters (1-7)
- **Path**: `/text-chapter/chapter-{n}/`
- **Purpose**: Theoretical content based on "The Web Application Hacker's Handbook"
- **Format**: Structured lessons with consistent layout

#### Interactive Chapters
- **Path**: `/interactive/chapter-{n}/`
- **Purpose**: Hands-on interactive content
- **Format**: Dynamic components with practical exercises

#### Wiki Sections
- **Path**: `/wiki/{topic}/`
- **Available Topics**:
  - `devsecops-tools` - AppSec Tools (SafeCode)
  - `owasp-zap-setup` - OWASP ZAP Configuration
  - `mobsf-setup` - Mobile Security Framework Setup
  - `modern-webapp-security` - Modern Web Application Security (Video)

## File Naming Conventions

### Route Structure
```
/app/{section}/{module-n?}/{lesson-n?}/page.tsx
```

**Examples**:
- `/app/guidelines/module-3/lesson-3/page.tsx`
- `/app/text-chapter/chapter-7/page.tsx`
- `/app/wiki/mobsf-setup/page.tsx`

### Component Organization
```
/components/{category}/{specific-component}.tsx
```

**Categories**:
- `content/` - Content-specific components
- `interactive/` - Interactive lesson components  
- `layout/` - Layout and navigation components
- `ui/` - Reusable UI components

### Asset Organization
```
/public/pics/{topic-category}/filename.{ext}
```

**Examples**:
- `/public/pics/mobsf-setup/architecture-diagram.jpg`
- `/public/pics/owasp-installation/screenshot-2025-07-03-183340.png`

## Content Patterns

### Standard Lesson Structure
Each lesson follows a consistent pattern implemented in `ContentPageLayout`:

```tsx
export default function ModuleXLessonY() {
  return (
    <ContentPageLayout
      title="Урок X: {Topic}"
      subtitle="Модуль Y: {Module Description}"
    >
      <H2 id="theory">Теория</H2>
      {/* Theoretical content */}
      
      <H2 id="demo">Демонстрация</H2>
      {/* Demonstration cases */}
      
      <H2 id="practice">Практика</H2>
      {/* Practical exercises */}
      
      <H2 id="quiz">Тест</H2>
      {/* Knowledge assessment */}
      
      <H2 id="sources">Источники</H2>
      {/* References and sources */}
    </ContentPageLayout>
  );
}
```

### Component Usage Patterns

#### Typography Components
```tsx
// Main headings
<H2 id="section-id">Section Title</H2>
<H3>Subsection Title</H3>

// Paragraphs
<P>Content paragraph with proper spacing</P>

// Lists
<Ul items={[
  "First item",
  "Second item with JSX content",
  <>Third item with <Link>embedded links</Link></>
]} />
```

#### Interactive Components
```tsx
// Quiz implementation
const QuizItem: React.FC<QuizItemProps> = ({ 
  question, 
  answers, 
  correctAnswerIndex 
}) => {
  // Component logic for quiz interactions
};

// Card layouts for demos
<Card className="my-6 border-accent/50">
  <CardHeader>
    <CardTitle className="flex items-center text-accent-foreground">
      <BookOpen className="mr-2 h-5 w-5" />
      Case Study Title
    </CardTitle>
  </CardHeader>
  <CardContent>
    {/* Case study content */}
  </CardContent>
</Card>
```

#### External Links Pattern
```tsx
const LinkStyle = "text-primary hover:text-primary/80 hover:underline";

<Link 
  href="https://external-url.com" 
  target="_blank" 
  rel="noopener noreferrer" 
  className={LinkStyle}
>
  Link Text
</Link>
```

## Data Structures

### Navigation Configuration
**File**: `src/constants/navigation.ts`

```typescript
export interface NavLink {
  href: string;
  label: string;
  icon?: LucideIcon;
  children?: NavLink[];
}

export const navigationLinks: NavLink[] = [
  // Hierarchical navigation structure
];
```

### Content Data Patterns
```typescript
// Quiz data structure
interface QuizQuestion {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
}

// Source references
interface SourceData {
  id: number;
  text: string;
  url?: string; // Optional for external references
}
```

## Integration Points

### AI Content Generation
- **Location**: `src/ai/`
- **Purpose**: Automated content generation using Google AI
- **Flows**: 
  - `generate-content-block.ts` - Generate content sections
  - `generate-intro-screen.ts` - Generate introduction content

### External Integrations
- **PortSwigger Labs**: Direct links to Web Security Academy
- **OWASP Tools**: Integration guides for ZAP and other tools
- **Mobile Security**: MobSF configuration and setup

## Migration Guidelines

### For Cline Rule Implementation

#### 1. Content Creation Rules
```typescript
// Rule for creating new lessons
const lessonCreationRule = {
  pattern: "/app/guidelines/module-{n}/lesson-{n}/page.tsx",
  structure: {
    imports: ["ContentPageLayout", "components"],
    sections: ["theory", "demo", "practice", "quiz", "sources"],
    components: ["H2", "H3", "P", "Ul", "Card", "QuizItem"]
  }
};
```

#### 2. File Naming Rules
```typescript
const fileNamingRules = {
  lessons: "module-{n}/lesson-{n}/page.tsx",
  chapters: "chapter-{n}/page.tsx", 
  wiki: "{topic-slug}/page.tsx",
  images: "{topic-category}/{descriptive-name}.{ext}"
};
```

#### 3. Content Standards
- **Language**: All content in Russian
- **Icons**: Lucide React icons for consistency
- **Spacing**: Consistent use of Tailwind spacing classes
- **Links**: External links with proper security attributes
- **Images**: WebP format preferred, descriptive alt text required

## Development Workflow

### Adding New Content
1. **Create lesson structure** in appropriate module directory
2. **Update navigation** in `src/constants/navigation.ts`
3. **Add source materials** to `sourse/` directory
4. **Include images** in relevant `public/pics/` subdirectory
5. **Implement quiz** if applicable
6. **Update references** and cross-links

### Content Validation
- TypeScript type checking with `npm run typecheck`
- Consistent component usage patterns
- Proper accessibility attributes
- External link validation

## Future Considerations

### Extensibility
- Modular component structure allows easy addition of new content types
- AI integration enables automated content generation
- Consistent patterns facilitate rule-based content creation

### Maintenance
- Source materials in `sourse/` directory for easy updates
- Centralized navigation configuration
- Reusable component patterns reduce maintenance overhead

### Performance
- Next.js optimization with Turbopack
- Static generation capabilities
- Optimized image loading with Next.js Image component

---

**Document Version**: 1.0  
**Last Updated**: December 30, 2025  
**Prepared for**: Cline AI Rule Integration  
**Author**: Course Structure Analysis System
