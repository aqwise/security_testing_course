# Migration Guide for Old Course Structure

## Overview
This guide provides step-by-step instructions for migrating content from old or legacy course structures to the standardized Security Testing Course format. It includes data transformation rules, content restructuring guidelines, and validation procedures.

## Pre-Migration Assessment

### Current Structure Analysis
Before migrating, assess the existing content structure:

```bash
# Analyze existing content structure
find . -name "*.tsx" -o -name "*.md" -o -name "*.docx" -o -name "*.pdf" | sort

# Check for naming inconsistencies
find . -name "*[Мм]одуль*" -o -name "*[Уу]рок*" -o -name "*[Лл]екци*" | sort

# Identify asset locations
find . -name "*.jpg" -o -name "*.png" -o -name "*.gif" -o -name "*.webp" | sort
```

### Legacy Pattern Identification
Common legacy patterns to look for:

#### Old File Naming Patterns
```
❌ OLD PATTERNS TO MIGRATE:
- lesson_1.tsx
- module-1-lesson-1.tsx  
- Module1Lesson1.tsx
- урок-1.tsx
- m1l1.tsx

✅ NEW STANDARDIZED PATTERN:
- src/app/guidelines/module-1/lesson-1/page.tsx
```

#### Old Component Patterns
```tsx
// ❌ OLD PATTERN - Direct HTML elements
export default function OldLesson() {
  return (
    <div>
      <h1>Title</h1>
      <p>Content</p>
      <ul>
        <li>Item 1</li>
        <li>Item 2</li>
      </ul>
    </div>
  );
}

// ✅ NEW PATTERN - Standardized components
export default function NewLesson() {
  return (
    <ContentPageLayout title="Title" subtitle="Subtitle">
      <H2 id="section">Section</H2>
      <P>Content paragraph</P>
      <Ul items={["Item 1", "Item 2"]} />
    </ContentPageLayout>
  );
}
```

## Migration Process

### Phase 1: Content Inventory and Preparation

#### Step 1: Create Content Inventory
```bash
# Create migration inventory script
cat > migration-inventory.sh << 'EOF'
#!/bin/bash
echo "=== MIGRATION INVENTORY ===" > migration-report.txt
echo "Generated: $(date)" >> migration-report.txt
echo "" >> migration-report.txt

echo "## EXISTING CONTENT FILES ##" >> migration-report.txt
find . -name "*.tsx" -path "*/app/*" | sort >> migration-report.txt
echo "" >> migration-report.txt

echo "## SOURCE MATERIALS ##" >> migration-report.txt
find . -name "*.md" -o -name "*.docx" -o -name "*.pdf" | sort >> migration-report.txt
echo "" >> migration-report.txt

echo "## IMAGES AND ASSETS ##" >> migration-report.txt
find . -name "*.jpg" -o -name "*.png" -o -name "*.gif" -o -name "*.webp" | sort >> migration-report.txt
echo "" >> migration-report.txt

echo "## OUTDATED PATTERNS ##" >> migration-report.txt
grep -r "export default function.*Lesson" --include="*.tsx" . >> migration-report.txt
EOF

chmod +x migration-inventory.sh
./migration-inventory.sh
```

#### Step 2: Backup Existing Content
```bash
# Create backup before migration
mkdir -p migration-backup/$(date +%Y%m%d_%H%M%S)
cp -r src/ migration-backup/$(date +%Y%m%d_%H%M%S)/
cp -r public/ migration-backup/$(date +%Y%m%d_%H%M%S)/
cp -r sourse/ migration-backup/$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
```

### Phase 2: Structure Standardization

#### Step 1: Directory Structure Migration
```bash
#!/bin/bash
# migrate-structure.sh - Migrate to standardized directory structure

# Create new directory structure
mkdir -p src/app/guidelines/{module-1,module-2,module-3,module-4}
mkdir -p src/app/text-chapter/{chapter-1,chapter-2,chapter-3,chapter-4,chapter-5,chapter-6,chapter-7}
mkdir -p src/app/wiki/{devsecops-tools,owasp-zap-setup,mobsf-setup,modern-webapp-security}
mkdir -p src/app/interactive/chapter-1
mkdir -p public/pics/{mobsf-setup,owasp-installation}
mkdir -p sourse

# Function to migrate lesson files
migrate_lesson_file() {
    local old_file=$1
    local module=$2
    local lesson=$3
    
    # Create lesson directory
    mkdir -p "src/app/guidelines/module-${module}/lesson-${lesson}"
    
    # Copy and rename file
    cp "$old_file" "src/app/guidelines/module-${module}/lesson-${lesson}/page.tsx"
    
    echo "Migrated: $old_file -> src/app/guidelines/module-${module}/lesson-${lesson}/page.tsx"
}

# Example usage:
# migrate_lesson_file "old-lessons/lesson1.tsx" "1" "1"
```

#### Step 2: File Content Migration
```javascript
// migrate-content.js - Content transformation script
const fs = require('fs');
const path = require('path');

class ContentMigrator {
  constructor() {
    this.transformations = {
      // Component imports transformation
      imports: {
        old: /import.*from.*['"]react['"];?/g,
        new: `import * as React from 'react';
import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import Link from 'next/link';`
      },
      
      // HTML to component transformation
      htmlToComponents: [
        { old: /<h1>(.*?)<\/h1>/g, new: '<H2 id="section">$1</H2>' },
        { old: /<h2>(.*?)<\/h2>/g, new: '<H3>$1</H3>' },
        { old: /<p>(.*?)<\/p>/g, new: '<P>$1</P>' },
        { old: /<div className="container">(.*?)<\/div>/gs, new: '<ContentPageLayout title="Title" subtitle="Subtitle">$1</ContentPageLayout>' }
      ],
      
      // Function name standardization
      functionName: {
        old: /export default function (\w+)\(\)/g,
        new: 'export default function Module$1Lesson$2Page()'
      }
    };
  }

  migrateFile(filePath, targetPath, options = {}) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Apply transformations
    content = this.applyTransformations(content, options);
    
    // Write migrated content
    fs.writeFileSync(targetPath, content);
    
    console.log(`Migrated: ${filePath} -> ${targetPath}`);
  }

  applyTransformations(content, options) {
    // Apply import transformations
    content = content.replace(this.transformations.imports.old, this.transformations.imports.new);
    
    // Apply HTML to component transformations
    this.transformations.htmlToComponents.forEach(transform => {
      content = content.replace(transform.old, transform.new);
    });
    
    // Apply function name standardization
    if (options.module && options.lesson) {
      content = content.replace(
        this.transformations.functionName.old,
        `export default function Module${options.module}Lesson${options.lesson}Page()`
      );
    }
    
    return content;
  }
}

// Usage example:
const migrator = new ContentMigrator();
migrator.migrateFile(
  'old-lessons/lesson1.tsx', 
  'src/app/guidelines/module-1/lesson-1/page.tsx',
  { module: 1, lesson: 1 }
);
```

### Phase 3: Content Structure Migration

#### Quiz Migration Template
```typescript
// quiz-migrator.ts - Migrate old quiz formats to new structure
interface OldQuizFormat {
  q: string;
  options: string[];
  correct: number;
}

interface NewQuizFormat {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
}

function migrateQuizData(oldQuizzes: OldQuizFormat[]): NewQuizFormat[] {
  return oldQuizzes.map(quiz => ({
    question: quiz.q,
    answers: quiz.options,
    correctAnswerIndex: quiz.correct
  }));
}

// Migration script for quiz components
function migrateQuizComponent(oldContent: string): string {
  return `
const quizQuestions = [
  ${migrateQuizData(extractOldQuizzes(oldContent))
    .map(q => `{ question: "${q.question}", answers: ${JSON.stringify(q.answers)}, correctAnswerIndex: ${q.correctAnswerIndex} }`)
    .join(',\n  ')}
];

interface QuizItemProps {
  question: string;
  answers: string[];
  correctAnswerIndex: number;
}

const QuizItem: React.FC<QuizItemProps> = ({ question, answers, correctAnswerIndex }) => {
  // Standard QuizItem implementation
  const [selectedAnswer, setSelectedAnswer] = React.useState<number | null>(null);
  // ... rest of QuizItem component
};
`;
}
```

#### Navigation Migration
```typescript
// navigation-migrator.ts - Migrate old navigation to new structure
interface OldNavItem {
  path: string;
  title: string;
  icon?: string;
}

interface NewNavItem {
  href: string;
  label: string;
  icon?: LucideIcon;
  children?: NewNavItem[];
}

function migrateNavigation(oldNav: OldNavItem[]): NewNavItem[] {
  return oldNav.map(item => ({
    href: standardizePath(item.path),
    label: translateTitle(item.title),
    icon: mapIcon(item.icon),
    children: item.children ? migrateNavigation(item.children) : undefined
  }));
}

function standardizePath(oldPath: string): string {
  // Convert old paths to new format
  return oldPath
    .replace(/lesson(\d+)/g, 'lesson-$1')
    .replace(/module(\d+)/g, 'module-$1')
    .replace(/^\//, '/guidelines/');
}

function translateTitle(title: string): string {
  // Ensure consistent Russian titles
  const translations = {
    'Lesson': 'Урок',
    'Module': 'Модуль',
    'Chapter': 'Глава'
  };
  
  return Object.entries(translations).reduce(
    (result, [en, ru]) => result.replace(new RegExp(en, 'g'), ru),
    title
  );
}
```

### Phase 4: Asset Migration

#### Image Migration
```bash
#!/bin/bash
# migrate-images.sh - Migrate and organize images

# Function to migrate images to standardized paths
migrate_images() {
    local source_dir=$1
    local topic_category=$2
    
    # Create target directory
    mkdir -p "public/pics/${topic_category}"
    
    # Find and migrate images
    find "$source_dir" -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" -o -name "*.webp" \) | while read img; do
        # Get filename and convert to kebab-case
        filename=$(basename "$img")
        new_filename=$(echo "$filename" | sed 's/[[:space:]]/-/g' | tr '[:upper:]' '[:lower:]')
        
        # Copy to new location
        cp "$img" "public/pics/${topic_category}/${new_filename}"
        
        echo "Migrated image: $img -> public/pics/${topic_category}/${new_filename}"
    done
}

# Usage examples:
migrate_images "old-images/mobsf" "mobsf-setup"
migrate_images "old-images/owasp" "owasp-installation"
migrate_images "old-images/screenshots" "general"
```

#### Source Material Migration
```bash
#!/bin/bash
# migrate-sources.sh - Migrate source materials

# Create sourse directory (maintaining original typo for consistency)
mkdir -p sourse

# Migrate various source formats
migrate_source_materials() {
    # Find and migrate markdown files
    find . -name "*.md" -not -path "./sourse/*" -not -path "./docs/*" | while read md_file; do
        cp "$md_file" "sourse/"
        echo "Migrated: $md_file -> sourse/"
    done
    
    # Find and migrate Word documents
    find . -name "*.docx" -not -path "./sourse/*" | while read docx_file; do
        cp "$docx_file" "sourse/"
        echo "Migrated: $docx_file -> sourse/"
    done
    
    # Find and migrate PDF files
    find . -name "*.pdf" -not -path "./sourse/*" | while read pdf_file; do
        cp "$pdf_file" "sourse/"
        echo "Migrated: $pdf_file -> sourse/"
    done
}

migrate_source_materials
```

## Post-Migration Validation

### Automated Validation Script
```bash
#!/bin/bash
# validate-migration.sh - Validate migrated content

echo "=== MIGRATION VALIDATION REPORT ===" > validation-report.txt
echo "Generated: $(date)" >> validation-report.txt
echo "" >> validation-report.txt

# Check directory structure
echo "## DIRECTORY STRUCTURE VALIDATION ##" >> validation-report.txt
expected_dirs=(
    "src/app/guidelines/module-1"
    "src/app/guidelines/module-2" 
    "src/app/guidelines/module-3"
    "src/app/guidelines/module-4"
    "src/app/text-chapter"
    "src/app/wiki"
    "public/pics"
    "sourse"
)

for dir in "${expected_dirs[@]}"; do
    if [ -d "$dir" ]; then
        echo "✅ $dir exists" >> validation-report.txt
    else
        echo "❌ $dir missing" >> validation-report.txt
    fi
done

# Check file naming conventions
echo "" >> validation-report.txt
echo "## FILE NAMING VALIDATION ##" >> validation-report.txt
find src/app/guidelines -name "*.tsx" | while read file; do
    if [[ $file =~ src/app/guidelines/module-[0-9]+/lesson-[0-9]+/page\.tsx ]]; then
        echo "✅ $file follows naming convention" >> validation-report.txt
    else
        echo "❌ $file does not follow naming convention" >> validation-report.txt
    fi
done

# Check component imports
echo "" >> validation-report.txt
echo "## COMPONENT IMPORT VALIDATION ##" >> validation-report.txt
grep -r "import.*ContentPageLayout" src/app/ | wc -l > temp_count.txt
imported_count=$(cat temp_count.txt)
echo "ContentPageLayout imported in $imported_count files" >> validation-report.txt
rm temp_count.txt

# Check TypeScript compilation
echo "" >> validation-report.txt
echo "## TYPESCRIPT COMPILATION ##" >> validation-report.txt
if npm run typecheck > /dev/null 2>&1; then
    echo "✅ TypeScript compilation successful" >> validation-report.txt
else
    echo "❌ TypeScript compilation failed" >> validation-report.txt
    npm run typecheck >> validation-report.txt 2>&1
fi

echo "Validation complete. Check validation-report.txt for details."
```

### Manual Validation Checklist

#### Content Structure Validation
- [ ] All lessons follow the standard 5-section structure (theory, demo, practice, quiz, sources)
- [ ] Navigation hierarchy is properly maintained
- [ ] All internal links point to correct locations
- [ ] External links include proper security attributes
- [ ] Images have appropriate alt text and are properly sized

#### Component Usage Validation
- [ ] `ContentPageLayout` is used for all main content pages
- [ ] Typography components (`H2`, `H3`, `P`, `Ul`) are used consistently
- [ ] Interactive components (`QuizItem`, `Card`) follow standard patterns
- [ ] Icon usage is consistent (Lucide React icons only)

#### Technical Validation
- [ ] TypeScript compilation passes without errors
- [ ] All imports resolve correctly
- [ ] No console errors in browser
- [ ] Responsive design works on all screen sizes
- [ ] Performance metrics are acceptable

## Rollback Procedures

### Emergency Rollback
```bash
#!/bin/bash
# rollback-migration.sh - Emergency rollback procedure

BACKUP_DIR="migration-backup/$(ls migration-backup/ | tail -n 1)"

if [ -d "$BACKUP_DIR" ]; then
    echo "Rolling back to backup: $BACKUP_DIR"
    
    # Stop development server if running
    pkill -f "next dev" || true
    
    # Restore from backup
    rm -rf src/
    rm -rf public/
    rm -rf sourse/
    
    cp -r "$BACKUP_DIR/src" .
    cp -r "$BACKUP_DIR/public" .
    cp -r "$BACKUP_DIR/sourse" . 2>/dev/null || true
    
    echo "Rollback completed. Restart development server."
else
    echo "No backup found for rollback!"
    exit 1
fi
```

### Selective Rollback
```bash
#!/bin/bash
# selective-rollback.sh - Rollback specific components

rollback_file() {
    local file_path=$1
    local backup_dir="migration-backup/$(ls migration-backup/ | tail -n 1)"
    
    if [ -f "$backup_dir/$file_path" ]; then
        cp "$backup_dir/$file_path" "$file_path"
        echo "Rolled back: $file_path"
    else
        echo "Backup not found for: $file_path"
    fi
}

# Usage: rollback_file "src/app/guidelines/module-1/lesson-1/page.tsx"
```

## Common Migration Issues and Solutions

### Issue 1: Import Resolution Errors
```
Error: Module not found: Can't resolve '@/components/content/ContentPageLayout'
```

**Solution:**
```bash
# Check if all required components exist
ls -la src/components/content/ContentPageLayout.tsx
ls -la src/components/content/CodeBlock.tsx

# Update tsconfig.json paths if needed
cat > tsconfig-paths.json << 'EOF'
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
EOF
```

### Issue 2: Russian Character Encoding
```
Error: Invalid character encoding in content
```

**Solution:**
```bash
# Convert files to UTF-8 encoding
find src/ -name "*.tsx" -exec file {} \; | grep -v UTF-8 | while read line; do
    file_path=$(echo "$line" | cut -d: -f1)
    iconv -f CP1251 -t UTF-8 "$file_path" > "$file_path.utf8"
    mv "$file_path.utf8" "$file_path"
    echo "Converted encoding: $file_path"
done
```

### Issue 3: Navigation Structure Conflicts
```
Error: Duplicate navigation entries or incorrect hierarchy
```

**Solution:**
```typescript
// navigation-fix.ts - Fix navigation structure issues
const fixNavigation = () => {
  // Remove duplicates
  const uniqueLinks = navigationLinks.filter((link, index, self) => 
    index === self.findIndex(l => l.href === link.href)
  );
  
  // Sort by module and lesson numbers
  return uniqueLinks.sort((a, b) => {
    const aMatch = a.href.match(/module-(\d+)\/lesson-(\d+)/);
    const bMatch = b.href.match(/module-(\d+)\/lesson-(\d+)/);
    
    if (aMatch && bMatch) {
      const [, aModule, aLesson] = aMatch;
      const [, bModule, bLesson] = bMatch;
      
      if (aModule !== bModule) {
        return parseInt(aModule) - parseInt(bModule);
      }
      return parseInt(aLesson) - parseInt(bLesson);
    }
    
    return a.href.localeCompare(b.href);
  });
};
```

## Migration Timeline

### Recommended Migration Schedule
```
Week 1: Assessment and Preparation
- Day 1-2: Content inventory and structure analysis
- Day 3-4: Backup creation and tool preparation
- Day 5-7: Test migration on small subset

Week 2: Core Migration
- Day 1-3: Directory structure migration
- Day 4-5: Content file migration
- Day 6-7: Component standardization

Week 3: Validation and Refinement
- Day 1-3: Automated validation and fixes
- Day 4-5: Manual testing and quality assurance
- Day 6-7: Performance optimization and final checks

Week 4: Deployment and Documentation
- Day 1-2: Production deployment preparation
- Day 3-4: Documentation updates
- Day 5-7: Team training and knowledge transfer
```

---

**Document Version**: 1.0  
**Compatible with**: Next.js 15.2.3, TypeScript, Tailwind CSS  
**Last Updated**: December 30, 2025  
**Usage**: Migrate legacy course content to standardized structure with Cline AI assistance
