
import type { ReactNode } from 'react';

interface CodeBlockProps {
  language?: string;
  code: string;
  className?: string;
}

export function CodeBlock({ language, code, className }: CodeBlockProps) {
  return (
    <pre className={`bg-muted p-4 rounded-md overflow-x-auto my-4 ${className}`}>
      <code className={language ? `language-${language}` : ''}>
        {code.trim()}
      </code>
    </pre>
  );
}
