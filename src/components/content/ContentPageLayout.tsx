
import Image from 'next/image';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import type { ReactNode } from 'react';

interface ContentPageLayoutProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  imageUrl?: string;
  imageAlt?: string;
  imageAiHint?: string;
}

export function ContentPageLayout({
  title,
  subtitle,
  children,
  imageUrl,
  imageAlt = "Decorative image",
  imageAiHint = "abstract tech"
}: ContentPageLayoutProps) {
  return (
    <div className="container mx-auto py-8 px-4 md:px-6 lg:px-8">
      <Card className="overflow-hidden shadow-lg rounded-lg">
        <div className={imageUrl ? "md:flex" : ""}> {/* Apply md:flex only if imageUrl exists */}
          <div className={imageUrl ? "md:w-3/5 p-6 md:p-10" : "w-full p-6 md:p-10"}> {/* Adjust width */}
            <CardHeader className="px-0 pt-0 pb-4">
              <CardTitle className="text-3xl lg:text-4xl font-bold text-foreground mb-2">{title}</CardTitle>
              {subtitle && <CardDescription className="text-lg text-muted-foreground">{subtitle}</CardDescription>}
            </CardHeader>
            <hr className="my-6 border-accent" />
            <CardContent className="px-0 text-base md:text-lg space-y-6 text-foreground/90">
              {children}
            </CardContent>
          </div>
          {imageUrl && ( // This block will not render if imageUrl is undefined
            <div className="md:w-2/5 p-6 md:p-10 bg-secondary/50 flex items-center justify-center">
              <Image
                src={imageUrl}
                alt={imageAlt}
                width={400}
                height={400}
                className="rounded-lg shadow-md object-cover aspect-square"
                data-ai-hint={imageAiHint}
              />
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

// Helper component for rendering paragraphs with improved spacing
export function P({ children }: { children: ReactNode }) {
  return <p className="mb-4 leading-relaxed">{children}</p>;
}

// Helper component for rendering lists
export function Ul({ items }: { items: ReactNode[] }) {
  return (
    <ul className="list-disc list-outside space-y-2 pl-5 mb-4">
      {items.map((item, index) => (
        <li key={index} className="text-foreground/80">{item}</li>
      ))}
    </ul>
  );
}

// Helper component for subheadings
export function H2({ children }: { children: ReactNode }) {
  return <h2 className="text-2xl font-semibold text-primary mt-8 mb-4">{children}</h2>;
}

export function H3({ children }: { children: ReactNode }) {
  return <h3 className="text-xl font-semibold text-accent-foreground mt-6 mb-3">{children}</h3>;
}
