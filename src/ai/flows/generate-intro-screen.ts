'use server';

/**
 * @fileOverview A flow to generate intro screen content based on a given description.
 *
 * - generateIntroScreen - A function that handles the generation of intro screen content.
 * - GenerateIntroScreenInput - The input type for the generateIntroScreen function.
 * - GenerateIntroScreenOutput - The return type for the generateIntroScreen function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const GenerateIntroScreenInputSchema = z.object({
  description: z
    .string()
    .describe('The description of the content to be displayed on the intro screen.'),
});
export type GenerateIntroScreenInput = z.infer<typeof GenerateIntroScreenInputSchema>;

const GenerateIntroScreenOutputSchema = z.object({
  title: z.string().describe('The main title for the intro screen.'),
  subtitle: z.string().describe('The subtitle or supporting information for the intro screen.'),
  accentElement: z
    .string()
    .describe('A brief description of the accent element to visually balance the intro screen.'),
  backgroundDescription: z
    .string()
    .describe('Description of the background, including textures, forms, and gradients.'),
  decorativeMotif: z
    .string()
    .describe('Description of the decorative motif used for branding, e.g., stepped arrows.'),
});

export type GenerateIntroScreenOutput = z.infer<typeof GenerateIntroScreenOutputSchema>;

export async function generateIntroScreen(
  input: GenerateIntroScreenInput
): Promise<GenerateIntroScreenOutput> {
  return generateIntroScreenFlow(input);
}

const prompt = ai.definePrompt({
  name: 'generateIntroScreenPrompt',
  input: {schema: GenerateIntroScreenInputSchema},
  output: {schema: GenerateIntroScreenOutputSchema},
  prompt: `You are an expert in designing intro screens for web applications based on Material Design principles.

  Based on the description of the content, create compelling elements for an intro screen.

  Description: {{{description}}}

  Consider the following guidelines for Material Design:
  - Use a primary color like Deep sky blue (#41A7D3) for a clean and modern feel.
  - Use a light gray background (#F0F4F7) to provide a neutral backdrop that supports readability.
  - Use an accent color like Light Blue (#83D6F2) to subtly highlight interactive elements.
  - Employ Roboto or a similar sans-serif font for clear and accessible typography.
  - Use structured grids and whitespace to ensure content is easy to scan and navigate.
  - Employ minimalist icons that adhere to Material Design principles, enhancing UI clarity.
  - Use subtle, tasteful animations for transitions and interactions.

  Based on the provided description, generate:
  - title: A main title that is engaging and informative.
  - subtitle: Supporting information like date and author, left-aligned and smaller font size.
  - accentElement: Description of a thin line or element to balance the text blocks.
  - backgroundDescription: Description of the background including textures, forms, and gradients.
  - decorativeMotif: Description of a repeating branding component like stepped arrows.
  `,
});

const generateIntroScreenFlow = ai.defineFlow(
  {
    name: 'generateIntroScreenFlow',
    inputSchema: GenerateIntroScreenInputSchema,
    outputSchema: GenerateIntroScreenOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    return output!;
  }
);
