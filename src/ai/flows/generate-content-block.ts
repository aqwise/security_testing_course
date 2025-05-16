'use server';
/**
 * @fileOverview A content block generator AI agent.
 *
 * - generateContentBlock - A function that handles the content block generation process.
 * - GenerateContentBlockInput - The input type for the generateContentBlock function.
 * - GenerateContentBlockOutput - The return type for the generateContentBlock function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const GenerateContentBlockInputSchema = z.object({
  prompt: z.string().describe('A prompt describing the content block to generate.'),
});
export type GenerateContentBlockInput = z.infer<typeof GenerateContentBlockInputSchema>;

const GenerateContentBlockOutputSchema = z.object({
  title: z.string().describe('The title of the content block.'),
  subtitle: z.string().optional().describe('The subtitle of the content block.'),
  content: z.string().describe('The main content of the content block, including a bulleted list and a concluding paragraph.'),
  imageUrl: z.string().describe('A data URI containing a base64-encoded image for the content block illustration.'),
});
export type GenerateContentBlockOutput = z.infer<typeof GenerateContentBlockOutputSchema>;

export async function generateContentBlock(input: GenerateContentBlockInput): Promise<GenerateContentBlockOutput> {
  return generateContentBlockFlow(input);
}

const prompt = ai.definePrompt({
  name: 'generateContentBlockPrompt',
  input: {schema: GenerateContentBlockInputSchema},
  output: {schema: GenerateContentBlockOutputSchema},
  prompt: `You are an AI assistant designed to generate content blocks for static websites, following Material Design principles.

  Based on the user's prompt, create a content block with the following structure:

  1.  **Title:** A clear and concise title for the content block.
  2.  **Subtitle:** (Optional) A brief subtitle to provide additional context.
  3.  **Content:** A well-structured content section, including a bulleted list of key points and a concluding paragraph. The bulleted list should have 3-5 items.
  4.  **Image:** Generate a relevant image to visually enhance the content block.  The image should be returned as a data URI.

  Ensure the content block is informative, engaging, and adheres to Material Design principles (clean, structured, and visually appealing).

  User Prompt: {{{prompt}}}

  Output in JSON format:
  `,
});

const generateContentBlockFlow = ai.defineFlow(
  {
    name: 'generateContentBlockFlow',
    inputSchema: GenerateContentBlockInputSchema,
    outputSchema: GenerateContentBlockOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    if (!output) {
      throw new Error('Failed to generate content block.');
    }

    // Generate the image separately using Gemini 2.0 Flash
    const imagePrompt = `Generate an image related to the following content block title: ${output.title}. The style should be suitable as an illustration in a content block.`;
    const {media} = await ai.generate({
      model: 'googleai/gemini-2.0-flash-exp',
      prompt: imagePrompt,
      config: {
        responseModalities: ['TEXT', 'IMAGE'],
      },
    });
    if (!media?.url) {
      throw new Error('Failed to generate image.');
    }

    return {
      ...output,
      imageUrl: media.url,
    };
  }
);
