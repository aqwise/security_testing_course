# Repository Guidelines

## Project Structure & Module Organization
- `src/app/`: Next.js App Router (routes, `layout.tsx`, pages). Create new pages under `src/app/<route>/page.tsx`.
- `src/components/`: Reusable UI; grouped by feature (`common`, `interactive`, `layout`, `ui`). Components use PascalCase filenames.
- `src/ai/`: Genkit setup and flows (`flows/*.ts`); local runner in `src/ai/dev.ts`.
- `src/constants`, `src/lib`, `src/utils`, `src/pics`: Shared data, helpers, assets.
- `public/`: Static files served as-is. `docs/`: project notes. `.github/workflows/`: GitHub Pages deploy.

## Build, Test, and Development Commands
- `npm ci` (or `npm install`): Install deps.
- `npm run dev`: Start dev server (Turbopack) on `http://localhost:9002`.
- `npm run build`: Static export to `out/` (configured via `next.config.ts`).
- `npm run start`: Start Next server build (not required for static `out/`).
- `npm run lint`: Run ESLint.
- `npm run typecheck`: TypeScript checks.
- `npm run genkit:dev` / `genkit:watch`: Run/auto-reload Genkit flows in `src/ai/`.

## Coding Style & Naming Conventions
- Language: TypeScript + React, Tailwind for styles.
- Indentation: 2 spaces; single quotes; semicolons.
- Exports: Pages default-export a component; shared components use named exports.
- Naming: Components/Types in PascalCase; functions/vars in camelCase.
- Imports: Use path alias `@/*` (see `tsconfig.json`). Run `npm run lint` before committing.

## Testing Guidelines
- No test framework is configured yet. If adding tests, prefer co-located files `*.test.ts(x)` or `src/**/__tests__/*` with Vitest/Jest and React Testing Library; include basic smoke tests for new pages and critical utilities. Ensure `npm run typecheck` and `npm run lint` pass.

## Commit & Pull Request Guidelines
- History is mixed; adopt Conventional Commits going forward, e.g., `feat(guidelines): add module III lesson 2`, `fix(app): hydrate attr mismatch`.
- PRs: concise title, clear description, linked issues, and screenshots for UI changes. Keep diffs focused and incremental. CI should build (`npm run build`) and lint cleanly.

## Security & Configuration Tips
- Do not commit secrets. Store keys in `.env.local`; `src/ai` reads env via `dotenv`.
- Deploys target GitHub Pages. `next.config.ts` sets `output: 'export'`, `basePath`, and `assetPrefix`; update `repoName`/`githubUserName` if forking.

