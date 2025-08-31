# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, Test, and Development Commands

```bash
# Development
npm ci                     # Install dependencies (preferred over npm install)
npm run dev               # Start dev server with Turbopack on port 9002
npm run build             # Build for production (static export to out/)
npm run start             # Start production server (not needed for static export)

# Code Quality
npm run lint              # Run ESLint
npm run typecheck         # TypeScript type checking

# AI/Genkit Development
npm run genkit:dev        # Start Genkit flows in development
npm run genkit:watch      # Auto-reload Genkit flows during development
```

## Project Architecture

This is a **Next.js security course application** built with TypeScript, Tailwind CSS, and Firebase Genkit for AI features. The application is designed to teach security testing concepts through interactive modules.

### Core Structure

- **App Router**: Uses Next.js 13+ app directory structure with `src/app/` containing all routes
- **Component Organization**: 
  - `src/components/interactive/` - Module-specific interactive components organized by course sections
  - `src/components/layout/` - Navigation, headers, layout components  
  - `src/components/ui/` - Reusable UI components (shadcn/ui based)
  - `src/components/content/` - Content-specific components like CodeBlock, YouTubePlayer

### Key Architecture Patterns

1. **Module-Based Structure**: Course content is organized into modules (1-4) with lessons, each having dedicated interactive components
2. **Component Composition**: Pages compose multiple section components (e.g., IntroSection, FooterSection) for modularity
3. **Static Export**: Configured for GitHub Pages deployment via `next.config.ts` with static export
4. **AI Integration**: Genkit flows in `src/ai/` for content generation and processing

### Navigation System

- Centralized navigation in `src/constants/navigation.ts`
- Hierarchical sidebar with nested routes (modules → lessons)
- Path-based active state detection in `SidebarNav.tsx`

### Content Organization

Course modules follow this pattern:
- **Introduction**: Welcome, approach, resources, goals
- **Module 1**: Security testing fundamentals and methodology  
- **Module 2**: Reconnaissance, mapping, discovery, analysis
- **Module 3**: Authentication, session, access control attacks
- **Module 4**: Injection attacks (SQL, command, path traversal, file upload)

## Development Guidelines

### Coding Standards
- **TypeScript**: Strict type checking enabled
- **Styling**: Tailwind CSS with 2-space indentation
- **Components**: PascalCase filenames, default exports for pages, named exports for components
- **Path Aliases**: Use `@/*` imports (configured in tsconfig.json)

### Git Workflow
- Main branch: `main`
- Current development: `dev/module-3-chapter-3`
- Use Conventional Commits (e.g., `feat(module3): add access control attacks`)

### Static Deployment
- Builds to `out/` directory for GitHub Pages
- Base path and asset prefix configured in `next.config.ts`
- Update `repoName`/`githubUserName` variables if forking

### Security Considerations
- No secrets in code - use `.env.local` for environment variables
- AI features (Genkit) load environment via `dotenv` in `src/ai/`

## Important Files

- `AGENTS.md` - Comprehensive development guidelines (consider this the authoritative source)
- `mob-sf-configuration.md` - MobSF setup documentation for security testing
- `src/constants/navigation.ts` - Site navigation structure
- `next.config.ts` - Next.js configuration including static export settings