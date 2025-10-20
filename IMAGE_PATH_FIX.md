# Image Path Fix for GitHub Pages Deployment

## Problem
After deployment to GitHub Pages, images in lessons 2 (XSS) and 3 (HTML Injection) were showing as broken.

## Root Cause
The application uses a `basePath` configuration in `next.config.ts` for GitHub Pages deployment:
```typescript
basePath: isProd ? `/${repoName}` : undefined
```

This means in production, all paths need to be prefixed with `/security_testing_course/`.

Images were using absolute paths like:
```jsx
<img src="/pics/xss-lesson/image.png" />
```

But in production, these paths should be:
```
/security_testing_course/pics/xss-lesson/image.png
```

## Solution
Used the existing `getImagePath()` utility from `src/utils/paths.ts` which automatically handles the basePath:

```typescript
import { getImagePath } from '@/utils/paths';

// Change from:
<img src="/pics/xss-lesson/image.png" />

// To:
<img src={getImagePath('/pics/xss-lesson/image.png')} />
```

## Files Modified

### 1. `src/app/school/injections/lesson-2/page.tsx` (XSS Lesson)
- Added import: `import { getImagePath } from '@/utils/paths';`
- Updated 5 images:
  - burp-collaborator-diagram.png
  - blind-xss-payload.jpg
  - blind-xss-result.png
  - xss-alert-example.png
  - svg-xss-example.jpg

### 2. `src/app/school/injections/lesson-3/page.tsx` (HTML Injection Lesson)
- Added import: `import { getImagePath } from '@/utils/paths';`
- Updated 2 images:
  - blind-html-injection-request.png
  - blind-html-injection-email-result.png

## Testing
1. **Local Development**: Images work correctly at `http://localhost:9002`
2. **Production Build**: Images will work correctly at `https://aqwise.github.io/security_testing_course/`

## How It Works
The `getImagePath()` utility:
- In **development**: Returns `/pics/...` (no basePath)
- In **production**: Returns `/security_testing_course/pics/...` (with basePath)

This ensures images work in both environments without code changes.

## Future Reference
When adding new images to lessons, always use:
```jsx
import { getImagePath } from '@/utils/paths';

<img src={getImagePath('/pics/folder/image.png')} alt="Description" />
```

For Next.js Image component:
```jsx
<Image src={getImagePath('/pics/folder/image.png')} width={800} height={600} alt="Description" />
```
