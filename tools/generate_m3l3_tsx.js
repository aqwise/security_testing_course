const fs = require('fs');
const path = require('path');

function stripTags(s) {
  return s
    .replace(/<a\s+[^>]*>(.*?)<\/a>/gi, '$1')
    .replace(/<strong>(.*?)<\/strong>/gi, '$1')
    .replace(/<em>(.*?)<\/em>/gi, '$1')
    .replace(/<code>(.*?)<\/code>/gi, '$1')
    .replace(/<br\s*\/?>(?=\s*)/gi, ' ')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ') // collapse whitespace
    .trim();
}

function escapeJsxText(s) {
  return s
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$/g, '\\$');
}

function parseHtmlToBlocks(html) {
  // Remove anchor-only tags
  let h = html.replace(/<a\s+id="[^"]*"><\/a>/gi, '');
  const blocks = [];
  // Simple streaming parse by splitting on top-level tags we care about
  const regex = /<(h1|h2|h3|p|ul)(\b[^>]*)?>([\s\S]*?)<\/\1>/gi;
  let m;
  while ((m = regex.exec(h))) {
    const tag = m[1].toLowerCase();
    const inner = m[3];
    if (tag === 'h1') continue; // title already provided by layout
    if (tag === 'p') {
      const text = stripTags(inner);
      if (text) blocks.push({ type: 'p', text });
    } else if (tag === 'h2') {
      const text = stripTags(inner);
      if (text) blocks.push({ type: 'h2', text });
    } else if (tag === 'h3') {
      const text = stripTags(inner);
      if (text) blocks.push({ type: 'h3', text });
    } else if (tag === 'ul') {
      const items = [];
      inner.replace(/<li>([\s\S]*?)<\/li>/gi, (_, li) => {
        const t = stripTags(li);
        if (t) items.push(t);
        return '';
      });
      if (items.length) blocks.push({ type: 'ul', items });
    }
  }
  return blocks;
}

function generateTsx(blocks) {
  const lines = [];
  lines.push(`'use client';`);
  lines.push('');
  lines.push("import * as React from 'react';");
  lines.push("import { ContentPageLayout, P, H2, H3, Ul } from '@/components/content/ContentPageLayout';");
  lines.push('');
  lines.push('export default function Module3Lesson3Page() {');
  lines.push('  return (');
  lines.push('    <ContentPageLayout');
  lines.push('      title="Урок 3: Атаки на контроль доступа"');
  lines.push('      subtitle="Полная версия из документа"');
  lines.push('    >');
  for (const b of blocks) {
    if (b.type === 'h2') {
      lines.push(`      <H2>${escapeJsxText(b.text)}</H2>`);
    } else if (b.type === 'h3') {
      lines.push(`      <H3>${escapeJsxText(b.text)}</H3>`);
    } else if (b.type === 'p') {
      lines.push(`      <P>${escapeJsxText(b.text)}</P>`);
    } else if (b.type === 'ul') {
      const items = b.items.map(it => '`' + escapeJsxText(it) + '`').join(', ');
      lines.push(`      <Ul items={[ ${items} ]} />`);
    }
  }
  lines.push('    </ContentPageLayout>');
  lines.push('  );');
  lines.push('}');
  lines.push('');
  return lines.join('\n');
}

const htmlPath = path.resolve(__dirname, '..', 'public', 'lessons', 'module-3-lesson-3.html');
const outPath = path.resolve(__dirname, '..', 'src', 'app', 'guidelines', 'module-3', 'lesson-3', 'page.tsx');
const html = fs.readFileSync(htmlPath, 'utf8');
const blocks = parseHtmlToBlocks(html);
const tsx = generateTsx(blocks);
fs.writeFileSync(outPath, tsx, 'utf8');
console.log(`Generated ${outPath} with ${blocks.length} blocks.`);

