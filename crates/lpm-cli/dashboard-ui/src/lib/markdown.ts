export type MarkdownBlockKind = 'h1' | 'h2' | 'paragraph' | 'listItem' | 'code';

export interface MarkdownBlock {
  kind: MarkdownBlockKind;
  text: string;
}

/**
 * The narrow subset of markdown the skill preview renders: two heading levels,
 * paragraphs, single-level bullets, and fenced code. Anything else falls
 * through as a paragraph, which matches how the source design read these files.
 */
export function parseSkillBody(markdown: string): MarkdownBlock[] {
  const blocks: MarkdownBlock[] = [];
  let inCode = false;
  let codeBuffer: string[] = [];

  for (const line of markdown.split('\n')) {
    if (line.trim().startsWith('```')) {
      if (inCode) {
        blocks.push({ kind: 'code', text: codeBuffer.join('\n') });
        codeBuffer = [];
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }

    if (inCode) {
      codeBuffer.push(line);
      continue;
    }

    if (line.startsWith('## ')) blocks.push({ kind: 'h2', text: line.slice(3) });
    else if (line.startsWith('# ')) blocks.push({ kind: 'h1', text: line.slice(2) });
    else if (line.startsWith('- ')) blocks.push({ kind: 'listItem', text: line.slice(2) });
    else if (line.trim() !== '') blocks.push({ kind: 'paragraph', text: line });
  }

  // An unterminated fence still shows its contents rather than dropping them.
  if (inCode && codeBuffer.length > 0) {
    blocks.push({ kind: 'code', text: codeBuffer.join('\n') });
  }

  return blocks;
}
