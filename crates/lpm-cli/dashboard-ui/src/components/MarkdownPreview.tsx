import type { ReactNode } from 'react';
import styles from './SkillDetail.module.css';
import { parseSkillBody, type MarkdownBlock } from '../lib/markdown';

interface MarkdownPreviewProps {
  markdown: string;
}

/** Consecutive bullets become one list so the markup stays semantic. */
function groupBlocks(blocks: MarkdownBlock[]): Array<MarkdownBlock | MarkdownBlock[]> {
  const grouped: Array<MarkdownBlock | MarkdownBlock[]> = [];

  for (const block of blocks) {
    const last = grouped[grouped.length - 1];
    if (block.kind === 'listItem') {
      if (Array.isArray(last)) last.push(block);
      else grouped.push([block]);
    } else {
      grouped.push(block);
    }
  }

  return grouped;
}

function renderBlock(block: MarkdownBlock, key: string): ReactNode {
  switch (block.kind) {
    case 'h1':
      return (
        <h3 key={key} className={styles.mdH1}>
          {block.text}
        </h3>
      );
    case 'h2':
      return (
        <h4 key={key} className={styles.mdH2}>
          {block.text}
        </h4>
      );
    case 'code':
      return (
        <pre key={key} className={styles.mdCode}>
          {block.text}
        </pre>
      );
    case 'paragraph':
    case 'listItem':
      return (
        <p key={key} className={styles.mdP}>
          {block.text}
        </p>
      );
  }
}

export function MarkdownPreview({ markdown }: MarkdownPreviewProps) {
  const grouped = groupBlocks(parseSkillBody(markdown));

  return (
    <div className={styles.previewDoc}>
      {grouped.map((entry, index) => {
        if (!Array.isArray(entry)) return renderBlock(entry, `b${index}`);
        return (
          <ul key={`l${index}`} className={styles.mdList}>
            {entry.map((item, itemIndex) => (
              <li key={itemIndex} className={styles.mdLi}>
                {item.text}
              </li>
            ))}
          </ul>
        );
      })}
    </div>
  );
}
