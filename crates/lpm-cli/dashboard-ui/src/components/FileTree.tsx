import styles from './SkillDetail.module.css';
import { buildFileTree } from '../lib/fileTree';

interface FileTreeProps {
  files: readonly string[];
}

export function FileTree({ files }: FileTreeProps) {
  const rows = buildFileTree(files);

  return (
    <ul className={styles.tree}>
      {rows.map((row) => {
        const className = [
          styles.treeRow,
          row.kind === 'directory' ? styles.treeRowDir : '',
          row.nested ? styles.treeRowNested : '',
        ]
          .filter(Boolean)
          .join(' ');

        const iconClass =
          row.kind === 'directory'
            ? `${styles.treeIcon} ${styles.treeIconDir}`
            : styles.treeIcon;

        return (
          <li key={row.id} className={className}>
            <span className={iconClass} aria-hidden="true">
              {row.kind === 'directory' ? '▾' : '·'}
            </span>
            <span>{row.label}</span>
          </li>
        );
      })}
    </ul>
  );
}
