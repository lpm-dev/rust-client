import styles from './SkillDetail.module.css';
import type { MetadataRow } from '../lib/skillView';

interface MetadataTableProps {
  rows: readonly MetadataRow[];
}

export function MetadataTable({ rows }: MetadataTableProps) {
  return (
    <dl className={styles.metaTable}>
      {rows.map((row) => (
        <div key={row.key} className={styles.metaRow}>
          <dt className={styles.metaKey}>{row.key}</dt>
          <dd
            className={
              row.warn ? `${styles.metaValue} ${styles.metaValueWarn}` : styles.metaValue
            }
          >
            {row.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
