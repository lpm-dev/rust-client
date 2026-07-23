import styles from './SkillDetail.module.css';
import type { StatCell } from '../lib/skillView';

interface StatsRowProps {
  cells: readonly StatCell[];
}

export function StatsRow({ cells }: StatsRowProps) {
  return (
    <div className={styles.statsRow}>
      {cells.map((cell) => (
        <div key={cell.label} className={styles.stat}>
          <div className={styles.statLabel}>{cell.label}</div>
          <div className={styles.statValue}>{cell.value}</div>
        </div>
      ))}
    </div>
  );
}
