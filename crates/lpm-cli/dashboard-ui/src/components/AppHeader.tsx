import styles from './AppHeader.module.css';
import { LpmLogo } from './LpmLogo';

interface AppHeaderProps {
  onRefresh: () => void;
  refreshing: boolean;
}

export function AppHeader({ onRefresh, refreshing }: AppHeaderProps) {
  return (
    <header className={styles.header}>
      <div className={styles.identity}>
        <LpmLogo />
        <span className={styles.brand}>
          LPM <span className={styles.brandLight}>CLI</span>
        </span>
        <span className={styles.separator} aria-hidden="true">
          -
        </span>
        <span className={styles.product}>Skill Dashboard</span>
      </div>
      <button
        type="button"
        className={styles.refresh}
        onClick={onRefresh}
        disabled={refreshing}
      >
        <span className={styles.glyph} aria-hidden="true">
          &#8635;
        </span>
        {refreshing ? 'refreshing' : 'refresh'}
      </button>
    </header>
  );
}
