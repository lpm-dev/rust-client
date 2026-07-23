import styles from './AppFooter.module.css';

interface AppFooterProps {
  status: string;
}

export function AppFooter({ status }: AppFooterProps) {
  return (
    <footer className={styles.footer}>
      <span>{status}</span>
      <span className={styles.shortcuts}>
        <span className={styles.shortcut}>
          <span className={styles.kbd}>/</span> find
        </span>
        <span className={styles.shortcut}>
          <span className={styles.kbd}>&#8593;&#8595;</span> move
        </span>
        <span className={styles.shortcut}>
          <span className={styles.kbd}>&#8629;</span> open
        </span>
      </span>
    </footer>
  );
}
