import { useRef } from 'react';
import styles from './SkillList.module.css';
import { SOURCE_TABS, type SourceCounts, type SourceTabId } from '../lib/skillQuery';
import { moveRovingFocus } from '../lib/keyboard';

interface SourceTabsProps {
  active: SourceTabId;
  counts: SourceCounts;
  onChange: (tab: SourceTabId) => void;
  /** id of the region these tabs filter, for `aria-controls`. */
  controls: string;
}

export function SourceTabs({ active, counts, onChange, controls }: SourceTabsProps) {
  const barRef = useRef<HTMLDivElement>(null);

  return (
    <div
      ref={barRef}
      className={styles.tabBar}
      role="tablist"
      aria-label="filter skills by source or status"
      onKeyDown={(event) => moveRovingFocus(event, barRef.current, '[role="tab"]')}
    >
      {SOURCE_TABS.map((tab) => {
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            id={`source-tab-${tab.id}`}
            aria-selected={isActive}
            aria-controls={controls}
            tabIndex={isActive ? 0 : -1}
            className={isActive ? `${styles.tab} ${styles.tabActive}` : styles.tab}
            onClick={() => onChange(tab.id)}
          >
            <span>{tab.label}</span>
            <span className={styles.tabCount}>{counts[tab.id]}</span>
          </button>
        );
      })}
    </div>
  );
}
