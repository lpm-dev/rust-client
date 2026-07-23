import type { KeyboardEvent } from 'react';
import styles from './SkillList.module.css';
import type { Skill } from '../api/types';
import { fileCountLabel } from '../lib/skillView';

interface SkillListItemProps {
  skill: Skill;
  selected: boolean;
  /** Receives keyboard focus when the list is tabbed into. */
  tabbable: boolean;
  onSelect: (id: string) => void;
}

function badgeClass(skill: Skill): string {
  if (skill.category === 'package') return `${styles.badge} ${styles.badgePackage}`;
  if (skill.category === 'external') return `${styles.badge} ${styles.badgeExternal}`;
  return styles.badge;
}

function dotClass(skill: Skill): string {
  if (skill.state === 'enabled') return `${styles.dot} ${styles.dotEnabled}`;
  if (skill.category === 'external') return `${styles.dot} ${styles.dotUnmanaged}`;
  return styles.dot;
}

export function SkillListItem({ skill, selected, tabbable, onSelect }: SkillListItemProps) {
  function handleKeyDown(event: KeyboardEvent<HTMLLIElement>) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelect(skill.id);
    }
  }

  return (
    <li
      role="option"
      aria-selected={selected}
      tabIndex={tabbable ? 0 : -1}
      className={selected ? `${styles.row} ${styles.rowActive}` : styles.row}
      onClick={() => onSelect(skill.id)}
      onKeyDown={handleKeyDown}
    >
      <div className={styles.rowTop}>
        <span className={styles.rowName}>{skill.name}</span>
        <span className={badgeClass(skill)}>{skill.category}</span>
      </div>
      <div className={styles.rowOwner}>{skill.namespace}</div>
      <div className={styles.rowDesc}>{skill.description}</div>
      <div className={styles.rowFoot}>
        <span className={styles.rowFootLeft}>
          <span className={dotClass(skill)} aria-hidden="true" />
          <span>
            {skill.scope} · {skill.agent}
          </span>
        </span>
        <span>{fileCountLabel(skill.stats.files)}</span>
      </div>
    </li>
  );
}
