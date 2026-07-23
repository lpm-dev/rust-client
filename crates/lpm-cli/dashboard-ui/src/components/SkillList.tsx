import { useRef, type KeyboardEvent, type RefObject } from 'react';
import styles from './SkillList.module.css';
import { SkillListItem } from './SkillListItem';
import { SourceTabs } from './SourceTabs';
import type { Skill, SkillId } from '../api/types';
import {
  SORT_OPTIONS,
  type SortId,
  type SourceCounts,
  type SourceTabId,
} from '../lib/skillQuery';

const LIST_REGION_ID = 'skill-list-region';

interface SkillListProps {
  skills: readonly Skill[];
  counts: SourceCounts;
  tab: SourceTabId;
  onTabChange: (tab: SourceTabId) => void;
  sort: SortId;
  onSortChange: (sort: SortId) => void;
  query: string;
  onQueryChange: (query: string) => void;
  selectedId: SkillId | null;
  onSelect: (id: SkillId) => void;
  searchRef: RefObject<HTMLInputElement | null>;
  status: 'loading' | 'ready' | 'error';
  errorMessage: string | null;
}

export function SkillList({
  skills,
  counts,
  tab,
  onTabChange,
  sort,
  onSortChange,
  query,
  onQueryChange,
  selectedId,
  onSelect,
  searchRef,
  status,
  errorMessage,
}: SkillListProps) {
  const listRef = useRef<HTMLUListElement>(null);

  // The list owns a single tab stop; arrows move within it.
  const selectedIndex = skills.findIndex((skill) => skill.id === selectedId);
  const tabbableIndex = selectedIndex >= 0 ? selectedIndex : 0;

  function handleListKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    const options = Array.from(
      listRef.current?.querySelectorAll<HTMLElement>('[role="option"]') ?? [],
    );
    if (options.length === 0) return;

    const current = options.indexOf(document.activeElement as HTMLElement);
    let next = -1;

    switch (event.key) {
      case 'ArrowDown':
        next = current < 0 ? 0 : Math.min(current + 1, options.length - 1);
        break;
      case 'ArrowUp':
        next = current < 0 ? options.length - 1 : Math.max(current - 1, 0);
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = options.length - 1;
        break;
      default:
        return;
    }

    event.preventDefault();
    options[next]?.focus();
  }

  const emptyMessage =
    status === 'error'
      ? (errorMessage ?? 'the skill scan failed.')
      : status === 'loading'
        ? 'scanning skill directories…'
        : 'no skills match this filter.';

  return (
    <>
      <SourceTabs
        active={tab}
        counts={counts}
        onChange={onTabChange}
        controls={LIST_REGION_ID}
      />

      <div className={styles.filterRow}>
        <div className={styles.searchWrap}>
          <span className={styles.searchIcon} aria-hidden="true">
            &#8981;
          </span>
          {/* Short placeholder because sort now shares the row; the full hint
              stays in the accessible name. */}
          <input
            ref={searchRef}
            type="search"
            className={styles.searchInput}
            placeholder="filter by name or owner"
            aria-label="filter skills by name, owner, or description"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
          />
          <span className={styles.searchKey} aria-hidden="true">
            /
          </span>
        </div>
        <div className={styles.sortWrap}>
          <select
            className={styles.sortSelect}
            aria-label="sort skills"
            value={sort}
            onChange={(event) => onSortChange(event.target.value as SortId)}
          >
            {SORT_OPTIONS.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div
        className={styles.listScroll}
        id={LIST_REGION_ID}
        role="tabpanel"
        aria-labelledby={`source-tab-${tab}`}
      >
        {skills.length > 0 ? (
          <ul
            ref={listRef}
            className={styles.listBox}
            role="listbox"
            aria-label="discovered skills"
            onKeyDown={handleListKeyDown}
          >
            {skills.map((skill, index) => (
              <SkillListItem
                key={skill.id}
                skill={skill}
                selected={skill.id === selectedId}
                tabbable={index === tabbableIndex}
                onSelect={onSelect}
              />
            ))}
          </ul>
        ) : (
          <p className={styles.listEmpty}>{emptyMessage}</p>
        )}
      </div>
    </>
  );
}
