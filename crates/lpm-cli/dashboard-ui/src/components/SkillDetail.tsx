import { useRef } from 'react';
import styles from './SkillDetail.module.css';
import { FileTree } from './FileTree';
import { MarkdownPreview } from './MarkdownPreview';
import { MetadataTable } from './MetadataTable';
import { StatsRow } from './StatsRow';
import type { Skill, SkillAction } from '../api/types';
import { moveRovingFocus } from '../lib/keyboard';
import {
  isManaged,
  skillBanner,
  skillBody,
  skillCrumb,
  skillMetadataRows,
  skillRawText,
  skillStatCells,
  skillTitle,
} from '../lib/skillView';

export type DetailTabId = 'preview' | 'raw' | 'files' | 'metadata';

interface SkillDetailProps {
  skill: Skill;
  activeTab: DetailTabId;
  onTabChange: (tab: DetailTabId) => void;
  copyLabel: string;
  onCopyPath: () => void;
  onReveal: () => void;
  onAction: (action: SkillAction) => void;
  pendingAction: SkillAction | null;
}

export function SkillDetail({
  skill,
  activeTab,
  onTabChange,
  copyLabel,
  onCopyPath,
  onReveal,
  onAction,
  pendingAction,
}: SkillDetailProps) {
  const tabsRef = useRef<HTMLDivElement>(null);

  const tabs: ReadonlyArray<{ id: DetailTabId; label: string }> = [
    { id: 'preview', label: 'preview' },
    { id: 'raw', label: 'raw' },
    { id: 'files', label: `files (${skill.stats.files})` },
    { id: 'metadata', label: 'metadata' },
  ];

  const managed = isManaged(skill);
  const enabled = skill.state === 'enabled' || skill.state === 'mixed';
  const toggleAction: SkillAction = enabled ? 'disable' : 'enable';
  const canToggle = skill.actions.includes(toggleAction);
  const busy = pendingAction !== null;

  return (
    <div className={styles.pad}>
      <div className={styles.topRow}>
        <div className={styles.topRowLeft}>
          <span className={styles.crumb}>{skillCrumb(skill)}</span>
        </div>
        <div className={styles.actions}>
          <button type="button" className={styles.ghostBtn} onClick={onCopyPath}>
            {copyLabel}
          </button>
          <button type="button" className={styles.ghostBtn} onClick={onReveal}>
            reveal
          </button>
          {skill.actions.includes('update') ? (
            <button
              type="button"
              className={styles.ghostBtn}
              disabled={busy}
              onClick={() => onAction('update')}
            >
              {pendingAction === 'update' ? 'previewing…' : 'update'}
            </button>
          ) : null}
          {skill.actions.includes('remove') ? (
            <button
              type="button"
              className={styles.ghostBtn}
              disabled={busy}
              onClick={() => onAction('remove')}
            >
              {pendingAction === 'remove' ? 'previewing…' : 'remove'}
            </button>
          ) : null}
          {managed ? (
            <button
              type="button"
              className={
                enabled ? `${styles.toggleBtn} ${styles.toggleBtnOn}` : styles.toggleBtn
              }
              aria-pressed={enabled}
              disabled={!canToggle || busy}
              onClick={() => onAction(toggleAction)}
            >
              <span className={styles.toggleDot} aria-hidden="true" />
              {pendingAction === toggleAction ? 'previewing…' : toggleAction}
            </button>
          ) : null}
        </div>
      </div>

      <h1 className={styles.title}>{skillTitle(skill)}</h1>
      <p className={styles.desc}>{skill.description}</p>

      <div className={styles.banner}>
        <span
          className={
            managed ? `${styles.bannerDot} ${styles.bannerDotManaged}` : styles.bannerDot
          }
          aria-hidden="true"
        />
        <span>{skillBanner(skill)}</span>
      </div>

      <div className={styles.pathRow}>
        <code className={styles.pathCode}>{skill.path}</code>
        <button
          type="button"
          className={styles.copyIcon}
          onClick={onCopyPath}
          aria-label={`copy path for ${skill.name}`}
        >
          <span aria-hidden="true">&#10697;</span>
        </button>
      </div>

      <StatsRow cells={skillStatCells(skill)} />

      <div
        ref={tabsRef}
        className={styles.detailTabs}
        role="tablist"
        aria-label="skill detail views"
        onKeyDown={(event) => moveRovingFocus(event, tabsRef.current, '[role="tab"]')}
      >
        {tabs.map((tab) => {
          const isActive = tab.id === activeTab;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`detail-tab-${tab.id}`}
              aria-selected={isActive}
              aria-controls={`detail-panel-${tab.id}`}
              tabIndex={isActive ? 0 : -1}
              className={
                isActive ? `${styles.detailTab} ${styles.detailTabActive}` : styles.detailTab
              }
              onClick={() => onTabChange(tab.id)}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      <div
        className={styles.tabBody}
        role="tabpanel"
        id={`detail-panel-${activeTab}`}
        aria-labelledby={`detail-tab-${activeTab}`}
        tabIndex={0}
      >
        {activeTab === 'preview' && <MarkdownPreview markdown={skillBody(skill)} />}
        {activeTab === 'raw' && <pre className={styles.rawPre}>{skillRawText(skill)}</pre>}
        {activeTab === 'files' && <FileTree files={skill.files} />}
        {activeTab === 'metadata' && <MetadataTable rows={skillMetadataRows(skill)} />}
      </div>
    </div>
  );
}
