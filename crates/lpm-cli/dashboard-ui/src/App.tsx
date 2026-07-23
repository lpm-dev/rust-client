import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import styles from './App.module.css';
import { ActionDialog } from './components/ActionDialog';
import { AppFooter } from './components/AppFooter';
import { AppHeader } from './components/AppHeader';
import { SkillDetail, type DetailTabId } from './components/SkillDetail';
import { SkillList } from './components/SkillList';
import type {
  ActionPreview,
  DashboardApi,
  Skill,
  SkillAction,
  SkillId,
  SkillsSnapshot,
} from './api/types';
import { isTypingTarget } from './lib/keyboard';
import { countBySource, selectSkills, type SortId, type SourceTabId } from './lib/skillQuery';

const COPIED_RESET_MS = 1400;
const ANNOUNCEMENT_RESET_MS = 6000;

interface AppProps {
  api: DashboardApi;
  onRevealRequested?: (path: string) => void;
}

type LoadStatus = 'loading' | 'ready' | 'error';

export function App({ api, onRevealRequested }: AppProps) {
  const [snapshot, setSnapshot] = useState<SkillsSnapshot>({
    skills: [],
    skippedLinks: 0,
    warningCount: 0,
    readOnly: false,
  });
  const [status, setStatus] = useState<LoadStatus>('loading');
  const [error, setError] = useState<string | null>(null);

  const [sourceTab, setSourceTab] = useState<SourceTabId>('all');
  const [detailTab, setDetailTab] = useState<DetailTabId>('preview');
  const [selectedId, setSelectedId] = useState<SkillId | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<Skill | null>(null);
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<SortId>('name');
  const [copied, setCopied] = useState(false);
  const [announcement, setAnnouncement] = useState('');
  const [preview, setPreview] = useState<ActionPreview | null>(null);
  const [previewingAction, setPreviewingAction] = useState<SkillAction | null>(null);
  const [applying, setApplying] = useState(false);

  const searchRef = useRef<HTMLInputElement>(null);
  const copiedTimer = useRef<number | undefined>(undefined);
  const announcementTimer = useRef<number | undefined>(undefined);

  const announce = useCallback((message: string) => {
    setAnnouncement(message);
    window.clearTimeout(announcementTimer.current);
    announcementTimer.current = window.setTimeout(
      () => setAnnouncement(''),
      ANNOUNCEMENT_RESET_MS,
    );
  }, []);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      setStatus('loading');
      setError(null);
      try {
        const next = await api.listSkills(signal);
        if (signal?.aborted) return;
        setSnapshot(next);
        setStatus('ready');
      } catch (cause) {
        if (signal?.aborted) return;
        setError(cause instanceof Error ? cause.message : 'the skill scan failed.');
        setStatus('error');
      }
    },
    [api],
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  useEffect(
    () => () => {
      window.clearTimeout(copiedTimer.current);
      window.clearTimeout(announcementTimer.current);
    },
    [],
  );

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== '/' || event.metaKey || event.ctrlKey || event.altKey) return;
      if (isTypingTarget(event.target)) return;
      event.preventDefault();
      searchRef.current?.focus();
      searchRef.current?.select();
    }

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const counts = useMemo(() => countBySource(snapshot.skills), [snapshot.skills]);

  const visibleSkills = useMemo(
    () => selectSkills(snapshot.skills, { tab: sourceTab, query, sort }),
    [snapshot.skills, sourceTab, query, sort],
  );

  const selectedSummary =
    visibleSkills.find((skill) => skill.id === selectedId) ??
    visibleSkills[0] ??
    null;
  const selectedSkill =
    selectedDetail?.id === selectedSummary?.id ? selectedDetail : selectedSummary;

  useEffect(() => {
    if (!selectedSummary) {
      setSelectedDetail(null);
      return;
    }
    const controller = new AbortController();
    const selectedSummaryId = selectedSummary.id;
    void api
      .getSkill(selectedSummaryId, controller.signal)
      .then((skill) => {
        if (controller.signal.aborted) return;
        if (skill) {
          setSelectedDetail(skill);
        } else {
          setSelectedDetail(null);
          announce('the selected skill is no longer on disk; refresh the inventory.');
        }
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        setSelectedDetail(null);
        announce(cause instanceof Error ? cause.message : 'the skill detail could not be read.');
      });
    return () => controller.abort();
  }, [announce, api, selectedSummary]);

  const handleSelect = useCallback((id: SkillId) => {
    setSelectedId(id);
    setSelectedDetail(null);
    setDetailTab('preview');
    setCopied(false);
  }, []);

  const handleCopyPath = useCallback(async () => {
    if (!selectedSkill) return;
    try {
      await navigator.clipboard?.writeText(selectedSkill.path);
      announce(`copied ${selectedSkill.path}`);
    } catch {
      announce('the clipboard is not available in this context.');
      return;
    }
    setCopied(true);
    window.clearTimeout(copiedTimer.current);
    copiedTimer.current = window.setTimeout(() => setCopied(false), COPIED_RESET_MS);
  }, [announce, selectedSkill]);

  const handleReveal = useCallback(async () => {
    if (!selectedSkill) return;
    onRevealRequested?.(selectedSkill.path);
    try {
      const result = await api.revealSkill(selectedSkill.id);
      announce(result.status === 'ok' ? `revealed ${selectedSkill.path}` : result.message);
    } catch (cause) {
      announce(cause instanceof Error ? cause.message : 'the skill could not be revealed.');
    }
  }, [announce, api, onRevealRequested, selectedSkill]);

  const handleAction = useCallback(
    async (action: SkillAction) => {
      if (!selectedSkill || !selectedSkill.actions.includes(action)) return;
      setPreviewingAction(action);
      try {
        setPreview(await api.previewAction(selectedSkill.id, action));
      } catch (cause) {
        announce(cause instanceof Error ? cause.message : `the ${action} plan failed.`);
      } finally {
        setPreviewingAction(null);
      }
    },
    [announce, api, selectedSkill],
  );

  const handleApply = useCallback(async () => {
    if (!preview) return;
    setApplying(true);
    try {
      const result = await api.applyAction(preview.planId);
      if (result.status === 'error') {
        announce(result.message);
        return;
      }
      const completedAction = preview.action;
      const completedSkill = preview.skill;
      setPreview(null);
      setSelectedDetail(null);
      await load();
      announce(`${completedSkill} ${completedAction} applied`);
    } catch (cause) {
      announce(cause instanceof Error ? cause.message : 'the reviewed plan could not be applied.');
    } finally {
      setApplying(false);
    }
  }, [announce, api, load, preview]);

  const scanStatus =
    status === 'ready'
      ? snapshot.warningCount > 0
        ? `${snapshot.skills.length} skills · ${snapshot.warningCount} scan warnings · ${snapshot.skippedLinks} entries skipped`
        : `${snapshot.skills.length} skills across project and global sources`
      : status === 'error'
        ? (error ?? 'the skill scan failed.')
        : 'scanning skill directories…';

  return (
    <div className={styles.app}>
      <AppHeader onRefresh={() => void load()} refreshing={status === 'loading'} />

      <main className={styles.main}>
        <section className={styles.left} aria-label="discovered skills">
          <SkillList
            skills={visibleSkills}
            counts={counts}
            tab={sourceTab}
            onTabChange={setSourceTab}
            sort={sort}
            onSortChange={setSort}
            query={query}
            onQueryChange={setQuery}
            selectedId={selectedSkill?.id ?? null}
            onSelect={handleSelect}
            searchRef={searchRef}
            status={status}
            errorMessage={error}
          />
        </section>

        <section className={styles.right} aria-label="skill detail">
          {selectedSkill ? (
            <SkillDetail
              skill={selectedSkill}
              activeTab={detailTab}
              onTabChange={setDetailTab}
              copyLabel={copied ? 'copied ✓' : 'copy path'}
              onCopyPath={() => void handleCopyPath()}
              onReveal={() => void handleReveal()}
              onAction={(action) => void handleAction(action)}
              pendingAction={previewingAction}
            />
          ) : null}
        </section>
      </main>

      <AppFooter status={announcement || scanStatus} />

      {preview ? (
        <ActionDialog
          preview={preview}
          applying={applying}
          onCancel={() => setPreview(null)}
          onApply={() => void handleApply()}
        />
      ) : null}

      <p className="visuallyHidden" role="status" aria-live="polite">
        {announcement}
      </p>
    </div>
  );
}
