import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createHttpDashboardApi } from './httpApi';

const INVENTORY_SKILL = {
  id: `managed:${'a'.repeat(64)}`,
  kind: 'managed',
  name: 'release-notes',
  description: 'Prepare release notes',
  source: 'acme/team-skills',
  scope: 'global',
  path: '/tmp/release-notes',
  context_tokens: 1250,
  file_count: 2,
  modified_at_ms: 1_784_726_400_000,
  targets: [
    {
      agent: 'codex',
      label: 'Codex',
      enabled: true,
      healthy: true,
    },
    {
      agent: 'cursor',
      label: 'Cursor',
      enabled: false,
      healthy: true,
    },
  ],
  healthy: true,
  security: {
    status: 'scanned',
    warning_count: 0,
    block_count: 0,
    findings: [],
  },
  actions: ['enable', 'disable', 'update', 'remove'],
};

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('HTTP dashboard API', () => {
  beforeEach(() => {
    window.sessionStorage.clear();
    window.history.replaceState(null, '', '/#token=session-secret');
    vi.restoreAllMocks();
  });

  it('captures the fragment token and maps the unified inventory', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        read_only: false,
        skipped_entries: 2,
        warnings: [{ message: 'unreadable root' }],
        skills: [INVENTORY_SKILL],
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const snapshot = await createHttpDashboardApi().listSkills();

    expect(window.location.hash).toBe('');
    expect(snapshot.warningCount).toBe(1);
    expect(snapshot.skippedLinks).toBe(2);
    expect(snapshot.skills[0]).toMatchObject({
      id: INVENTORY_SKILL.id,
      scope: 'global',
      state: 'mixed',
      agent: 'Codex, Cursor',
      context: '~1.3k tokens',
      actions: ['enable', 'disable', 'update', 'remove'],
    });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(init.headers).get('Authorization')).toBe('Bearer session-secret');
  });

  it('reports a missing launch session without making an unauthenticated request', async () => {
    window.history.replaceState(null, '', '/');
    window.sessionStorage.clear();
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(createHttpDashboardApi().listSkills()).rejects.toThrow(
      'Restart `lpm skills dashboard`',
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('loads exact selected-skill source and statistics by stable id', async () => {
    const raw =
      '---\nname: release-notes\ndescription: Prepare release notes\n---\n\n# Notes\n';
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        skill: INVENTORY_SKILL,
        detail: {
          raw,
          body: '\n# Notes\n',
          files: ['SKILL.md', 'references/format.md'],
          stats: { files: 2, words: 2, lines: 2, frontmatter_keys: 2 },
          metadata: { version: '2.0.0', globs: ['**/*.md'] },
          warnings: [],
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const api = createHttpDashboardApi();

    const skill = await api.getSkill(INVENTORY_SKILL.id);

    expect(skill).toMatchObject({
      raw,
      body: '\n# Notes\n',
      files: ['SKILL.md', 'references/format.md'],
      stats: { files: 2, words: 2, lines: 2, keys: 2 },
      version: '2.0.0',
      globs: '**/*.md',
    });
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `/api/v1/skills/${encodeURIComponent(INVENTORY_SKILL.id)}`,
    );
  });

  it('keeps mutation preview separate from applying the reviewed plan', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          plan_id: 'plan-1',
          expires_in_seconds: 600,
          action: 'disable',
          skill: 'release-notes',
          scope: 'global',
          changes: [{ action: 'remove', path: '/tmp/release-notes' }],
          updates: [],
          security_warning_count: 0,
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ success: true }));
    vi.stubGlobal('fetch', fetchMock);
    const api = createHttpDashboardApi();

    const preview = await api.previewAction(INVENTORY_SKILL.id, 'disable');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse((fetchMock.mock.calls[0]?.[1] as RequestInit).body as string)).toEqual({
      skill_id: INVENTORY_SKILL.id,
      action: 'disable',
      agents: [],
    });

    await api.applyAction(preview.planId);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.parse((fetchMock.mock.calls[1]?.[1] as RequestInit).body as string)).toEqual({
      plan_id: 'plan-1',
    });
  });
});
