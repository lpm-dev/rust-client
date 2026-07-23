import type {
  ActionPreview,
  ActionResult,
  DashboardApi,
  PlannedChange,
  PlannedUpdate,
  Skill,
  SkillAction,
  SkillCategory,
  SkillScope,
  SkillState,
  SkillTarget,
  SkillsSnapshot,
} from './types';

const SESSION_KEY = 'lpm_skills_dashboard_token';

interface InventoryTarget {
  agent: string;
  label: string;
  enabled: boolean;
  healthy: boolean;
}

interface SecurityAssessment {
  status: string;
  warning_count: number;
  block_count: number;
  message?: string;
}

interface InventorySkill {
  id: string;
  kind: SkillCategory;
  name: string;
  description?: string;
  source: string;
  scope: SkillScope;
  package?: string;
  version?: string;
  path?: string;
  context_tokens?: number;
  file_count: number;
  modified_at_ms?: number;
  targets: InventoryTarget[];
  healthy: boolean;
  integrity?: string;
  security: SecurityAssessment;
  actions: SkillAction[];
}

interface InventoryResponse {
  read_only: boolean;
  skipped_entries: number;
  warnings: unknown[];
  skills: InventorySkill[];
}

interface DetailResponse {
  skill: InventorySkill;
  detail: {
    raw?: string;
    body?: string;
    files: string[];
    stats: {
      files: number;
      words: number;
      lines: number;
      frontmatter_keys: number;
    };
    metadata: {
      version?: string;
      globs: string[];
    };
    warnings: string[];
  };
}

interface PreviewResponse {
  plan_id: string;
  expires_in_seconds: number;
  action: SkillAction;
  skill: string;
  scope: SkillScope;
  changes: PlannedChange[];
  updates: PlannedUpdate[];
  security_warning_count: number;
}

class DashboardHttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function captureSessionToken(): string | null {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const launchedToken = fragment.get('token');
  if (launchedToken) {
    window.sessionStorage.setItem(SESSION_KEY, launchedToken);
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    return launchedToken;
  }
  const storedToken = window.sessionStorage.getItem(SESSION_KEY);
  if (storedToken) return storedToken;
  return null;
}

function stateFor(skill: InventorySkill): SkillState {
  if (skill.kind !== 'managed') return skill.healthy ? 'enabled' : 'unavailable';
  const enabled = skill.targets.filter((target) => target.enabled).length;
  if (enabled === 0) return skill.targets.length === 0 ? 'unavailable' : 'disabled';
  return enabled === skill.targets.length ? 'enabled' : 'mixed';
}

function formatTimestamp(timestamp: number | undefined): string {
  if (!timestamp) return '—';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
    .format(timestamp)
    .toLowerCase();
}

function formatContext(tokens: number | undefined): string {
  if (tokens === undefined) return '—';
  if (tokens < 1000) return `~${tokens.toLocaleString('en-US')} tokens`;
  return `~${(tokens / 1000).toFixed(1)}k tokens`;
}

function securitySummary(security: SecurityAssessment): string {
  if (security.status !== 'scanned') return security.message ?? security.status;
  if (security.block_count > 0) {
    return `${security.block_count} ${security.block_count === 1 ? 'block' : 'blocks'}`;
  }
  if (security.warning_count > 0) {
    return `${security.warning_count} ${security.warning_count === 1 ? 'warning' : 'warnings'}`;
  }
  return 'no findings';
}

function targetsFor(targets: InventoryTarget[]): SkillTarget[] {
  return targets.map((target) => ({
    agent: target.agent,
    label: target.label,
    enabled: target.enabled,
    healthy: target.healthy,
  }));
}

function summarySkill(skill: InventorySkill): Skill {
  const agents = [...new Set(skill.targets.map((target) => target.label))];
  const modifiedAt = skill.modified_at_ms ?? 0;
  return {
    id: skill.id,
    name: skill.name,
    namespace: skill.package ?? skill.source,
    category: skill.kind,
    scope: skill.scope,
    state: stateFor(skill),
    agent: agents.length > 0 ? agents.join(', ') : '—',
    version: skill.version ?? '—',
    updated: formatTimestamp(modifiedAt),
    updatedTs: modifiedAt,
    description: skill.description ?? 'Skill metadata is unavailable.',
    path: skill.path ?? '—',
    files: [],
    stats: { files: skill.file_count, words: 0, lines: 0, keys: 0 },
    context: formatContext(skill.context_tokens),
    integrity: skill.integrity ?? (skill.healthy ? 'healthy' : 'needs attention'),
    security: securitySummary(skill.security),
    globs: '—',
    warnings: [],
    targets: targetsFor(skill.targets),
    actions: skill.actions,
  };
}

function detailedSkill(response: DetailResponse): Skill {
  const skill = summarySkill(response.skill);
  return {
    ...skill,
    version: response.detail.metadata.version ?? skill.version,
    files: response.detail.files,
    stats: {
      files: response.detail.stats.files,
      words: response.detail.stats.words,
      lines: response.detail.stats.lines,
      keys: response.detail.stats.frontmatter_keys,
    },
    globs:
      response.detail.metadata.globs.length > 0
        ? response.detail.metadata.globs.join(', ')
        : '—',
    warnings: response.detail.warnings,
    ...(response.detail.body === undefined ? {} : { body: response.detail.body }),
    ...(response.detail.raw === undefined ? {} : { raw: response.detail.raw }),
  };
}

export function createHttpDashboardApi(): DashboardApi {
  const token = captureSessionToken();

  async function request<T>(
    path: string,
    init: RequestInit = {},
    signal?: AbortSignal,
  ): Promise<T> {
    if (!token) {
      throw new Error('Dashboard session is missing. Restart `lpm skills dashboard`.');
    }
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${token}`);
    if (init.body !== undefined) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {
      ...init,
      headers,
      ...(signal === undefined ? {} : { signal }),
    });
    if (!response.ok) {
      const payload = (await response.json().catch(() => null)) as { error?: string } | null;
      throw new DashboardHttpError(
        response.status,
        payload?.error ?? `Dashboard request failed (${response.status}).`,
      );
    }
    return (await response.json()) as T;
  }

  return {
    async listSkills(signal): Promise<SkillsSnapshot> {
      const response = await request<InventoryResponse>('/api/v1/inventory', {}, signal);
      return {
        skills: response.skills.map(summarySkill),
        skippedLinks: response.skipped_entries,
        warningCount: response.warnings.length,
        readOnly: response.read_only,
      };
    },

    async getSkill(id, signal) {
      try {
        const response = await request<DetailResponse>(
          `/api/v1/skills/${encodeURIComponent(id)}`,
          {},
          signal,
        );
        return detailedSkill(response);
      } catch (error) {
        if (error instanceof DashboardHttpError && error.status === 404) return null;
        throw error;
      }
    },

    async revealSkill(id): Promise<ActionResult> {
      await request(`/api/v1/skills/${encodeURIComponent(id)}/reveal`, { method: 'POST' });
      return { status: 'ok' };
    },

    async previewAction(id, action): Promise<ActionPreview> {
      const response = await request<PreviewResponse>('/api/v1/actions/preview', {
        method: 'POST',
        body: JSON.stringify({ skill_id: id, action, agents: [] }),
      });
      return {
        planId: response.plan_id,
        action: response.action,
        skill: response.skill,
        scope: response.scope,
        expiresInSeconds: response.expires_in_seconds,
        changes: response.changes,
        updates: response.updates,
        securityWarningCount: response.security_warning_count,
      };
    },

    async applyAction(planId): Promise<ActionResult> {
      await request('/api/v1/actions/apply', {
        method: 'POST',
        body: JSON.stringify({ plan_id: planId }),
      });
      return { status: 'ok' };
    },
  };
}
