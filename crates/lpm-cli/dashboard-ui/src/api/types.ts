export type SkillId = string;

export type SkillCategory = 'managed' | 'package' | 'external';
export type SkillScope = 'global' | 'project';
export type SkillState = 'enabled' | 'disabled' | 'mixed' | 'unavailable';
export type SkillAction = 'enable' | 'disable' | 'update' | 'remove';

export interface SkillTarget {
  agent: string;
  label: string;
  enabled: boolean;
  healthy: boolean;
  status: string;
}

export interface SkillStats {
  files: number;
  words: number;
  lines: number;
  keys: number;
}

export interface Skill {
  id: SkillId;
  name: string;
  namespace: string;
  category: SkillCategory;
  scope: SkillScope;
  state: SkillState;
  agent: string;
  version: string;
  updated: string;
  updatedTs: number;
  description: string;
  path: string;
  files: string[];
  stats: SkillStats;
  context: string;
  integrity: string;
  security: string;
  globs: string;
  body?: string;
  raw?: string;
  warnings: string[];
  targets: SkillTarget[];
  actions: SkillAction[];
}

export interface SkillsSnapshot {
  skills: Skill[];
  skippedLinks: number;
  warningCount: number;
  readOnly: boolean;
}

export type ActionResult =
  | { status: 'ok' }
  | { status: 'error'; message: string };

export interface PlannedChange {
  action: string;
  path: string;
}

export interface PlannedUpdate {
  name?: string;
  diff?: string;
  [key: string]: unknown;
}

export interface ActionPreview {
  planId: string;
  action: SkillAction;
  skill: string;
  scope: SkillScope;
  expiresInSeconds: number;
  changes: PlannedChange[];
  updates: PlannedUpdate[];
  securityWarningCount: number;
}

export interface DashboardApi {
  listSkills(signal?: AbortSignal): Promise<SkillsSnapshot>;
  getSkill(id: SkillId, signal?: AbortSignal): Promise<Skill | null>;
  revealSkill(id: SkillId): Promise<ActionResult>;
  previewAction(id: SkillId, action: SkillAction): Promise<ActionPreview>;
  applyAction(planId: string): Promise<ActionResult>;
}
