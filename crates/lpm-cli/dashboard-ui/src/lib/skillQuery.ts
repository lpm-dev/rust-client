import type { Skill } from '../api/types';
import { needsAttention } from './skillView';

export type SourceTabId = 'all' | 'attention' | 'global' | 'project' | 'package';
export type SortId = 'name' | 'updated' | 'size' | 'state';

export const SOURCE_TABS: ReadonlyArray<{ id: SourceTabId; label: string }> = [
  { id: 'all', label: 'all sources' },
  { id: 'attention', label: 'needs attention' },
  { id: 'global', label: 'global' },
  { id: 'project', label: 'project' },
  { id: 'package', label: 'package' },
];

export const SORT_OPTIONS: ReadonlyArray<{ id: SortId; label: string }> = [
  { id: 'name', label: 'name' },
  { id: 'updated', label: 'updated' },
  { id: 'size', label: 'context size' },
  { id: 'state', label: 'state' },
];

export type SourceCounts = Record<SourceTabId, number>;

export function countBySource(skills: readonly Skill[]): SourceCounts {
  return {
    all: skills.length,
    attention: skills.filter(needsAttention).length,
    global: skills.filter((s) => s.scope === 'global').length,
    project: skills.filter((s) => s.scope === 'project').length,
    package: skills.filter((s) => s.category === 'package').length,
  };
}

function matchesSource(skill: Skill, tab: SourceTabId): boolean {
  switch (tab) {
    case 'attention':
      return needsAttention(skill);
    case 'global':
      return skill.scope === 'global';
    case 'project':
      return skill.scope === 'project';
    case 'package':
      return skill.category === 'package';
    case 'all':
      return true;
  }
}

/** `~6.2k tokens` -> 6.2. Used only for relative ordering. */
function contextWeight(context: string): number {
  const match = context.match(/([\d.]+)\s*(k)?\s+tokens/i);
  if (!match) return 0;
  const parsed = Number.parseFloat(match[1] ?? '');
  if (Number.isNaN(parsed)) return 0;
  return match[2] ? parsed * 1000 : parsed;
}

function compare(a: Skill, b: Skill, sort: SortId): number {
  switch (sort) {
    case 'updated':
      return b.updatedTs - a.updatedTs;
    case 'size':
      return contextWeight(b.context) - contextWeight(a.context);
    case 'state':
      return a.state.localeCompare(b.state);
    case 'name':
      return a.name.localeCompare(b.name);
  }
}

export function selectSkills(
  skills: readonly Skill[],
  options: { tab: SourceTabId; query: string; sort: SortId },
): Skill[] {
  const query = options.query.trim().toLowerCase();

  const filtered = skills.filter((skill) => {
    if (!matchesSource(skill, options.tab)) return false;
    if (!query) return true;
    return `${skill.name} ${skill.namespace} ${skill.description}`
      .toLowerCase()
      .includes(query);
  });

  return filtered.sort((a, b) => compare(a, b, options.sort));
}
