import { expect, it } from 'vitest';
import type { Skill } from '../api/types';
import { countBySource, selectSkills } from './skillQuery';

function skill(name: string, context: string): Skill {
  return {
    id: `managed:${name}`,
    name,
    namespace: 'local',
    category: 'managed',
    scope: 'project',
    state: 'enabled',
    agent: 'Codex',
    version: '—',
    updated: '—',
    updatedTs: 0,
    description: name,
    path: `/tmp/${name}`,
    files: ['SKILL.md'],
    stats: { files: 1, words: 1, lines: 1, keys: 2 },
    context,
    integrity: 'healthy',
    security: 'no findings',
    globs: '—',
    warnings: [],
    targets: [],
    actions: [],
  };
}

it('context size sort accounts for abbreviated thousands', () => {
  const skills = [skill('small', '~950 tokens'), skill('large', '~1.3k tokens')];

  const sorted = selectSkills(skills, { tab: 'all', query: '', sort: 'size' });

  expect(sorted.map(({ name }) => name)).toEqual(['large', 'small']);
});

it('needs attention source selects unavailable and security-flagged skills', () => {
  const unavailable = skill('broken-link', '~0 tokens');
  unavailable.state = 'unavailable';
  const flagged = skill('unsafe-content', '~100 tokens');
  flagged.security = '1 warning';
  const healthy = skill('healthy', '~100 tokens');

  const selected = selectSkills([healthy, flagged, unavailable], {
    tab: 'attention',
    query: '',
    sort: 'name',
  });

  expect(selected.map(({ name }) => name)).toEqual(['broken-link', 'unsafe-content']);
});

it('source counts include skills that need attention', () => {
  const unavailable = skill('broken-link', '~0 tokens');
  unavailable.state = 'unavailable';
  const flagged = skill('unsafe-content', '~100 tokens');
  flagged.security = '1 warning';

  const counts = countBySource([skill('healthy', '~100 tokens'), flagged, unavailable]);

  expect(counts.attention).toBe(2);
});
