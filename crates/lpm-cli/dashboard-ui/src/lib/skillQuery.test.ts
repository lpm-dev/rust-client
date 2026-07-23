import { expect, it } from 'vitest';
import type { Skill } from '../api/types';
import { selectSkills } from './skillQuery';

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
