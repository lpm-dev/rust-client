import { expect, it } from 'vitest';
import type { Skill } from '../api/types';
import { skillRawText } from './skillView';

it('raw view preserves the exact authored markdown', () => {
  const raw = '---\nname: exact\ndescription: Exact source\ncustom: keep-me\n---\n\nBody.\n';
  const skill: Skill = {
    id: 'managed:exact',
    name: 'exact',
    namespace: 'local',
    category: 'managed',
    scope: 'project',
    state: 'enabled',
    agent: 'Codex',
    version: '—',
    updated: '—',
    updatedTs: 0,
    description: 'Exact source',
    path: '/tmp/exact',
    files: ['SKILL.md'],
    stats: { files: 1, words: 1, lines: 1, keys: 3 },
    context: '~1 token',
    integrity: 'healthy',
    security: 'no findings',
    globs: '—',
    body: '\nBody.\n',
    raw,
    warnings: [],
    targets: [],
    actions: [],
  };

  expect(skillRawText(skill)).toBe(raw);
});
