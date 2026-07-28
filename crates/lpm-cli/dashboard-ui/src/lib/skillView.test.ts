import { expect, it } from 'vitest';
import type { Skill } from '../api/types';
import { skillBanner, skillRawText } from './skillView';

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

it('broken external link banner explains the missing target', () => {
  const skill: Skill = {
    id: 'external:broken',
    name: 'broken',
    namespace: 'external agent directory',
    category: 'external',
    scope: 'global',
    state: 'unavailable',
    agent: 'Claude Code',
    version: '—',
    updated: '—',
    updatedTs: 0,
    description: 'Broken agent skill link. Its target no longer exists.',
    path: '/tmp/broken',
    files: [],
    stats: { files: 0, words: 0, lines: 0, keys: 0 },
    context: '—',
    integrity: 'broken-link',
    security: 'external skill target is a broken link',
    globs: '—',
    warnings: [],
    targets: [],
    actions: [],
  };

  expect(skillBanner(skill)).toBe(
    'needs attention · broken agent-directory link — target no longer exists',
  );
});
