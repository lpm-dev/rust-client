import { createRef } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it } from 'vitest';
import type { Skill } from '../api/types';
import { SkillList } from './SkillList';
import { SkillListItem } from './SkillListItem';

const TARGETS = [
  ['codex', 'Codex'],
  ['claude-code', 'Claude Code'],
  ['kimi', 'Kimi'],
  ['pi', 'Pi'],
  ['cursor', 'Cursor'],
  ['opencode', 'OpenCode'],
  ['grok', 'Grok'],
].map(([agent, label]) => ({
  agent,
  label,
  enabled: true,
  healthy: true,
  status: 'healthy',
}));

function externalSkill(): Skill {
  return {
    id: 'external:shared',
    name: 'shared-skill',
    namespace: 'external agent directory',
    category: 'external',
    scope: 'global',
    state: 'enabled',
    agent: TARGETS.map(({ label }) => label).join(', '),
    version: '—',
    updated: 'now',
    updatedTs: 1,
    description: 'Shared by every supported agent.',
    path: '/tmp/shared-skill',
    files: [],
    stats: { files: 1, words: 10, lines: 2, keys: 0 },
    context: '~10 tokens',
    integrity: '—',
    security: 'no findings',
    globs: '—',
    warnings: [],
    targets: TARGETS,
    actions: [],
  };
}

it('skill rows render every supported agent target as a branded icon', () => {
  const markup = renderToStaticMarkup(
    <SkillListItem
      skill={externalSkill()}
      selected={false}
      tabbable={true}
      onSelect={() => undefined}
    />,
  );

  expect(
    TARGETS.map(({ agent }) => agent).filter((agent) =>
      markup.includes(`data-agent-icon="${agent}"`),
    ),
  ).toEqual(TARGETS.map(({ agent }) => agent));
});

it('filter controls render a sized search icon and inset sort chevron', () => {
  const markup = renderToStaticMarkup(
    <SkillList
      skills={[]}
      counts={{ all: 0, attention: 0, global: 0, project: 0, package: 0 }}
      tab="all"
      onTabChange={() => undefined}
      sort="name"
      onSortChange={() => undefined}
      query=""
      onQueryChange={() => undefined}
      selectedId={null}
      onSelect={() => undefined}
      searchRef={createRef<HTMLInputElement>()}
      status="ready"
      errorMessage={null}
    />,
  );

  expect(markup).toContain('data-ui-icon="search"');
  expect(markup).toContain('width="20"');
  expect(markup).toContain('height="20"');
  expect(markup).toContain('data-ui-icon="sort-chevron"');
});
