import type { Skill } from '../api/types';

/** `@lpm.dev/acme.http-client` + `migration` -> `acme.http-client / migration`. */
export function skillTitle(skill: Skill): string {
  return skill.namespace.startsWith('@lpm.dev/')
    ? `${skill.namespace.replace('@lpm.dev/', '')} / ${skill.name}`
    : skill.name;
}

export function skillCrumb(skill: Skill): string {
  return `${skill.category} skill · ${skill.namespace} · updated ${skill.updated}`;
}

/** Body as authored, or a minimal stand-in when the file has not been read. */
export function skillBody(skill: Skill): string {
  return skill.body ?? `# ${skill.name}\n\n${skill.description}`;
}

export function skillRawText(skill: Skill): string {
  return skill.raw ?? skillBody(skill);
}

export function skillBanner(skill: Skill): string {
  if (skill.category === 'external') {
    return 'inspection only · unmanaged agent-directory skill — run lpm skills add to manage it';
  }
  if (skill.category === 'package') {
    return 'inspection only · this set is owned by an LPM.dev package manifest';
  }
  if (skill.actions.length === 0) {
    return 'managed standalone · inspection only in this dashboard session';
  }
  return 'managed standalone · preview-and-apply actions available';
}

export function isManaged(skill: Skill): boolean {
  return skill.category === 'managed';
}

export function hasSecurityWarning(skill: Skill): boolean {
  return skill.security !== 'no findings' && skill.security !== '—';
}

export interface MetadataRow {
  key: string;
  value: string;
  warn: boolean;
}

export function skillMetadataRows(skill: Skill): MetadataRow[] {
  const warn = hasSecurityWarning(skill);
  return [
    { key: 'name', value: skill.name, warn: false },
    { key: 'description', value: skill.description, warn: false },
    { key: 'version', value: skill.version, warn: false },
    { key: 'globs', value: skill.globs, warn: false },
    { key: 'category', value: skill.category, warn: false },
    { key: 'scope', value: skill.scope, warn: false },
    { key: 'agent target', value: skill.agent, warn: false },
    { key: 'integrity', value: skill.integrity, warn: false },
    { key: 'security', value: skill.security, warn },
    { key: 'est. context', value: skill.context, warn: false },
  ];
}

export interface StatCell {
  label: string;
  value: string;
}

export function skillStatCells(skill: Skill): StatCell[] {
  return [
    { label: 'files', value: String(skill.stats.files) },
    { label: 'body words', value: skill.stats.words.toLocaleString('en-US') },
    { label: 'markdown lines', value: String(skill.stats.lines) },
    { label: 'frontmatter keys', value: String(skill.stats.keys) },
  ];
}

export function fileCountLabel(count: number): string {
  return `${count} ${count === 1 ? 'file' : 'files'}`;
}
