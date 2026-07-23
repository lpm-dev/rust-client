export interface FileTreeRow {
  /** Stable key: the original relative path for files, `dir/` for folders. */
  id: string;
  kind: 'directory' | 'file';
  label: string;
  /** Files inside a directory render one level in. */
  nested: boolean;
}

/**
 * Flattens `['SKILL.md', 'references/tokens.md']` into the two-level list the
 * files tab renders: each directory header followed by its children, then the
 * files that sit at the skill root.
 */
export function buildFileTree(files: readonly string[]): FileTreeRow[] {
  const directories = new Map<string, string[]>();
  const rootFiles: string[] = [];

  for (const file of files) {
    const slash = file.indexOf('/');
    if (slash === -1) {
      rootFiles.push(file);
      continue;
    }
    const dir = file.slice(0, slash);
    const rest = file.slice(slash + 1);
    const bucket = directories.get(dir);
    if (bucket) bucket.push(rest);
    else directories.set(dir, [rest]);
  }

  const rows: FileTreeRow[] = [];

  for (const [dir, children] of directories) {
    rows.push({ id: `${dir}/`, kind: 'directory', label: `${dir}/`, nested: false });
    for (const child of children) {
      rows.push({ id: `${dir}/${child}`, kind: 'file', label: child, nested: true });
    }
  }

  for (const file of rootFiles) {
    rows.push({ id: file, kind: 'file', label: file, nested: false });
  }

  return rows;
}
