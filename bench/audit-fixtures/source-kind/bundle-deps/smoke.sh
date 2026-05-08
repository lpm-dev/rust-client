#!/bin/bash
# bundleDependencies layout-survival smoke. The npm package ships 65
# vendored deps inside its tarball's `node_modules/` dir; we verify
# that subtree survives extraction + linking under both modes.
set -e

# 1. Top-level entries are present.
for entry in npm lodash; do
    if [[ ! -e "node_modules/$entry/package.json" ]]; then
        echo "missing top-level entry: node_modules/$entry"
        exit 2
    fi
done

# 2. npm's tarball-shipped node_modules survived extraction. We
# follow symlinks because both linker modes plant a symlink at
# node_modules/npm/, and the bundled subtree lives under the
# resolved real dir.
bundled_root="$(realpath node_modules/npm)/node_modules"
if [[ ! -d "$bundled_root" ]]; then
    echo "missing bundled subtree: $bundled_root"
    exit 3
fi

bundled_count=$(find "$bundled_root" -mindepth 1 -maxdepth 1 -type d -not -name '.bin' -not -name '.lpm*' | wc -l | tr -d ' ')
if (( bundled_count < 30 )); then
    echo "expected at least 30 bundled deps under npm; got $bundled_count"
    exit 4
fi

# 3. A handful of known-bundled deps must each have a real
# package.json with name + version. Names verified against
# npm@11.14.0's bundleDependencies list (run-time inspection).
# Pin to long-stable entries so this list survives patch bumps.
for bundled in abbrev archy cacache chalk ci-info fastest-levenshtein ini proc-log; do
    pj="$bundled_root/$bundled/package.json"
    if [[ ! -f "$pj" ]]; then
        echo "missing bundled dep: $bundled"
        exit 5
    fi
    node -e "
const m = require('fs').readFileSync('$pj','utf8');
const j = JSON.parse(m);
if (j.name !== '$bundled') { console.error('$bundled package.json has wrong name:', j.name); process.exit(7); }
if (typeof j.version !== 'string' || j.version.length === 0) { console.error('$bundled package.json missing version'); process.exit(8); }
"
done

# 4. npm's own package.json is reachable + reports a v11 version
# (sanity that the package itself extracted correctly, not just the
# bundled subtree).
node -e "
const j = JSON.parse(require('fs').readFileSync('node_modules/npm/package.json', 'utf8'));
if (!j.version.startsWith('11.')) {
    console.error('npm version mismatch:', j.version);
    process.exit(9);
}
if (!Array.isArray(j.bundleDependencies) || j.bundleDependencies.length < 30) {
    console.error('npm package.json bundleDependencies not as expected:',
        Array.isArray(j.bundleDependencies) ? j.bundleDependencies.length : typeof j.bundleDependencies);
    process.exit(10);
}
"
