"use strict";
// Simulates a real package's postinstall walking node_modules to find
// siblings. Lifecycle scripts in this audit are blocked by
// script-policy=deny, so smoke.sh runs this script manually after
// install. The behavior is what matters, not the script's launch
// site.
//
// Real-world postinstall walkers (e.g., @grpc/grpc-js, react-native
// native-binding loaders, node-gyp-build helpers) operate in two
// modes:
//   A. Walk from `INIT_CWD` (the project root) to find consumer-level
//      direct deps. This is mode-agnostic — both linker modes plant
//      direct deps at <root>/node_modules/<name>/ either as a real
//      dir or a symlink.
//   B. Walk from `process.cwd()` (the package's resolved location)
//      to find OWN dependencies. Under hoisted, Node walks up to
//      <root>/node_modules/. Under isolated, Node walks up to the
//      wrappers tree segment that contains the package + its declared
//      deps. EITHER WAY, the package's declared deps must resolve
//      from inside its own resolved real path — that's the contract
//      package authors rely on.
//
// We test BOTH walker modes here. (A) covers the consumer-side
// expectation; (B) covers the package-side runtime contract. A bug
// in either trips a specific check rather than a generic failure.
const fs = require("fs");
const path = require("path");

const work = process.cwd();
const nm = path.join(work, "node_modules");

// === Walker mode A: from project root (INIT_CWD-style). ===
const topDirect = fs.readdirSync(nm).filter((e) => !e.startsWith("."));
for (const expected of ["chalk", "lodash", "ms"]) {
	if (!topDirect.includes(expected)) {
		console.error(`top-level scan missing direct dep: ${expected}; saw:`, topDirect);
		process.exit(2);
	}
	const pj = path.join(nm, expected, "package.json");
	if (!fs.existsSync(pj)) {
		console.error(`top-level dep ${expected} has no package.json at ${pj}`);
		process.exit(3);
	}
	const m = JSON.parse(fs.readFileSync(pj, "utf8"));
	if (m.name !== expected) {
		console.error(`top-level ${expected} has wrong name field: ${m.name}`);
		process.exit(4);
	}
}

// === Walker mode B: from inside chalk's resolved real path. ===
// chalk's real-world postinstall (if it had one walking siblings)
// would run with cwd = the resolved real dir, exactly what
// `realpathSync` gives us. From there, chalk's DECLARED deps must
// each `require()` cleanly. chalk@4 declares: ansi-styles,
// supports-color (which are its direct deps; color-convert and
// has-flag come in transitively).
const chalkReal = fs.realpathSync(path.join(nm, "chalk"));

// Sanity: chalk is visible to itself in its own siblings list. This
// catches a layout where the linker dropped chalk's parent dir.
const chalkSiblings = fs.readdirSync(path.dirname(chalkReal)).filter((e) => !e.startsWith("."));
if (!chalkSiblings.includes("chalk")) {
	console.error("from-chalk: chalk not visible to itself in siblings list:", chalkSiblings);
	process.exit(5);
}

// Functional: spawn a child node process from chalk's real cwd and
// require each of chalk's DECLARED deps. This is the contract that
// real walkers depend on — the package's own deps reachable from
// the package's own dir. Under hoisted, Node walks up to root
// node_modules. Under isolated, Node walks up to the wrappers
// segment. Both must work.
const child = require("child_process");
for (const dep of ["ansi-styles", "supports-color"]) {
	const result = child.spawnSync(
		process.execPath,
		[
			"-e",
			`const m = require('${dep}'); if (typeof m !== 'object' && typeof m !== 'function') { process.exit(13) }`,
		],
		{ cwd: chalkReal, encoding: "utf8" }
	);
	if (result.status !== 0) {
		console.error(
			`from-chalk: require('${dep}') failed (chalk's own declared dep); stderr:`,
			result.stderr.trim()
		);
		process.exit(6);
	}
}

// Transitive deps (chalk → ansi-styles → color-convert; chalk →
// supports-color → has-flag) are intentionally NOT tested from
// chalk's cwd. Each package's resolved location only exposes its
// OWN declared deps via Node's walk-up — transitives get exercised
// by the INTERMEDIATE package's own require chain (e.g.,
// ansi-styles requires color-convert from ansi-styles' cwd, not
// from chalk's). Asserting otherwise would test a non-contract and
// fail on any package manager that uses content-addressed storage
// (lpm v2, pnpm, yarn berry pnp).

// === Walker mode B for a leaf package (lodash). ===
// lodash has no transitive deps — its wrappers segment under
// isolated mode is therefore minimal. This catches a bug where the
// linker over-trims a leaf's wrappers dir.
const lodashReal = fs.realpathSync(path.join(nm, "lodash"));
const lodashSiblings = fs.readdirSync(path.dirname(lodashReal)).filter((e) => !e.startsWith("."));
if (!lodashSiblings.includes("lodash")) {
	console.error("from-lodash: lodash not visible to itself in siblings list:", lodashSiblings);
	process.exit(8);
}

console.log("OK");
