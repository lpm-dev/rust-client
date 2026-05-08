"use strict";
// Lives at <project>/src/run.js. Both requires below resolve via Node
// walking up to <project>/node_modules/audit-fixture-self-ref-pkg/ —
// which lpm-linker materializes as a symlink back to <project>/. So
// each `require` round-trips through the self-ref symlink, then back
// to a real file inside the project.
const self = require("audit-fixture-self-ref-pkg");
const util = require("audit-fixture-self-ref-pkg/lib/util");

if (self.greeting !== "hello-from-self-root") {
	console.error("self root export wrong:", self.greeting);
	process.exit(2);
}
if (self.greet("audit") !== "hello, audit, from-self-root") {
	console.error("self root function wrong:", self.greet("audit"));
	process.exit(3);
}
if (util.upper("ok") !== "OK") {
	console.error("self sub-path util wrong:", util.upper("ok"));
	process.exit(4);
}
if (util.kind !== "self-ref-util") {
	console.error("self sub-path util.kind wrong:", util.kind);
	process.exit(5);
}
