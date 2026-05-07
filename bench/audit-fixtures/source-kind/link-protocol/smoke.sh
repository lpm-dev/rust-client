#!/bin/bash
# link: protocol smoke. lpm currently materializes link:-source deps
# the same way as file: (copies bytes rather than symlinking). This
# audit verifies functional correctness — the package loads and
# behaves correctly under both linker modes — without enforcing a
# symlink structure that lpm doesn't currently produce. The
# live-edit semantic (canonical link: behavior in npm/yarn) is a
# separate behavioral question, mode-agnostic, tracked outside this
# audit.
set -e
node -e "
const c = require('linked-counter');
if (c.bump() !== 1 || c.bump() !== 2) {
    console.error('linked-counter state machine broken');
    process.exit(3);
}
"
