#!/bin/bash
# Smoke runs introspect.js — same shape as a real package's
# postinstall script that walks node_modules to find siblings,
# except invoked manually because script-policy=deny blocks
# postinstalls during the audit. The introspection logic and
# its assertions are what matters, not the launch site.
#
# We deliberately do NOT use `set -e` around the node call —
# introspect.js communicates failure via exit code AND stderr
# message, and we want both surfaced in the audit's smoke log
# rather than silently propagated.
node introspect.js
exit $?
