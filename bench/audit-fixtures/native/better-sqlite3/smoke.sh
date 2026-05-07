#!/bin/bash
# better-sqlite3: open in-memory DB, run a query, close. Exercises
# the compiled .node binding load.
set -e
node -e "
const Database = require('better-sqlite3');
const db = new Database(':memory:');
const result = db.prepare('SELECT 1 + 1 AS x').get();
if (result.x !== 2) { console.error('unexpected result:', result); process.exit(2); }
db.close();
"
