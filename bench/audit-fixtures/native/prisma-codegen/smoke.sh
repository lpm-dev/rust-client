#!/bin/bash
# Prisma: run `prisma generate` explicitly (real projects do this in
# postinstall, which lpm's script policy may block by default), then
# load @prisma/client and verify the User model methods are wired.
# The generated client lives at node_modules/.prisma/client/ — sibling
# of @prisma/client — exercising the riskiest postinstall pattern.
set -e

node_modules/.bin/prisma generate --schema=./prisma/schema.prisma > /tmp/prisma-gen-$$.log 2>&1 || {
    echo "prisma generate failed:"
    cat /tmp/prisma-gen-$$.log
    rm -f /tmp/prisma-gen-$$.log
    exit 2
}
rm -f /tmp/prisma-gen-$$.log

node -e "
const { PrismaClient } = require('@prisma/client');
const client = new PrismaClient();
if (!client.user || typeof client.user.findFirst !== 'function') {
    console.error('generated client missing User model methods');
    process.exit(3);
}
client.\$disconnect().catch(() => {});
"
