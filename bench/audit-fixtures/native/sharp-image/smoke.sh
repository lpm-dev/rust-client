#!/bin/bash
# Sharp: produce a tiny PNG via libvips. Exercises the entire stack
# (binding load + native call). Failure here means the postinstall
# binary download didn't land where Node's binding loader looks.
set -e
node -e "
const sharp = require('sharp');
sharp({ create: { width: 8, height: 8, channels: 3, background: { r: 0, g: 128, b: 255 } } })
    .png()
    .toBuffer()
    .then(buf => {
        if (buf.length < 50) { console.error('PNG too small:', buf.length); process.exit(2); }
    })
    .catch(err => { console.error('sharp failed:', err.message); process.exit(3); });
"
