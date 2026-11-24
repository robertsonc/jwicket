// Entry point so that `node --test tests/js/` works on Node 22, which runs a directory argument as a
// module (this file) instead of searching it. It loads every *.test.mjs here; node:test collects them.
// `node --test tests/js/*.test.mjs` runs the same tests without this file.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

for (const name of fs.readdirSync(__dirname).filter((n) => n.endsWith('.test.mjs')).sort()) {
  import(pathToFileURL(path.join(__dirname, name)).href).catch((err) => {
    console.error(`tests/js/${name} did not load:`, err);
    process.exitCode = 1;
  });
}
