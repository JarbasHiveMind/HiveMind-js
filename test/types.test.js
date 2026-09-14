'use strict';

// The package ships hand-written TypeScript declarations
// (static/js/hivemind.d.ts). This compiles the readme examples against them
// through the package's own "exports", so a declaration that drifts from the
// documented API, or a package.json that stops pointing at it, fails here.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

test('package.json points every entry at the shipped declarations', () => {
    assert.equal(pkg.types, 'static/js/hivemind.d.ts');
    assert.equal(pkg.exports['.'].types, './static/js/hivemind.d.ts');
    assert.equal(Object.keys(pkg.exports['.'])[0], 'types', 'the types condition must come first');
    assert.ok(pkg.files.includes('static/js/hivemind.d.ts'), 'the declarations are not published');
    assert.ok(fs.existsSync(path.join(root, 'static/js/hivemind.d.ts')));
});

test('the readme examples type-check against the declarations', { timeout: 180000 }, () => {
    const r = spawnSync('npx', [
        '--yes', '-p', 'typescript@5.6.3', 'tsc',
        '--noEmit', '--strict', '--target', 'es2022', '--lib', 'es2022,dom',
        '--module', 'esnext', '--moduleResolution', 'bundler',
        'test/types/readme-usage.ts',
    ], { cwd: root, encoding: 'utf8', shell: process.platform === 'win32' });
    assert.equal(r.status, 0, 'tsc failed:\n' + (r.stdout || '') + (r.stderr || ''));
});
