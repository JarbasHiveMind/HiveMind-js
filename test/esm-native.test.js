// A browser that runs <script type="module"> with no bundler loads
// hivemind.mjs, and hivemind.mjs imports hivemind.js AS A MODULE. In that
// case there is no `module`, no `require`, and no default export from a
// CommonJS wrapper. Node only gives the same conditions when hivemind.js sits
// in a "type": "module" package, so this test copies the three files into
// such a directory and imports hivemind.mjs from a child process.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const SRC = path.join(__dirname, '..', 'static', 'js');

test('hivemind.mjs imports as native ESM with no CommonJS globals', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hivemind-esm-'));
    try {
        for (const f of ['hivemind.js', 'hivemind.mjs']) {
            fs.copyFileSync(path.join(SRC, f), path.join(dir, f));
        }
        fs.writeFileSync(path.join(dir, 'package.json'), '{"type": "module"}\n');
        // The check runs from a file: `node -e` defines `module` even with
        // --input-type=module, and a browser module has no `module`.
        fs.writeFileSync(path.join(dir, 'probe.js'),
            "export const cjs = typeof module !== 'undefined' || typeof require !== 'undefined';\n");
        fs.writeFileSync(path.join(dir, 'entry.js'), `
            const { cjs } = await import('./probe.js');
            if (cjs) throw new Error('CommonJS globals present');
            const m = await import('./hivemind.mjs');
            if (typeof m.JarbasHiveMind !== 'function') throw new Error('JarbasHiveMind missing');
            if (typeof m.default.JarbasHiveMind !== 'function') throw new Error('default export missing');
            if (typeof m.encodeBitstring !== 'function') throw new Error('encodeBitstring missing');
            console.log(JSON.stringify({ ok: true, version: m.HM_VERSION, suites: Array.isArray(m.NOISE_SUITES_JS) }));
        `);
        const out = execFileSync(process.execPath, [path.join(dir, 'entry.js')],
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        const res = JSON.parse(out.trim().split('\n').pop());
        assert.equal(res.ok, true);
        assert.equal(res.version, require('../package.json').version);
        assert.equal(res.suites, true);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
