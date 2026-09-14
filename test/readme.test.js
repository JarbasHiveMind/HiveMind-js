'use strict';

// The readme is the API reference most users read. These checks keep the
// statements that drifted from the code in line with it, and keep unused
// files out of static/js, which ships to every consumer.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = process.env.HMJS_ROOT || path.join(__dirname, '..');
const readme = fs.readFileSync(path.join(ROOT, 'readme.md'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

describe('readme accuracy', () => {
    test('every file in static/js is used: named in the readme or shipped by package.json', () => {
        const shipped = new Set((pkg.files || []).map(f => path.basename(f)));
        for (const name of fs.readdirSync(path.join(ROOT, 'static', 'js'))) {
            assert.ok(shipped.has(name) || readme.includes(name),
                'static/js/' + name + ' is not referenced');
        }
    });

    test('the onMycroftSpeak row names both spoken-response topics', () => {
        const row = readme.split('\n').find(l => l.startsWith('| `onMycroftSpeak'));
        assert.ok(row, 'onMycroftSpeak row missing');
        assert.match(row, /ovos\.utterance\.speak/);
        assert.match(row, /`speak`/);
    });

    test('the readme states no fixed test count that goes stale', () => {
        assert.doesNotMatch(readme, /\d+\s+tests\s+across\s+\d+\s+files/i);
    });

    test('the readme does not claim the tests run without npm install', () => {
        assert.doesNotMatch(readme, /no npm install needed/i);
    });

    test('every test file the readme names exists', () => {
        const named = new Set(readme.match(/test\/[\w.-]+\.test\.js/g) || []);
        assert.ok(named.size > 0);
        for (const rel of named) {
            assert.ok(fs.existsSync(path.join(ROOT, rel)), rel + ' is named but missing');
        }
    });

    test('the file layout lists the ESM entry point', () => {
        assert.match(readme, /hivemind\.mjs/);
    });
});
