// Reference-only fixture check. Rewriting requires an explicit --write argument.
import assert from 'node:assert/strict';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

assert.ok(process.argv[2], 'Usage: node verify.mjs /path/to/reference/dist/index.mjs [--write]');
assert.ok(process.argv.length === 3 || (process.argv.length === 4 && process.argv[3] === '--write'));
const modulePath = resolve(process.argv[2]);
const metadata = JSON.parse(await readFile(resolve(modulePath, '../../package.json'), 'utf8'));
assert.equal(metadata.name, '@toon-format/toon');
assert.equal(metadata.version, '4.1.1');
const { encode, decode } = await import(pathToFileURL(modulePath).href);
const directory = fileURLToPath(new URL('.', import.meta.url));

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value)
      .sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
      .map(([key, child]) => [key, canonical(child)]));
  }
  return value;
}

const inputs = (await readdir(directory)).filter(name => name.endsWith('.testresult.json')).sort();
assert.ok(inputs.length > 0, 'No contract fixtures found');
for (const input of inputs) {
  const name = input.replace(/\.testresult\.json$/, '.toon');
  const json = await readFile(resolve(directory, name.replace(/\.toon$/, '.json')), 'utf8');
  const expected = JSON.parse(json, (key, value) => {
    assert.ok(typeof value !== 'number' || !Number.isInteger(value) || Number.isSafeInteger(value),
      `${name}: the reference codec cannot verify an unsafe integer at ${key}`);
    return value;
  });
  const encoded = encode(canonical(expected), { indentSize: 2, delimiter: ',' });
  assert.deepEqual(decode(encoded, { indentSize: 2, strict: true }), expected, `${name}: encoder round trip`);
  if (process.argv[3] === '--write') await writeFile(resolve(directory, name), encoded);
  const golden = await readFile(resolve(directory, name), 'utf8');
  assert.equal(encoded, golden, `${name}: bytes`);
  assert.deepEqual(decode(golden, { indentSize: 2, strict: true }), expected, `${name}: JSON model`);
  console.log(`PASS ${name}: exact bytes and decoded JSON`);
}
