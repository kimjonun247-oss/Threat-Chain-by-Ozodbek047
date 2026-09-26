// Build the dashboard: web/src/*.ts -> dist/*.js (one readable file per
// script, used when THREATCHAIN_DEBUG_ASSETS=1) and the minified dist/bundle.js
// and dist/bundle.css that the server sends by default.
//
//   node build.mjs          write dist/
//   node build.mjs --check  exit 1 when dist/ differs from what the sources build
//
// dist/ is committed: running ThreatChain needs Python only, never Node.js.
import { transform } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, '..', 'dist');
const manifest = JSON.parse(await readFile(path.join(here, 'bundle.json'), 'utf8'));
const check = process.argv.includes('--check');
const TARGET = 'es2020';
const outputs = new Map();

for (const script of manifest['bundle.js']) {
  const name = script.replace(/\.js$/, '');
  const source = await readFile(path.join(here, 'src', name + '.ts'), 'utf8');
  const { code } = await transform(source, { loader: 'ts', target: TARGET, format: undefined, charset: 'utf8' });
  outputs.set(script, `// Generated from web/src/${name}.ts by web/build.mjs -- edit the source, not this file.\n${code}`);
}
// Classic <script> tags already share one global scope, so joining them in
// page order changes nothing about which names each script sees. The
// separator guards against a file ending without a semicolon.
const joined = manifest['bundle.js'].map(script => outputs.get(script)).join('\n;\n');
outputs.set('bundle.js', (await transform(joined, { loader: 'js', target: TARGET, minify: true, charset: 'utf8' })).code);
const styles = await Promise.all(manifest['bundle.css'].map(sheet => readFile(path.join(dist, sheet), 'utf8')));
outputs.set('bundle.css', (await transform(styles.join('\n'), { loader: 'css', target: 'chrome100', minify: true, charset: 'utf8' })).code);

let stale = [];
for (const [file, content] of outputs) {
  const target = path.join(dist, file);
  const current = await readFile(target, 'utf8').catch(() => null);
  if (current === content) continue;
  if (check) stale.push(file);
  else await writeFile(target, content);
}
if (check && stale.length) {
  console.error('dist/ is out of date with web/src -- run `npm run build` in web/: ' + stale.join(', '));
  process.exit(1);
}
console.log(check ? 'dist/ matches web/src' : `built ${outputs.size} files` );
