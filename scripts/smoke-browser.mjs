import { strict as assert } from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { access, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { createServer as createHttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageRoot = resolve(process.argv[2] ?? repositoryRoot);
const packageJson = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));

// Native import maps exercise the distributed ESM without a bundler replacing
// Node APIs. Package checks separately exercise conditional export resolution.
function browserTarget(value) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') {
    for (const [condition, target] of Object.entries(value)) {
      if (['browser', 'import', 'default'].includes(condition)) {
        const selected = browserTarget(target);
        if (selected) return selected;
      }
    }
  }
  return undefined;
}

const mounts = new Map([['/sdk/', packageRoot]]);
const imports = {};
async function* filesBelow(directory, prefix = '') {
  for (const item of await readdir(join(directory, prefix), { withFileTypes: true })) {
    const path = prefix + item.name;
    if (item.isDirectory()) yield* filesBelow(directory, `${path}/`);
    else if (item.isFile()) yield path;
  }
}
async function mapExports(name, metadata, prefix, directory) {
  const exports = Object.entries(metadata.exports ?? { '.': metadata.main });
  // Browsers cannot express export patterns with suffixes such as *.js in an
  // import map. Expand those patterns against the installed package instead.
  for (const [subpath, target] of exports) {
    const selected = browserTarget(target);
    if (!subpath.includes('*') || !selected) continue;
    const [before, after] = selected.split('*');
    if (after === undefined || selected.split('*').length !== 2) {
      throw new Error(`Unsupported export pattern in ${name}: ${selected}`);
    }
    const base = before.slice(0, before.lastIndexOf('/') + 1);
    for await (const file of filesBelow(join(directory, base))) {
      const candidate = base + file;
      if (!candidate.startsWith(before) || !candidate.endsWith(after)) continue;
      const match = candidate.slice(before.length, after ? -after.length : undefined);
      const specifier = name + subpath.slice(1).replaceAll('*', match);
      imports[specifier] = prefix + candidate.replace(/^\.\//, '');
    }
  }
  // Exact exports take precedence over patterns regardless of declaration order.
  for (const [subpath, target] of exports) {
    if (subpath.includes('*')) continue;
    const selected = browserTarget(target);
    if (selected) imports[name + subpath.slice(1)] = prefix + selected.replace(/^\.\//, '');
  }
}
await mapExports(packageJson.name, packageJson, '/sdk/', packageRoot);
for (const [specifier, target] of Object.entries(packageJson.imports ?? {})) {
  const selected = browserTarget(target);
  if (selected) imports[specifier] = `/sdk/${selected.replace(/^\.\//, '')}`;
}

const dependencies = Object.keys({ ...packageJson.dependencies, ...packageJson.peerDependencies });
const resolution = spawnSync(process.execPath, ['--input-type=module', '-e',
  'console.log(JSON.stringify(Object.fromEntries(process.argv.slice(1).map(name => [name, import.meta.resolve(name)]))))',
  ...dependencies], { cwd: packageRoot, encoding: 'utf8' });
if (resolution.status !== 0) throw new Error(resolution.stderr || 'Cannot resolve package dependencies.');
for (const [name, entry] of Object.entries(JSON.parse(resolution.stdout))) {
  let directory = dirname(fileURLToPath(entry));
  for (;;) {
    let metadata;
    try { metadata = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8')); } catch {}
    if (metadata?.name === name) {
      const prefix = `/dependencies/${name}/`;
      mounts.set(prefix, directory);
      await mapExports(name, metadata, prefix, directory);
      break;
    }
    const parent = dirname(directory);
    if (parent === directory) throw new Error(`Cannot locate package root for ${name}.`);
    directory = parent;
  }
}

const sdk = await import(pathToFileURL(join(packageRoot, browserTarget(packageJson.exports['.']))).href);
const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const json = { z: [null, true, 0, 1e-7, 'é', '𝄞'], a: { b: 2, a: 1 }, future: 'kept' };
const bytes = [0, 1, 2, 127, 128, 255];
const canonical = sdk.canonicalizeJsonValueToBytes(json);
const independentDigest = (value, algorithm = 'sha256') =>
  `${algorithm}:${createHash(algorithm).update(value).digest('hex')}`;
const entry = {
  identifier: 'urn:air:publisher.example:agent:demo',
  type: 'application/json',
  data: json,
  digest: independentDigest(canonical),
};
const signer = 'did:web:publisher.example';
function makeJws(payload, typ, identity = signer) {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ, kid: `${identity}#key` })).toString('base64url');
  const content = Buffer.from(payload).toString('base64url');
  const input = `${header}.${content}`;
  return `${input}.${sign('sha256', Buffer.from(input), {
    key: keys.privateKey, dsaEncoding: 'ieee-p1363',
  }).toString('base64url')}`;
}
const manifest = await sdk.signTrustManifest(entry, { contributor: signer },
  ({ payload, typ }) => makeJws(payload, typ), { issuedAt: '2026-11-19T00:00:00Z' });
const noExposeManifest = await sdk.signTrustManifest(entry, { contributor: 'did:web:no-expose.publisher.example' },
  ({ payload, typ }) => makeJws(payload, typ, 'did:web:no-expose.publisher.example'),
  { issuedAt: '2026-11-19T00:00:00Z' });
const catalog = {
  specVersion: '0.9', entries: [entry],
  signature: { signer, profile: 'did-web-v1', issuedAt: '2026-11-19T00:00:00Z' },
};
catalog.signature.jws = makeJws(sdk.createCatalogSignaturePayload(catalog), 'ai-catalog+jws').replace(/\.[^.]+\./, '..');
const publicKey = keys.publicKey.export({ format: 'jwk' });
const did = {
  id: signer,
  verificationMethod: [{ id: `${signer}#key`, type: 'JsonWebKey2020', controller: signer, publicKeyJwk: publicKey }],
  assertionMethod: ['#key'],
};
const catalogBytes = Buffer.from(JSON.stringify({ specVersion: '0.9', entries: [] }) + ' '.repeat(4096));
const requestCounts = new Map();
const certificate = await readFile(join(repositoryRoot, 'tests/fixtures/transport-cert.pem'));
const privateKey = await readFile(join(repositoryRoot, 'tests/fixtures/transport-key.pem'));
const crossOriginServer = createHttpsServer({ cert: certificate, key: privateKey }, (request, response) => {
  const url = new URL(request.url, `https://${request.headers.host}`);
  requestCounts.set(url.href, (requestCounts.get(url.href) ?? 0) + 1);
  const noCors = url.pathname === '/no-cors' || url.pathname === '/redirect-no-cors' || url.hostname.startsWith('no-cors.');
  const noExpose = url.pathname === '/no-expose' || url.pathname.startsWith('/redirect') ||
    url.pathname === '/.well-known/did.json' || url.hostname.startsWith('no-expose.');
  if (!noCors) response.setHeader('Access-Control-Allow-Origin',
    url.pathname === '/redirect-origin' ? request.headers.origin ?? 'https://unrelated.example' : '*');
  if (!noExpose) response.setHeader('Access-Control-Expose-Headers',
    `Access-Control-Allow-Origin, Access-Control-Expose-Headers${url.pathname === '/hidden-link' ? '' : ', Link'}`);
  response.setHeader('Content-Type', 'application/json');
  if (url.pathname === '/.well-known/did.json') {
    response.writeHead(302, { Location: '/did-document' });
    response.end();
  } else if (url.pathname === '/did-document') {
    const identity = `did:web:${url.hostname}`;
    response.end(JSON.stringify({
      ...did, id: identity,
      verificationMethod: [{ ...did.verificationMethod[0], id: `${identity}#key`, controller: identity }],
    }));
  } else if (url.pathname === '/advertised' || url.pathname === '/broken-advertisement' || url.pathname === '/hidden-link') {
    response.setHeader('Link', `<${url.pathname === '/broken-advertisement' ? '/missing' : '/catalog'}>; rel="ai-catalog"`);
    response.end('homepage');
  } else if (url.pathname === '/page') {
    response.end('homepage');
  } else if (url.pathname === '/missing' || url.hostname !== 'publisher.example') {
    response.writeHead(404);
    response.end();
  } else if (url.pathname.startsWith('/redirect')) {
    const target = url.pathname === '/redirect-chain' ? '/redirect' :
      url.pathname === '/redirect-no-expose' ? '/no-expose' : '/catalog';
    response.writeHead(302, { Location: target });
    response.end();
  } else if (url.pathname === '/stall') {
    response.writeHead(200);
    response.write('{');
  } else if (url.pathname === '/invalid-utf8') {
    response.end(Buffer.from([0xff, 0xfe]));
  } else {
    response.setHeader('Content-Encoding', 'gzip');
    response.end(gzipSync(catalogBytes));
  }
});

function listen(server) {
  return new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolveListen(server.address().port);
    });
  });
}

let finish;
const completion = new Promise((resolveCompletion) => { finish = resolveCompletion; });
const fixture = {
  json, bytes, entry, manifest, noExposeManifest, catalog, publicKey, privateKey: keys.privateKey.export({ format: 'jwk' }),
  canonical: Array.from(canonical),
  digests: Object.fromEntries(['sha256', 'sha384', 'sha512'].map((algorithm) => [algorithm, {
    bytes: independentDigest(Buffer.from(bytes), algorithm), json: independentDigest(canonical, algorithm),
  }])),
  origin: 'https://publisher.example',
  catalogBytes: Array.from(catalogBytes), catalogDigest: independentDigest(catalogBytes),
};
const pageServer = createHttpsServer({ cert: certificate, key: privateKey }, async (request, response) => {
  try {
    const pathname = new URL(request.url, 'https://localhost').pathname;
    if (pathname === '/same-origin') {
      response.setHeader('Content-Type', 'application/json');
      response.setHeader('Access-Control-Allow-Origin', '*');
      response.end(catalogBytes);
    } else if (pathname === '/same-origin-redirect') {
      response.writeHead(302, { Location: `${fixture.origin}/catalog` });
      response.end();
    } else if (pathname === '/fixture') {
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify(fixture));
    } else if (pathname === '/results' && request.method === 'POST') {
      let body = '';
      for await (const chunk of request) body += chunk;
      response.end('ok');
      finish(JSON.parse(body));
    } else if (pathname === '/smoke.js') {
      response.setHeader('Content-Type', 'text/javascript');
      response.end(await readFile(join(repositoryRoot, 'scripts/browser/smoke.js')));
    } else if (pathname === '/') {
      response.setHeader('Content-Type', 'text/html');
      response.end(`<!doctype html><html lang="en"><title>SDK browser smoke test</title>
<script type="importmap">${JSON.stringify({ imports })}</script>
<script type="module">
import('/smoke.js').catch(error => fetch('/results', { method: 'POST', body: JSON.stringify({ fatal: error.stack ?? String(error) }) }));
</script>`);
    } else {
      for (const [prefix, directory] of mounts) {
        if (!pathname.startsWith(prefix)) continue;
        const path = resolve(directory, decodeURIComponent(pathname.slice(prefix.length)));
        const relativePath = relative(directory, path);
        if (isAbsolute(relativePath) || relativePath.startsWith(`..${sep}`) || relativePath === '..') break;
        response.setHeader('Content-Type', 'text/javascript');
        response.end(await readFile(path));
        return;
      }
      response.writeHead(404);
      response.end();
    }
  } catch (error) {
    response.writeHead(500);
    response.end(String(error));
  }
});

async function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const candidates = process.platform === 'darwin'
    ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
    : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  for (const candidate of candidates) {
    try { await access(candidate); return candidate; } catch {}
  }
  throw new Error('Chrome was not found. Set CHROME_PATH to a Chrome or Chromium executable.');
}

let chrome;
let profile;
let timeout;
let chromeLogs = '';
try {
  const chromePath = await findChrome();
  const crossOriginPort = await listen(crossOriginServer);
  const pagePort = await listen(pageServer);
  profile = await mkdtemp(join(tmpdir(), 'ai-catalog-browser-'));
  chrome = spawn(chromePath, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--no-proxy-server',
    // Only this disposable browser accepts the local TLS fixture certificate.
    '--ignore-certificate-errors', `--user-data-dir=${profile}`,
    `--host-resolver-rules=MAP publisher.example:443 127.0.0.1:${crossOriginPort}, MAP *.publisher.example:443 127.0.0.1:${crossOriginPort}`,
    `https://127.0.0.1:${pagePort}/`,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  chrome.stderr.on('data', (chunk) => { chromeLogs = (chromeLogs + chunk).slice(-8000); });
  const result = await Promise.race([
    completion,
    new Promise((_, reject) => {
      chrome.once('error', reject);
      chrome.once('exit', (code) => reject(new Error(`Chrome exited before finishing (${code}).`)));
      timeout = setTimeout(() => reject(new Error(`Browser smoke test timed out.\n${chromeLogs}`)), 30_000);
    }),
  ]);
  if (result.fatal) throw new Error(result.fatal);
  for (const check of result.checks) {
    console.log(`${check.passed ? 'PASS' : 'FAIL'} ${check.name}${check.error ? `: ${check.error}` : ''}`);
  }
  assert.equal(result.checks.filter((check) => !check.passed).length, 0, 'Browser checks failed.');
  const nodeKey = keys.publicKey.toCryptoKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  assert.deepEqual(await sdk.checkTrustManifestSignature(result.browserManifest, {
    publicKey: nodeKey, expectedAlgorithm: 'ES256',
  }), { status: 'valid' });
  assert.ok(requestCounts.get('https://publisher.example/.well-known/did.json') > 0,
    'Automatic DID verification must request the real DID URL.');
  console.log(`Browser smoke test passed (${result.checks.length} checks; browser signature verified in Node).`);
} finally {
  clearTimeout(timeout);
  if (chrome?.pid && chrome.exitCode === null && chrome.signalCode === null) {
    const exited = new Promise((resolveExit) => chrome.once('exit', resolveExit));
    chrome.kill();
    await exited;
  }
  pageServer.closeAllConnections();
  crossOriginServer.closeAllConnections();
  await Promise.all([new Promise((r) => pageServer.close(r)), new Promise((r) => crossOriginServer.close(r))]);
  if (profile) await rm(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
