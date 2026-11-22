import * as sdk from 'ai-catalog-sdk';
import { aiCatalogSchema } from 'ai-catalog-sdk/zod';
import { aiCatalogJsonSchema } from 'ai-catalog-sdk/json-schema';

const fixture = await (await fetch('/fixture')).json();
const checks = [];
async function check(name, operation) {
  try {
    await operation();
    checks.push({ name, passed: true });
  } catch (error) {
    checks.push({ name, passed: false, error: error.stack ?? String(error) });
  }
}
function equal(actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(JSON.stringify({ actual, expected }));
  }
}
function found(result) {
  equal(result.status, 'found');
  return result;
}
const entryFor = (path) => ({
  identifier: 'nested', type: 'application/ai-catalog+json', url: fixture.origin + path,
});
const nowMs = Date.parse('2026-11-20T12:00:00Z');
const publicKey = await crypto.subtle.importKey('jwk', fixture.publicKey,
  { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
const signatureOptions = { publicKey, expectedAlgorithm: 'ES256', nowMs };

await check('JavaScript entry points run without Node globals', () => {
  equal([typeof globalThis.Buffer, typeof globalThis.process, isSecureContext], ['undefined', 'undefined', true]);
  const value = { specVersion: '0.9', entries: [], future: { kept: true } };
  equal(sdk.parseCatalog(value), value);
  equal(aiCatalogSchema.parse(value), value);
  equal(aiCatalogJsonSchema.$schema, 'https://json-schema.org/draft/2020-12/schema');
});
await check('canonical JSON bytes match Node', () => {
  equal(Array.from(sdk.canonicalizeJsonValueToBytes(fixture.json)), fixture.canonical);
});
for (const algorithm of ['sha256', 'sha384', 'sha512']) {
  await check(`${algorithm} hashes JSON and byte subviews identically to Node crypto`, async () => {
    const bytes = new Uint8Array([9, ...fixture.bytes, 8]).subarray(1, -1);
    equal(await sdk.createDigest(bytes, algorithm), fixture.digests[algorithm].bytes);
    equal(await sdk.createDigest(fixture.json, algorithm), fixture.digests[algorithm].json);
  });
}
await check('digest verification distinguishes match and mismatch', async () => {
  equal(await sdk.checkDigest(fixture.json, fixture.digests.sha256.json), { status: 'match' });
  equal(await sdk.checkDigest(fixture.json, `sha256:${'0'.repeat(64)}`), { status: 'mismatch' });
});
await check('Node signatures verify with native browser CryptoKey', async () => {
  equal(await sdk.checkTrustManifestSignature(fixture.manifest, signatureOptions), { status: 'valid' });
  equal(await sdk.checkCatalogSignature(fixture.catalog, signatureOptions), { status: 'valid' });
});
await check('tampered signed content fails verification', async () => {
  equal(await sdk.checkTrustManifestSignature({ ...fixture.manifest, extensions: { changed: true } },
    signatureOptions), { status: 'invalid_signature' });
});
await check('entry verification resolves its DID over real browser HTTPS', async () => {
  const result = await sdk.checkCatalogEntry({ ...fixture.entry, trustManifests: [fixture.manifest] }, { nowMs });
  equal(result.status, 'checked');
  equal(result.manifests.map(({ status, isPublisherEndorsement }) => ({ status, isPublisherEndorsement })),
    [{ status: 'passed', isPublisherEndorsement: true }]);
});

const signingKey = await crypto.subtle.importKey('jwk', fixture.privateKey,
  { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
const browserManifest = await sdk.signTrustManifest(fixture.entry, { contributor: 'did:web:publisher.example' },
  async ({ payload, typ }) => {
    const protectedHeader = base64url(new TextEncoder().encode(JSON.stringify({
      alg: 'ES256', typ, kid: 'did:web:publisher.example#key',
    })));
    const input = `${protectedHeader}.${base64url(payload)}`;
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey,
      new TextEncoder().encode(input));
    return `${input}.${base64url(new Uint8Array(signature))}`;
  }, { issuedAt: '2026-11-19T00:00:00Z' });
await check('browser signing helper produces a verifiable signature', async () => {
  equal(await sdk.checkTrustManifestSignature(browserManifest, signatureOptions), { status: 'valid' });
});

await check('cross-origin catalog loading retains decoded gzip bytes', async () => {
  const result = found(await sdk.loadCatalogFromEntry(entryFor('/catalog')));
  equal(Array.from(result.bytes), fixture.catalogBytes);
  equal(await sdk.checkDigest(result.bytes, fixture.catalogDigest), { status: 'match' });
});
await check('automatic redirect reports the final catalog URL', async () => {
  equal(found(await sdk.loadCatalogFromEntry(entryFor('/redirect'))).url, `${fixture.origin}/catalog`);
});
await check('decoded byte limit bounds compressed responses', async () => {
  equal((await sdk.loadCatalogFromEntry(entryFor('/catalog'), { maxResponseBytes: 128 })).status, 'fetch_failed');
});
await check('timeout includes an unfinished response body', async () => {
  equal((await sdk.loadCatalogFromEntry(entryFor('/stall'), { resourceTimeoutMs: 100 })).status, 'fetch_failed');
});
await check('caller cancellation rejects with its exact reason', async () => {
  const controller = new AbortController();
  const reason = { canceled: 'browser test' };
  const request = sdk.loadCatalogFromEntry(entryFor('/stall'), { signal: controller.signal });
  const timer = setTimeout(() => controller.abort(reason), 20);
  try {
    await request;
    throw new Error('The canceled operation resolved.');
  } catch (error) {
    if (error !== reason) throw error;
  } finally {
    clearTimeout(timer);
  }
});
await check('invalid UTF-8 is an invalid catalog result', async () => {
  equal((await sdk.loadCatalogFromEntry(entryFor('/invalid-utf8'))).status, 'invalid_catalog');
});
await check('advertised catalog failures are terminal', async () => {
  equal((await sdk.discoverCatalog(`${fixture.origin}/broken-advertisement`)).status, 'fetch_failed');
});
await check('well-known-only discovery skips an advertised failure', async () => {
  found(await sdk.discoverCatalog(`${fixture.origin}/broken-advertisement`, { strategy: 'well-known' }));
});
await check('normal browser visibility hides unexposed advertisements', async () => {
  equal((await fetch(`${fixture.origin}/hidden-link`)).headers.get('Link'), null);
  found(await sdk.discoverCatalog(`${fixture.origin}/hidden-link`));
});
await check('normal mode allows readable responses without inspection headers', async () => {
  equal((await sdk.loadCatalogFromEntry(entryFor('/no-cors'))).status, 'fetch_failed');
  found(await sdk.loadCatalogFromEntry(entryFor('/no-expose')));
  equal((await sdk.discoverCatalog('https://no-expose.publisher.example/page', { strategy: 'well-known' })).status,
    'not_found');
});

await check('strict mode requires exposure declarations even for readable same-origin responses', async () => {
  const url = `${location.origin}/same-origin`;
  equal((await fetch(url)).headers.get('Access-Control-Allow-Origin'), '*');
  const entry = { identifier: 'nested', type: 'application/ai-catalog+json', url };
  found(await sdk.loadCatalogFromEntry(entry));
  sdk.configure({ requirePublicAccessHeaders: true });
  try {
    equal((await sdk.loadCatalogFromEntry(entry)).status, 'fetch_failed');
  } finally {
    sdk.configure({ requirePublicAccessHeaders: false });
  }
});

await check('normal mode resolves a readable DID without inspection headers', async () => {
  const result = await sdk.checkCatalogEntry({ ...fixture.entry, trustManifests: [fixture.noExposeManifest] }, { nowMs });
  equal(result.status, 'checked');
  equal(result.manifests[0].status, 'passed');
});

await check('entry verification captures configuration before asynchronous digest work', async () => {
  const entry = { ...fixture.entry, trustManifests: [fixture.noExposeManifest] };
  const ordinaryRequest = sdk.checkCatalogEntry(entry, { nowMs });
  sdk.configure({ requirePublicAccessHeaders: true });
  try {
    const ordinary = await ordinaryRequest;
    equal(ordinary.status, 'checked');
    equal(ordinary.manifests[0].status, 'passed');
    const strictRequest = sdk.checkCatalogEntry(entry, { nowMs });
    sdk.configure({ requirePublicAccessHeaders: false });
    const strict = await strictRequest;
    equal(strict.status, 'checked');
    equal(strict.manifests[0].status, 'issuer_check_failed');
  } finally {
    sdk.configure({ requirePublicAccessHeaders: false });
  }
});

sdk.configure({ requirePublicAccessHeaders: true });
await check('strict mode accepts the response contract and exposed advertisement', async () => {
  found(await sdk.discoverCatalog(`${fixture.origin}/advertised`));
  found(await sdk.loadCatalogFromEntry(entryFor('/catalog')));
  found(await sdk.loadCatalogFromEntry(entryFor('/redirect')));
  equal((await sdk.loadCatalogFromEntry(entryFor('/redirect-no-expose'))).status, 'fetch_failed');
});
await check('strict mode follows public redirects without intermediate header exposure', async () => {
  equal(found(await sdk.loadCatalogFromEntry(entryFor('/redirect-chain'))).url, `${fixture.origin}/catalog`);
});
await check('strict mode preserves browser access through an origin-specific redirect', async () => {
  equal(found(await sdk.loadCatalogFromEntry(entryFor('/redirect-origin'))).url, `${fixture.origin}/catalog`);
});
await check('strict mode preserves browser access through a same-origin redirect without CORS headers', async () => {
  const entry = { identifier: 'nested', type: 'application/ai-catalog+json', url: `${location.origin}/same-origin-redirect` };
  equal(found(await sdk.loadCatalogFromEntry(entry)).url, `${fixture.origin}/catalog`);
});
await check('strict mode fails when a cross-origin redirect omits browser permission', async () => {
  equal((await sdk.loadCatalogFromEntry(entryFor('/redirect-no-cors'))).status, 'fetch_failed');
});
await check('strict mode allows well-known fallback after a verifiably absent advertisement', async () => {
  found(await sdk.discoverCatalog(`${fixture.origin}/page`));
});
await check('strict mode checks advertisement visibility even if Link is hidden', async () => {
  equal((await sdk.discoverCatalog(`${fixture.origin}/hidden-link`)).status, 'fetch_failed');
});
await check('strict mode treats unreadable and uninspectable responses as the same failure', async () => {
  const blocked = await sdk.loadCatalogFromEntry(entryFor('/no-cors'));
  const uninspectable = await sdk.loadCatalogFromEntry(entryFor('/no-expose'));
  equal([blocked.status, uninspectable.status], ['fetch_failed', 'fetch_failed']);
  equal(blocked.error.message, uninspectable.error.message);
});
await check('strict mode retains the native browser fetch failure as a diagnostic cause', async () => {
  const blocked = await sdk.loadCatalogFromEntry(entryFor('/no-cors'));
  equal(blocked.status, 'fetch_failed');
  let cause = blocked.error.cause;
  while (cause instanceof Error && !(cause instanceof TypeError)) cause = cause.cause;
  if (!(cause instanceof TypeError)) throw new Error('The native fetch TypeError was not retained.');
});
await check('strict mode checks headers before interpreting a 404 as absence', async () => {
  const blocked = await sdk.discoverCatalog('https://no-cors.publisher.example/page', { strategy: 'well-known' });
  const uninspectable = await sdk.discoverCatalog('https://no-expose.publisher.example/page', { strategy: 'well-known' });
  equal([blocked.status, uninspectable.status], ['fetch_failed', 'fetch_failed']);
  equal(blocked.error.message, uninspectable.error.message);
  equal((await sdk.discoverCatalog('https://missing.publisher.example/page', { strategy: 'well-known' })).status,
    'not_found');
});
await check('strict mode propagates into automatic DID resolution through redirects', async () => {
  const result = await sdk.checkCatalogEntry({ ...fixture.entry, trustManifests: [fixture.manifest] }, { nowMs });
  equal(result.status, 'checked');
  equal(result.manifests[0].status, 'passed');
  const uninspectable = await sdk.checkCatalogEntry({ ...fixture.entry, trustManifests: [fixture.noExposeManifest] }, { nowMs });
  equal(uninspectable.status, 'checked');
  equal(uninspectable.manifests[0].status, 'issuer_check_failed');
});
sdk.configure({ requirePublicAccessHeaders: false });

await fetch('/results', { method: 'POST', body: JSON.stringify({ checks, browserManifest }) });
