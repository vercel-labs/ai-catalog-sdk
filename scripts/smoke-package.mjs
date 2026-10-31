import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const temporaryDirectory = await mkdtemp(join(tmpdir(), 'ai-catalog-sdk-'));
const consumerDirectory = join(temporaryDirectory, 'consumer');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const node = process.execPath;
const childEnvironment = { ...process.env };
for (const key of Object.keys(childEnvironment)) {
  if (
    key.startsWith('npm_package_') ||
    key.startsWith('npm_lifecycle_') ||
    [
      'INIT_CWD',
      'PNPM_SCRIPT_SRC_DIR',
      'npm_command',
      'npm_config_user_agent',
      'npm_execpath',
      'npm_node_execpath',
    ].includes(key)
  ) {
    delete childEnvironment[key];
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    encoding: 'utf8',
    env: childEnvironment,
    stdio: options.capture ? 'pipe' : 'inherit',
  });
  if (result.status !== 0) {
    if (options.capture) {
      process.stderr.write(result.stdout ?? '');
      process.stderr.write(result.stderr ?? '');
    }
    throw new Error(
      `${command} ${args.join(' ')} failed with exit code ${result.status}`,
    );
  }
  return result.stdout ?? '';
}

try {
  const packOutput = run(
    npm,
    ['pack', '--json', '--pack-destination', temporaryDirectory],
    { capture: true },
  );
  const [packed] = JSON.parse(packOutput);
  if (!packed?.filename) {
    throw new Error('npm pack did not report a tarball filename');
  }

  console.log(`Packed ${packed.filename}`);
  for (const file of packed.files ?? []) console.log(`  ${file.path}`);

  await mkdir(consumerDirectory);
  await writeFile(
    join(consumerDirectory, 'package.json'),
    JSON.stringify({ private: true, type: 'module' }, null, 2),
  );
  run(
    npm,
    [
      'install',
      '--ignore-scripts',
      '--no-package-lock',
      '--no-audit',
      '--no-fund',
      '--fetch-retries=1',
      '--fetch-timeout=30000',
      '@types/node@24.12.4',
      'zod@4.4.0',
      join(temporaryDirectory, packed.filename),
    ],
    { cwd: consumerDirectory },
  );

  await writeFile(
    join(consumerDirectory, 'smoke.mjs'),
    `import { strict as assert } from 'node:assert';
import { generateKeyPairSync, sign } from 'node:crypto';
import { implementedSpecRevision, parseCatalog } from ${JSON.stringify(pkg.name)};
import { aiCatalogSchema } from ${JSON.stringify(`${pkg.name}/zod`)};
import { aiCatalogJsonSchema } from ${JSON.stringify(`${pkg.name}/json-schema`)};
import { canonicalizeJsonValueToBytes, checkCatalogEntry, checkCatalogEntryArtifactBinding, checkCatalogSignature, checkDigest, checkTrustManifestSignature, createCatalogSignaturePayload, createTrustManifestSignaturePayload, signTrustManifest } from ${JSON.stringify(`${pkg.name}/verification`)};
import rawSchema from ${JSON.stringify(`${pkg.name}/schema/ai-catalog.schema.json`)} with { type: 'json' };

const value = { specVersion: '1.0', entries: [] };
assert.deepEqual(parseCatalog(value).entries, []);
const opaqueHostManifest = { formerField: ['opaque', 1, null] };
const catalogWithOpaqueHost = parseCatalog({
  ...value,
  host: { displayName: 'Example', trustManifest: opaqueHostManifest },
});
assert.deepEqual(catalogWithOpaqueHost.host.trustManifest, opaqueHostManifest);
assert.equal(aiCatalogSchema.safeParse(value).success, true);
const futureContentCatalog = {
  ...value,
  entries: [{
    identifier: 'future-content',
    type: 'application/json',
    data: null,
    trustManifests: [{ contributor: 'urn:example:contributor', futureEvidence: null }],
  }],
};
assert.deepEqual(parseCatalog(futureContentCatalog), futureContentCatalog);
assert.equal(aiCatalogSchema.safeParse(futureContentCatalog).success, true);
const futureContentReport = await checkCatalogEntry(futureContentCatalog.entries[0]);
assert.equal(futureContentReport.status, 'checked');
assert.deepEqual(futureContentReport.manifests.map(result => result.status), ['missing_signature']);
for (const futureFields of [{}, { futureEvidence: null }]) {
  const malformedCatalog = {
    ...value,
    entries: [{
      ...futureContentCatalog.entries[0],
      trustManifests: [{ contributor: 'urn:example:contributor', attestations: 'invalid', ...futureFields }],
    }],
  };
  assert.throws(() => parseCatalog(malformedCatalog));
  assert.equal(aiCatalogSchema.safeParse(malformedCatalog).success, false);
}
assert.equal(aiCatalogJsonSchema.$id, rawSchema.$id);
assert.equal(implementedSpecRevision.commit, '9aac2c1bfa622356e45a31f3dc1d342bdb329e00');
const decode = bytes => new TextDecoder().decode(bytes);
assert.equal(decode(canonicalizeJsonValueToBytes({ b: 2, a: 1 })), '{"a":1,"b":2}');
const signatureMetadata = { signer: 'did:example:alice', profile: 'custom-v1', issuedAt: '2026-08-31T00:00:00Z' };
const payloadCatalog = {
  ...value,
  signature: { ...signatureMetadata, jws: 'excluded' },
  additionalSignatures: ['excluded'],
  extension: { signature: { jws: 'retained' }, additionalSignatures: ['retained'] },
};
const catalogPayload = JSON.parse(decode(createCatalogSignaturePayload(payloadCatalog)));
assert.deepEqual(catalogPayload.signature, signatureMetadata);
assert.equal(Object.hasOwn(catalogPayload, 'additionalSignatures'), false);
assert.deepEqual(catalogPayload.extension, payloadCatalog.extension);
const manifestPayload = JSON.parse(decode(createTrustManifestSignaturePayload({ contributor: 'did:example:alice', signature: { ...signatureMetadata, jws: 'excluded' }, additionalSignatures: null })));
assert.deepEqual(manifestPayload, { contributor: 'did:example:alice', signature: signatureMetadata });
assert.equal(checkDigest(new Uint8Array(), 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').status, 'match');

const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function createJws({ payload, typ }, representation = 'compact') {
  const protectedSegment = Buffer.from(JSON.stringify({ alg: 'ES256', typ })).toString('base64url');
  const payloadSegment = Buffer.from(payload).toString('base64url');
  const signatureSegment = sign('sha256', Buffer.from(protectedSegment + '.' + payloadSegment), {
    key: keys.privateKey, dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  if (representation === 'flattened') return { protected: protectedSegment, payload: payloadSegment, signature: signatureSegment };
  return protectedSegment + '.' + (representation === 'detached' ? '' : payloadSegment) + '.' + signatureSegment;
}
const catalogForSignature = { ...value, signature: signatureMetadata };
const catalogJws = createJws({ payload: createCatalogSignaturePayload(catalogForSignature), typ: 'ai-catalog+jws' }, 'detached');
const signedCatalog = { ...catalogForSignature, signature: { ...signatureMetadata, jws: catalogJws } };
const bindingOptions = { publicKey: keys.publicKey, expectedAlgorithm: 'ES256' };
assert.equal((await checkCatalogSignature(signedCatalog, bindingOptions)).status, 'valid');

const artifactBytes = new TextEncoder().encode('test');
const entry = {
  identifier: 'urn:air:example.com:artifact:one',
  version: '',
  type: 'application/json',
  digest: 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  url: 'https://example.com/artifact.json',
};
const subject = { identifier: entry.identifier, version: entry.version, type: entry.type, digest: entry.digest };
const metadata = { profile: 'custom-v1', issuedAt: signatureMetadata.issuedAt };
const manifests = [];
for (const representation of ['compact', 'detached', 'flattened']) {
  const manifest = await signTrustManifest(
    { contributor: 'did:example:alice', subject },
    metadata,
    input => createJws(input, representation),
  );
  assert.equal(manifest.signature.jws.split('.')[1], '');
  assert.equal((await checkTrustManifestSignature(manifest, bindingOptions)).status, 'valid');
  assert.equal((await checkCatalogEntryArtifactBinding(entry, artifactBytes, manifest, bindingOptions)).status, 'valid');
  manifests.push(manifest);
}
const derived = await signTrustManifest(entry, { contributor: 'did:example:alice' }, metadata, createJws);
assert.deepEqual(derived.subject, subject);
assert.equal(Object.hasOwn(entry, 'trustManifests'), false);
assert.equal(Object.hasOwn(derived.subject, 'url'), false);
const signedEntry = { ...entry, trustManifests: manifests };
parseCatalog({ ...value, entries: [signedEntry] });
const report = await checkCatalogEntry(signedEntry, artifactBytes);
assert.equal(report.status, 'checked');
assert.deepEqual(report.manifests.map(result => result.index), [0, 1, 2]);
assert.deepEqual(report.manifests.map(result => result.status), ['profile_not_implemented', 'profile_not_implemented', 'profile_not_implemented']);
const emptyReport = await checkCatalogEntry(signedEntry, artifactBytes, { contributors: [] });
assert.equal(emptyReport.status, 'checked');
assert.deepEqual(emptyReport.manifests, []);
const publisherOnly = await checkCatalogEntry(signedEntry, artifactBytes, { contributors: [], alwaysCheckPublisherManifests: true });
assert.equal(publisherOnly.status, 'checked');
assert.deepEqual(publisherOnly.manifests, []);
const publisherMetadata = { contributor: 'did:web:example.com', extensions: { 'com.example': true } };
const selectedPublisher = await checkCatalogEntry({ ...signedEntry, trustManifests: [...manifests, publisherMetadata] }, artifactBytes, {
  contributors: [], alwaysCheckPublisherManifests: true, clockToleranceMs: 0,
});
assert.equal(selectedPublisher.status, 'checked');
assert.deepEqual(selectedPublisher.manifests.map(result => [result.index, result.status]), [[3, 'missing_signature']]);
const inlineEntry = { identifier: 'inline', type: 'application/json', data: null };
assert.deepEqual(await checkCatalogEntry(inlineEntry), { status: 'checked', manifests: [] });
const inlineSubject = {
  identifier: inlineEntry.identifier,
  type: inlineEntry.type,
  digest: 'sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b',
};
const inlineManifest = await signTrustManifest({ contributor: 'did:example:alice', subject: inlineSubject }, metadata, createJws);
assert.equal((await checkCatalogEntryArtifactBinding({ ...inlineEntry, digest: inlineSubject.digest }, inlineManifest, bindingOptions)).status, 'valid');
const unavailablePublisher = await checkCatalogEntry(inlineEntry, { contributors: [], alwaysCheckPublisherManifests: true });
assert.deepEqual(unavailablePublisher, { status: 'checked', manifests: [] });
const invalidEntry = await checkCatalogEntry({ ...inlineEntry, trustManifests: [{ contributor: 'did:example:alice' }] });
assert.equal(invalidEntry.status, 'invalid_entry');
assert.ok(invalidEntry.error.issues.some(issue => issue.path[0] === 'trustManifests'));
const wrongArtifact = await checkCatalogEntry({ ...entry, digest: 'sha256:' + '0'.repeat(64) }, artifactBytes, { contributors: [] });
assert.equal(wrongArtifact.status, 'artifact_check_failed');
assert.equal(wrongArtifact.digestResult.status, 'mismatch');
await assert.rejects(signTrustManifest({ contributor: 'did:example:alice', subject }, metadata, input => ({
  ...createJws(input, 'flattened'), payload: 'different',
})), TypeError);
for (const [property, status] of [['identifier', 'identifier_mismatch'], ['version', 'version_mismatch']]) {
  const result = await checkCatalogEntryArtifactBinding({ ...entry, [property]: 'different' }, artifactBytes, derived, bindingOptions);
  assert.equal(result.status, 'subject_check_failed');
  assert.equal(result.subjectResult.status, status);
}
const abortController = new AbortController();
const cancellationReason = new Error('Packed consumer cancellation');
abortController.abort(cancellationReason);
await assert.rejects(checkCatalogEntry(signedEntry, artifactBytes, { signal: abortController.signal }), error => error === cancellationReason);
`,
  );
  run(node, ['smoke.mjs'], { cwd: consumerDirectory });

  await writeFile(
    join(consumerDirectory, 'consumer.ts'),
    `import { createPublicKey } from 'node:crypto';
import {
  type AICatalog,
  type CatalogEntryWithData,
  type CatalogEntryWithUrl,
  type HostInfo,
  type ParseResult,
  type Signature,
  type SignedTrustManifest,
  type TrustManifest,
  type TrustSubject,
  entryTypes,
  isCatalogEntryWithData,
  isCatalogEntryWithUrl,
  isEntryType,
  mediaTypes,
  safeParseCatalog,
} from '${pkg.name}';
import { aiCatalogSchema } from '${pkg.name}/zod';
import { aiCatalogJsonSchema, type JsonSchema } from '${pkg.name}/json-schema';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntry,
  checkCatalogEntryArtifactBinding,
  checkCatalogSignature,
  checkDigest,
  checkTrustManifestSignature,
  createCatalogSignaturePayload,
  createTrustManifestSignaturePayload,
  signTrustManifest,
  DigestAlgorithmUnavailableError,
  type DigestCheckResult,
  type CatalogEntryArtifactBindingCheckResult,
  type CatalogEntryCheckOptions,
  type CatalogEntryCheckResult,
  type SignatureCheckOptions,
  type SignatureCheckResult,
  type TrustManifestSignatureMetadata,
  type TrustManifestSigner,
  type JwsSigningResult,
} from '${pkg.name}/verification';
import rawSchema from '${pkg.name}/schema/ai-catalog.schema.json' with { type: 'json' };

const authored: AICatalog = { specVersion: '1.0', entries: [] };
const authoredHost: HostInfo = {
  displayName: 'Example',
  // @ts-expect-error Host Trust Manifests are not a recognized authoring field.
  trustManifest: {},
};
const subject: TrustSubject = {
  identifier: 'example-artifact', version: '', type: 'application/example', digest: 'sha256:${'a'.repeat(64)}',
};
// @ts-expect-error A Trust Subject requires its artifact identifier.
const subjectWithoutIdentifier: TrustSubject = { type: subject.type, digest: subject.digest };
const subjectWithoutVersion: TrustSubject = { identifier: subject.identifier, type: subject.type, digest: subject.digest };
const result: ParseResult<AICatalog> = safeParseCatalog(authored);
const predicate = isEntryType(mediaTypes.a2aAgentCard);
const pluginPredicate = isEntryType(entryTypes.agentPlugin);
authored.entries.filter(predicate);
const pluginEntries = authored.entries.filter(pluginPredicate);
const pluginType:
  | typeof mediaTypes.agentPluginZip
  | typeof mediaTypes.agentPluginGzip
  | undefined = pluginEntries[0]?.type;
authored.entries.filter(predicate).filter(isCatalogEntryWithData);
authored.entries.filter(isCatalogEntryWithData).filter(predicate);
authored.entries.filter(predicate).filter(isCatalogEntryWithUrl);
authored.entries.filter(isCatalogEntryWithUrl).filter(predicate);
const entriesWithData: CatalogEntryWithData[] = authored.entries.filter(isCatalogEntryWithData);
const entriesWithUrl: CatalogEntryWithUrl[] = authored.entries.filter(isCatalogEntryWithUrl);
aiCatalogSchema.parse(authored);
const schema: JsonSchema = aiCatalogJsonSchema;
const digestResult: DigestCheckResult = checkDigest(new Uint8Array(), 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
const canonicalBytes: Uint8Array = canonicalizeJsonValueToBytes({ b: 2, a: 1 });
const metadata: TrustManifestSignatureMetadata = { profile: 'custom-v1', issuedAt: '2026-08-31T00:00:00Z' };
const signature: Signature = { ...metadata, signer: 'did:example:alice', jws: 'protected..signature' };
// @ts-expect-error A completed Signature requires jws.
const incompleteSignature: Signature = { ...metadata, signer: 'did:example:alice' };
const trustManifest: TrustManifest = { contributor: 'did:example:alice', subject, signature };
const signaturePayload: Uint8Array = createTrustManifestSignaturePayload(trustManifest);
const presigningPayload: Uint8Array = createTrustManifestSignaturePayload({ ...trustManifest, signature: { ...metadata, signer: trustManifest.contributor } });
const catalogSignaturePayload: Uint8Array = createCatalogSignaturePayload({ ...authored, signature: { ...metadata, signer: trustManifest.contributor } });
const signaturePublicKey = createPublicKey({
  key: { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' },
  format: 'jwk',
});
const signatureOptions: SignatureCheckOptions = { publicKey: signaturePublicKey, expectedAlgorithm: 'ES256' };
const signatureCheck: Promise<SignatureCheckResult> = checkTrustManifestSignature(trustManifest, signatureOptions);
const catalogSignatureCheck: Promise<SignatureCheckResult> = checkCatalogSignature(authored, signatureOptions);
const entryWithData: CatalogEntryWithData = { identifier: subject.identifier, type: subject.type, digest: subject.digest, data: null, trustManifests: [trustManifest] };
const entryWithUrl: CatalogEntryWithUrl = { identifier: subject.identifier, version: '', type: subject.type, digest: subject.digest, url: 'https://example.com/artifact', trustManifests: [trustManifest] };
const dataBindingCheck: Promise<CatalogEntryArtifactBindingCheckResult> = checkCatalogEntryArtifactBinding(entryWithData, trustManifest, signatureOptions);
const urlBindingCheck: Promise<CatalogEntryArtifactBindingCheckResult> = checkCatalogEntryArtifactBinding(entryWithUrl, new Uint8Array(), trustManifest, signatureOptions);
const unionEntry = authored.entries[0];
const unionBindingCheck = unionEntry === undefined ? undefined : isCatalogEntryWithData(unionEntry)
  ? checkCatalogEntryArtifactBinding(unionEntry, trustManifest, signatureOptions)
  : checkCatalogEntryArtifactBinding(unionEntry, new Uint8Array(), trustManifest, signatureOptions);
// @ts-expect-error Entries with url require explicit artifact bytes.
checkCatalogEntryArtifactBinding(entryWithUrl, trustManifest, signatureOptions);
// @ts-expect-error Entries with data do not accept separate artifact bytes.
checkCatalogEntryArtifactBinding(entryWithData, new Uint8Array(), trustManifest, signatureOptions);
const options: CatalogEntryCheckOptions = {
  contributors: ['did:example:alice'], alwaysCheckPublisherManifests: true, clockToleranceMs: 0,
  signal: new AbortController().signal, timeoutMs: 60_000, maxResponseBytes: 16 * 1024 * 1024,
};
const dataCheck: Promise<CatalogEntryCheckResult> = checkCatalogEntry(entryWithData);
const configuredDataCheck: Promise<CatalogEntryCheckResult> = checkCatalogEntry(entryWithData, options);
const urlCheck: Promise<CatalogEntryCheckResult> = checkCatalogEntry(entryWithUrl, new Uint8Array());
const configuredUrlCheck: Promise<CatalogEntryCheckResult> = checkCatalogEntry(entryWithUrl, new Uint8Array(), options);
// @ts-expect-error Entries with url require explicit artifact bytes.
checkCatalogEntry(entryWithUrl, options);
// @ts-expect-error Entries with data do not accept separate artifact bytes.
checkCatalogEntry(entryWithData, new Uint8Array(), options);
// @ts-expect-error Automatic verification selects its own keys.
checkCatalogEntry(entryWithData, { publicKey: signaturePublicKey });
const report = {} as CatalogEntryCheckResult;
if (report.status === 'checked') {
  for (const evaluation of report.manifests) {
    const index: number = evaluation.index;
    const manifest: TrustManifest = evaluation.manifest;
    if (evaluation.status === 'valid') {
      const publisher: boolean = evaluation.isPublisherEndorsement;
      void publisher;
    } else {
      // @ts-expect-error Failed evaluations do not assert a publisher relationship.
      evaluation.isPublisherEndorsement;
    }
    if (evaluation.status === 'profile_check_failed' || evaluation.status === 'issuer_check_failed') {
      const diagnostic: Error = evaluation.error;
      void diagnostic;
    }
    void index; void manifest;
  }
}
const callback: TrustManifestSigner = ({ payload, typ }) => {
  const bytes: Uint8Array = payload;
  const manifestTyp: 'ai-catalog-trust-manifest+jws' = typ;
  void bytes; void manifestTyp;
  return 'protected..signature';
};
const signed: Promise<SignedTrustManifest> = signTrustManifest({ contributor: 'did:example:alice', subject }, metadata, callback);
const signedFromEntry: Promise<SignedTrustManifest> = signTrustManifest(entryWithUrl, { contributor: 'did:example:alice' }, metadata, callback);
const flattened: { protected?: string; payload: string; signature: string; header?: Record<string, unknown> } = { protected: 'header', payload: 'payload', signature: 'signature' };
const callbackResult: JwsSigningResult = flattened;
signTrustManifest({ contributor: 'did:example:alice', subject }, metadata, async () => callbackResult);
// @ts-expect-error A manual signing body requires subject.
signTrustManifest({ contributor: 'did:example:alice' }, metadata, callback);
// @ts-expect-error Signing constructs the completed signature.
signTrustManifest({ contributor: 'did:example:alice', subject, signature }, metadata, callback);
// @ts-expect-error The entry overload derives subject rather than accepting it.
signTrustManifest(entryWithUrl, { contributor: 'did:example:alice', subject }, metadata, callback);
// @ts-expect-error Signing derives signer from contributor.
signTrustManifest({ contributor: 'did:example:alice', subject }, { ...metadata, signer: 'did:example:alice' }, callback);
if (digestResult.status === 'algorithm_not_implemented') {
  const algorithm: string = digestResult.algorithm;
  void algorithm;
}
const unavailable: Error = new DigestAlgorithmUnavailableError('sha256');
void result; void authoredHost; void subjectWithoutIdentifier; void subjectWithoutVersion; void incompleteSignature;
void pluginType; void entriesWithData; void entriesWithUrl; void schema; void unavailable; void canonicalBytes;
void catalogSignaturePayload; void signaturePayload; void presigningPayload; void signatureCheck; void catalogSignatureCheck;
void dataBindingCheck; void urlBindingCheck; void unionBindingCheck; void dataCheck; void configuredDataCheck;
void urlCheck; void configuredUrlCheck; void signed; void signedFromEntry; void rawSchema;
`,
  );
  await writeFile(
    join(consumerDirectory, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2020',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          exactOptionalPropertyTypes: true,
          resolveJsonModule: true,
          skipLibCheck: false,
          types: ['node'],
          noEmit: true,
        },
        include: ['consumer.ts'],
      },
      null,
      2,
    ),
  );
  run(node, [join(root, 'node_modules', 'typescript', 'bin', 'tsc')], {
    cwd: consumerDirectory,
  });
  run(node, [join(root, 'node_modules', 'typescript-5-5', 'bin', 'tsc')], {
    cwd: consumerDirectory,
  });
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}
