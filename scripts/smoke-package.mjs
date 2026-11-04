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
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { CatalogParseError, CatalogValidationError, implementedSpecRevision, parseCatalog } from ${JSON.stringify(pkg.name)};
import { aiCatalogSchema } from ${JSON.stringify(`${pkg.name}/zod`)};
import { aiCatalogJsonSchema } from ${JSON.stringify(`${pkg.name}/json-schema`)};
import { canonicalizeJsonValueToBytes, checkCatalogEntry, checkCatalogEntryArtifactBinding, checkCatalogSignature, checkDigest, checkTrustManifestSignature, createDigest, createCatalogSignaturePayload, createTrustManifestSignaturePayload } from ${JSON.stringify(`${pkg.name}/verification`)};
import rawSchema from ${JSON.stringify(`${pkg.name}/schema/ai-catalog.schema.json`)} with { type: 'json' };

const value = { specVersion: '1.0', entries: [] };
assert.deepEqual(parseCatalog(value).entries, []);
assert.throws(() => parseCatalog({ ...value, entries: [null] }), CatalogParseError);
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
assert.deepEqual(futureContentReport.manifests.map(result => result.status), ['unsigned']);
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
const signatureMetadata = { signer: 'did:example:alice', profile: 'https://example.com/profiles/custom-v1', issuedAt: '2026-08-31T00:00:00Z' };
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
assert.equal(createDigest(new Uint8Array()), 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
const canonicalDigest = 'sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777';
assert.equal(createDigest({ b: 2, a: 1 }), canonicalDigest);
assert.equal(createDigest({ a: 1, b: 2 }), canonicalDigest);
assert.equal(checkDigest(new TextEncoder().encode('{"a":1,"b":2}'), canonicalDigest).status, 'match');
const stringDigest = 'sha256:' + createHash('sha256').update('"abc"').digest('hex');
assert.equal(createDigest('abc'), stringDigest);
assert.notEqual(stringDigest, createDigest(new TextEncoder().encode('abc')));
assert.equal(checkDigest(new TextEncoder().encode('"abc"'), stringDigest).status, 'match');
assert.equal(checkDigest(new TextEncoder().encode('abc'), stringDigest).status, 'mismatch');
const sha384Digest = createDigest(Buffer.from('abc'), 'sha384');
assert.ok(sha384Digest.startsWith('sha384:'));
assert.equal(checkDigest(Buffer.from('abc'), sha384Digest).status, 'match');

const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
function createJws({ payload, typ }, representation = 'compact', headerFields = {}) {
  const protectedSegment = Buffer.from(JSON.stringify({ alg: 'ES256', typ, ...headerFields })).toString('base64url');
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
const metadata = { profile: signatureMetadata.profile, issuedAt: signatureMetadata.issuedAt };
const manifestForPayload = { contributor: 'did:example:alice', subject, signature: { ...metadata, signer: 'did:example:alice' } };
const derived = { ...manifestForPayload, signature: {
  ...manifestForPayload.signature,
  jws: createJws({ payload: createTrustManifestSignaturePayload(manifestForPayload), typ: 'ai-catalog-trust-manifest+jws' }, 'detached'),
} };
const manifests = [derived, derived, derived];
assert.equal((await checkTrustManifestSignature(derived, bindingOptions)).status, 'valid');
assert.equal((await checkCatalogEntryArtifactBinding(entry, artifactBytes, derived, bindingOptions)).status, 'valid');
const fixedNow = Date.parse('2026-08-31T00:00:00Z');
const signedEntry = { ...entry, trustManifests: manifests };
const declarationErrors = {
  ...derived,
  contributor: 'not a URI',
  subject: { ...derived.subject, identifier: 'different artifact' },
  signature: { ...derived.signature, profile: '', issuedAt: 'yesterday', expiresAt: 'earlier' },
  attestations: [{ type: 'example', uri: 'https://example.com/evidence', size: -1, digest: 'sha256:zz' }],
};
const malformedEntry = { ...entry, trustManifests: [declarationErrors] };
const malformedCatalog = { ...value, entries: [malformedEntry, malformedEntry] };
assert.throws(() => parseCatalog(malformedCatalog), CatalogParseError);
const malformedReport = await checkCatalogEntry(malformedEntry, artifactBytes);
assert.equal(malformedReport.status, 'checked');
assert.equal(malformedReport.manifests[0].status, 'invalid_manifest');
assert.ok(malformedReport.manifests[0].error instanceof CatalogValidationError);
const excludedMalformed = await checkCatalogEntry(malformedEntry, artifactBytes, { contributors: [] });
assert.equal(excludedMalformed.status, 'checked');
assert.deepEqual(excludedMalformed.manifests, [{ manifest: declarationErrors, status: 'not_checked' }]);
const malformedAttachments = [
  null,
  { ...derived, signature: { ...derived.signature, issuedAt: 42 } },
];
const mixedAttachments = [...malformedAttachments, derived, {
  contributor: 'did:example:metadata', extensions: { 'example.com': true },
}];
const mixedEntry = { ...entry, trustManifests: mixedAttachments };
assert.throws(() => parseCatalog({ ...value, entries: [mixedEntry] }), CatalogParseError);
assert.equal(aiCatalogSchema.safeParse({ ...value, entries: [mixedEntry] }).success, false);
const isolatedReport = await checkCatalogEntry(mixedEntry, artifactBytes);
assert.equal(isolatedReport.status, 'checked');
assert.deepEqual(isolatedReport.manifests.map(result => result.status), [
  'invalid_manifest', 'invalid_manifest', 'profile_not_implemented', 'unsigned',
]);
assert.deepEqual(isolatedReport.manifests.map(result => result.manifest), mixedAttachments);
assert.ok(isolatedReport.manifests.slice(0, 2).every(result => result.error instanceof CatalogValidationError));
const excludedRawReport = await checkCatalogEntry(mixedEntry, artifactBytes, { contributors: [] });
assert.equal(excludedRawReport.status, 'checked');
assert.deepEqual(excludedRawReport.manifests, mixedAttachments.map(manifest => ({ manifest, status: 'not_checked' })));
const invalidEntry = await checkCatalogEntry({ ...entry, identifier: 42 }, artifactBytes);
assert.equal(invalidEntry.status, 'invalid_entry');
assert.ok(invalidEntry.error instanceof CatalogParseError);
const malformedJwsManifest = { ...derived, signature: { ...derived.signature, jws: 'not-a-jws' } };
const sharedArtifactFailure = { status: 'artifact_digest_mismatch' };
assert.deepEqual(await checkCatalogEntry({ ...entry, trustManifests: [malformedJwsManifest] }, new Uint8Array([0])), sharedArtifactFailure);
const parsedManifests = parseCatalog({ ...value, entries: [signedEntry] }).entries[0].trustManifests;
const report = await checkCatalogEntry(signedEntry, artifactBytes);
assert.equal(report.status, 'checked');
assert.deepEqual(report.manifests.map(result => result.manifest), parsedManifests);
assert.ok(report.manifests.every(result => !Object.hasOwn(result, 'index')));
assert.deepEqual(report.manifests.map(result => result.status), ['profile_not_implemented', 'profile_not_implemented', 'profile_not_implemented']);
const uncheckedReport = await checkCatalogEntry(signedEntry, artifactBytes, { contributors: [], nowMs: fixedNow, clockToleranceMs: 0 });
assert.equal(uncheckedReport.status, 'checked');
assert.deepEqual(uncheckedReport.manifests, parsedManifests.map(manifest => ({ manifest, status: 'not_checked' })));
const publisherOnly = await checkCatalogEntry(signedEntry, artifactBytes, { contributors: [], alwaysCheckPublisherManifests: true });
assert.equal(publisherOnly.status, 'checked');
assert.deepEqual(publisherOnly.manifests, parsedManifests.map(manifest => ({ manifest, status: 'not_checked' })));
const publisherMetadata = { contributor: 'did:web:example.com', extensions: { 'com.example': true } };
const selectedPublisher = await checkCatalogEntry({ ...signedEntry, trustManifests: [...manifests, publisherMetadata] }, artifactBytes, {
  contributors: [], alwaysCheckPublisherManifests: true, clockToleranceMs: 0,
});
assert.equal(selectedPublisher.status, 'checked');
assert.deepEqual(selectedPublisher.manifests, [
  ...parsedManifests.map(manifest => ({ manifest, status: 'not_checked' })),
  { manifest: publisherMetadata, status: 'unsigned' },
]);
const inlineEntry = { identifier: 'inline', type: 'application/json', data: null };
assert.deepEqual(await checkCatalogEntry(inlineEntry), { status: 'checked', manifests: [] });
const inlineSubject = {
  identifier: inlineEntry.identifier,
  type: inlineEntry.type,
  digest: 'sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b',
};
const inlineBody = { contributor: 'did:example:alice', subject: inlineSubject, signature: { ...metadata, signer: 'did:example:alice' } };
const inlineManifest = { ...inlineBody, signature: { ...inlineBody.signature, jws: createJws({ payload: createTrustManifestSignaturePayload(inlineBody), typ: 'ai-catalog-trust-manifest+jws' }, 'detached') } };
assert.equal((await checkCatalogEntryArtifactBinding({ ...inlineEntry, digest: inlineSubject.digest }, inlineManifest, bindingOptions)).status, 'valid');
const unavailablePublisher = await checkCatalogEntry(inlineEntry, { contributors: [], alwaysCheckPublisherManifests: true });
assert.deepEqual(unavailablePublisher, { status: 'checked', manifests: [] });
const invalidManifestReport = await checkCatalogEntry({ ...inlineEntry, trustManifests: [{ contributor: 'did:example:alice' }] });
assert.equal(invalidManifestReport.status, 'checked');
assert.equal(invalidManifestReport.manifests[0].status, 'invalid_manifest');
assert.ok(invalidManifestReport.manifests[0].error instanceof CatalogValidationError);
const wrongArtifact = await checkCatalogEntry({ ...entry, digest: 'sha256:' + '0'.repeat(64) }, artifactBytes, { contributors: [] });
assert.deepEqual(wrongArtifact, { status: 'artifact_digest_mismatch' });
assert.deepEqual(await checkCatalogEntry({ ...inlineEntry, digest: 'sha256:00' }), { status: 'invalid_digest' });
assert.deepEqual(await checkCatalogEntry({ ...inlineEntry, digest: 'blake3:00' }), {
  status: 'digest_algorithm_not_implemented', algorithm: 'blake3',
});
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
  type JsonValue,
  type ParseResult,
  type Signature,
  type TrustManifest,
  type TrustSubject,
  entryTypes,
  isCatalogEntryWithData,
  isCatalogEntryWithUrl,
  isEntryType,
  mediaTypes,
  safeParseCatalog,
  CatalogValidationError,
  type CatalogIssue,
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
  createDigest,
  createCatalogSignaturePayload,
  createTrustManifestSignaturePayload,
  DigestAlgorithmUnavailableError,
  type DigestAlgorithm,
  type DigestCheckResult,
    type CatalogEntryArtifactBindingCheckResult,
  type CatalogEntryCheckOptions,
  type CatalogEntryCheckResult,
  type SignatureCheckOptions,
  type SignatureCheckResult,
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
const metadata = { profile: 'custom-v1', issuedAt: '2026-08-31T00:00:00Z' };
const digestAlgorithm: DigestAlgorithm = 'sha384';
const generatedDigest: string = createDigest(new Uint8Array(), digestAlgorithm);
const jsonDigest: string = createDigest({ b: 2, a: 1 });
const unionDigest: string = createDigest({} as Uint8Array | JsonValue);
// @ts-expect-error Digest creation supports the SDK's implemented algorithms.
createDigest(new Uint8Array(), 'md5');
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
const manifestOptions: SignatureCheckOptions = signatureOptions;
const dataBindingCheck: Promise<CatalogEntryArtifactBindingCheckResult> = checkCatalogEntryArtifactBinding(entryWithData, trustManifest, manifestOptions);
const urlBindingCheck: Promise<CatalogEntryArtifactBindingCheckResult> = checkCatalogEntryArtifactBinding(entryWithUrl, new Uint8Array(), trustManifest, manifestOptions);
const unionEntry = authored.entries[0];
const unionBindingCheck = unionEntry === undefined ? undefined : isCatalogEntryWithData(unionEntry)
  ? checkCatalogEntryArtifactBinding(unionEntry, trustManifest, signatureOptions)
  : checkCatalogEntryArtifactBinding(unionEntry, new Uint8Array(), trustManifest, signatureOptions);
// @ts-expect-error Entries with url require explicit artifact bytes.
checkCatalogEntryArtifactBinding(entryWithUrl, trustManifest, signatureOptions);
// @ts-expect-error Entries with data do not accept separate artifact bytes.
checkCatalogEntryArtifactBinding(entryWithData, new Uint8Array(), trustManifest, signatureOptions);
const options: CatalogEntryCheckOptions = {
  contributors: ['did:example:alice'], alwaysCheckPublisherManifests: true, clockToleranceMs: 0, nowMs: 0,
  signal: new AbortController().signal, resolutionTimeoutMs: 60_000, maxResponseBytes: 16 * 1024 * 1024,
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
  const uncheckedManifests: JsonValue[] = report.manifests
    .filter(evaluation => evaluation.status === 'not_checked')
    .map(evaluation => evaluation.manifest);
  void uncheckedManifests;
  for (const evaluation of report.manifests) {
    // @ts-expect-error Evaluations correspond to input positions without an index field.
    evaluation.index;
    // @ts-expect-error Unvalidated or excluded manifest values require narrowing.
    const manifestWithoutNarrowing: TrustManifest = evaluation.manifest;
    if (evaluation.status === 'passed') {
      const manifest: TrustManifest = evaluation.manifest;
      const publisher: boolean = evaluation.isPublisherEndorsement;
      void manifest; void publisher;
    } else {
      // @ts-expect-error Failed evaluations do not assert a publisher relationship.
      evaluation.isPublisherEndorsement;
    }
    if (evaluation.status === 'profile_check_failed' || evaluation.status === 'issuer_check_failed') {
      const diagnostic: Error = evaluation.error;
      void diagnostic;
    }
    if (evaluation.status === 'invalid_manifest') {
      const rawInvalidManifest: JsonValue = evaluation.manifest;
      // @ts-expect-error A structurally invalid manifest may be any JSON value.
      const invalidManifest: TrustManifest = evaluation.manifest;
      void rawInvalidManifest; void invalidManifest;
    }
    void manifestWithoutNarrowing;
  }
} else if (report.status === 'digest_algorithm_not_implemented') {
  const algorithm: string = report.algorithm;
  void algorithm;
} else if (report.status === 'artifact_digest_mismatch' || report.status === 'invalid_digest') {
  // @ts-expect-error Entry digest failures do not have a nested digestResult.
  report.digestResult;
}
if (digestResult.status === 'algorithm_not_implemented') {
  const algorithm: string = digestResult.algorithm;
  void algorithm;
}
const unavailable: Error = new DigestAlgorithmUnavailableError('sha256');
void result; void authoredHost; void subjectWithoutIdentifier; void subjectWithoutVersion; void incompleteSignature;
void pluginType; void entriesWithData; void entriesWithUrl; void schema; void unavailable; void canonicalBytes;
void catalogSignaturePayload; void signaturePayload; void presigningPayload; void signatureCheck; void catalogSignatureCheck;
void dataBindingCheck; void urlBindingCheck; void unionBindingCheck; void dataCheck; void configuredDataCheck;
void urlCheck; void configuredUrlCheck; void rawSchema;
void generatedDigest; void jsonDigest; void unionDigest;
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
