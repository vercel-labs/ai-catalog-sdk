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
    `import { createPublicKey } from 'node:crypto';
import { implementedSpecRevision, parseCatalog } from ${JSON.stringify(pkg.name)};
import { aiCatalogSchema } from ${JSON.stringify(`${pkg.name}/zod`)};
import { aiCatalogJsonSchema } from ${JSON.stringify(`${pkg.name}/json-schema`)};
import { canonicalizeJsonValueToBytes, checkCatalogEntryArtifactBinding, checkDigest, checkTrustManifestSignature, createTrustManifestSignaturePayload } from ${JSON.stringify(`${pkg.name}/verification`)};
import rawSchema from ${JSON.stringify(`${pkg.name}/schema/ai-catalog.schema.json`)} with { type: 'json' };

const value = { specVersion: '1.0', entries: [] };
if (parseCatalog(value).entries.length !== 0) process.exit(1);
if (!aiCatalogSchema.safeParse(value).success) process.exit(1);
if (aiCatalogJsonSchema.$id !== rawSchema.$id) process.exit(1);
if (implementedSpecRevision.commit.length !== 40) process.exit(1);
if (new TextDecoder().decode(canonicalizeJsonValueToBytes({ b: 2, a: 1 })) !== '{"a":1,"b":2}') process.exit(1);
if (new TextDecoder().decode(createTrustManifestSignaturePayload({ identity: 'did:example:alice', signature: 'detached-jws' })) !== '{"identity":"did:example:alice"}') process.exit(1);
if (checkDigest(new Uint8Array(), 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').status !== 'match') process.exit(1);
const signedManifest = {
  identity: 'did:example:alice',
  issuedAt: '2026-03-15T10:00:00Z',
  subject: {
    digest: 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    type: 'application/json',
  },
  signature: 'eyJhbGciOiJFUzI1NiJ9..NKmmKrtfVExTyrPwimVozLDtLRAZP0r29iJYkrBRAR7rFsM3UqsXFFH3htDDVUKWPJ-UjvgFQqOWDT97iDzT0A',
};
const signaturePublicKey = createPublicKey({
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  },
  format: 'jwk',
});
if ((await checkTrustManifestSignature(signedManifest, { publicKey: signaturePublicKey, expectedAlgorithm: 'ES256' })).status !== 'valid') process.exit(1);
const artifactBytes = new TextEncoder().encode('test');
const signedEntry = {
  identifier: 'signed-artifact',
  type: 'application/json',
  url: 'https://example.com/artifact.json',
  trustManifest: signedManifest,
};
if ((await checkCatalogEntryArtifactBinding(signedEntry, artifactBytes, { publicKey: signaturePublicKey, expectedAlgorithm: 'ES256' })).status !== 'valid') process.exit(1);
`,
  );
  run(node, ['smoke.mjs'], { cwd: consumerDirectory });

  await writeFile(
    join(consumerDirectory, 'consumer.ts'),
    `import { createPublicKey } from 'node:crypto';
import {
  type AICatalog,
  type InlineCatalogEntry,
  type ParseResult,
  type ReferencedCatalogEntry,
  type TrustManifest,
  entryTypes,
  isEntryType,
  isInlineCatalogEntry,
  mediaTypes,
  safeParseCatalog,
} from '${pkg.name}';
import { aiCatalogSchema } from '${pkg.name}/zod';
import { aiCatalogJsonSchema, type JsonSchema } from '${pkg.name}/json-schema';
import {
  canonicalizeJsonValueToBytes,
  checkCatalogEntryArtifactBinding,
  checkDigest,
  checkTrustManifestSignature,
  createTrustManifestSignaturePayload,
  DigestAlgorithmUnavailableError,
  type DigestCheckResult,
  type CatalogEntryArtifactBindingCheckResult,
  type TrustManifestSignatureCheckOptions,
  type TrustManifestSignatureCheckResult,
} from '${pkg.name}/verification';
import rawSchema from '${pkg.name}/schema/ai-catalog.schema.json' with { type: 'json' };

const authored: AICatalog = { specVersion: '1.0', entries: [] };
const result: ParseResult<AICatalog> = safeParseCatalog(authored);
const predicate = isEntryType(mediaTypes.a2aAgentCard);
const pluginPredicate = isEntryType(entryTypes.agentPlugin);
authored.entries.filter(predicate);
const pluginEntries = authored.entries.filter(pluginPredicate);
const pluginType:
  | typeof mediaTypes.agentPluginZip
  | typeof mediaTypes.agentPluginGzip
  | undefined = pluginEntries[0]?.type;
authored.entries.filter(predicate).filter(isInlineCatalogEntry);
authored.entries.filter(isInlineCatalogEntry).filter(predicate);
aiCatalogSchema.parse(authored);
const schema: JsonSchema = aiCatalogJsonSchema;
const digestResult: DigestCheckResult = checkDigest(
  new Uint8Array(),
  'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
);
const canonicalBytes: Uint8Array = canonicalizeJsonValueToBytes({ b: 2, a: 1 });
const trustManifest: TrustManifest = {
  identity: 'did:example:alice',
  issuedAt: '2026-08-31T00:00:00Z',
  subject: {
    type: 'application/example',
    digest: 'sha256:${'a'.repeat(64)}',
  },
  signature: 'detached-jws',
};
const signaturePayload: Uint8Array =
  createTrustManifestSignaturePayload(trustManifest);
const signaturePublicKey = createPublicKey({
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  },
  format: 'jwk',
});
const signatureOptions: TrustManifestSignatureCheckOptions = {
  publicKey: signaturePublicKey,
  expectedAlgorithm: 'ES256',
};
const signatureCheck: Promise<TrustManifestSignatureCheckResult> =
  checkTrustManifestSignature(trustManifest, signatureOptions);
const inlineBindingEntry: InlineCatalogEntry = {
  identifier: 'inline-binding',
  type: 'application/example',
  data: null,
  trustManifest,
};
const referencedBindingEntry: ReferencedCatalogEntry = {
  identifier: 'referenced-binding',
  type: 'application/example',
  url: 'https://example.com/artifact',
  trustManifest,
};
const inlineBindingCheck: Promise<CatalogEntryArtifactBindingCheckResult> =
  checkCatalogEntryArtifactBinding(inlineBindingEntry, signatureOptions);
const referencedBindingCheck: Promise<CatalogEntryArtifactBindingCheckResult> =
  checkCatalogEntryArtifactBinding(
    referencedBindingEntry,
    new Uint8Array(),
    signatureOptions,
  );
const unionBindingEntry = authored.entries[0];
const unionBindingCheck = unionBindingEntry === undefined
  ? undefined
  : isInlineCatalogEntry(unionBindingEntry)
    ? checkCatalogEntryArtifactBinding(unionBindingEntry, signatureOptions)
    : checkCatalogEntryArtifactBinding(
        unionBindingEntry,
        new Uint8Array(),
        signatureOptions,
      );
// @ts-expect-error Referenced entries require explicit artifact bytes.
checkCatalogEntryArtifactBinding(referencedBindingEntry, signatureOptions);
// @ts-expect-error Inline entries do not accept separate artifact bytes.
checkCatalogEntryArtifactBinding(inlineBindingEntry, new Uint8Array(), signatureOptions);
const bindingResult = {} as CatalogEntryArtifactBindingCheckResult;
if (
  bindingResult.status === 'subject_check_failed' &&
  bindingResult.subjectResult.status === 'algorithm_not_implemented'
) {
  const algorithm: string = bindingResult.subjectResult.algorithm;
  void algorithm;
}
if (digestResult.status === 'algorithm_not_implemented') {
  const algorithm: string = digestResult.algorithm;
  void algorithm;
}
const unavailable: Error = new DigestAlgorithmUnavailableError('sha256');
void result;
void pluginType;
void schema;
void unavailable;
void canonicalBytes;
void signaturePayload;
void signatureCheck;
void inlineBindingCheck;
void referencedBindingCheck;
void unionBindingCheck;
void rawSchema;
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
