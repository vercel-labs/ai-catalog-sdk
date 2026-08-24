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
      'zod@4.4.0',
      join(temporaryDirectory, packed.filename),
    ],
    { cwd: consumerDirectory },
  );

  await writeFile(
    join(consumerDirectory, 'smoke.mjs'),
    `import { implementedSpecRevision, parseCatalog } from ${JSON.stringify(pkg.name)};
import { aiCatalogSchema } from ${JSON.stringify(`${pkg.name}/zod`)};
import { aiCatalogJsonSchema } from ${JSON.stringify(`${pkg.name}/json-schema`)};
import rawSchema from ${JSON.stringify(`${pkg.name}/schema/ai-catalog.schema.json`)} with { type: 'json' };

const value = { specVersion: '1.0', entries: [] };
if (parseCatalog(value).entries.length !== 0) process.exit(1);
if (!aiCatalogSchema.safeParse(value).success) process.exit(1);
if (aiCatalogJsonSchema.$id !== rawSchema.$id) process.exit(1);
if (implementedSpecRevision.commit.length !== 40) process.exit(1);
`,
  );
  run(node, ['smoke.mjs'], { cwd: consumerDirectory });

  await writeFile(
    join(consumerDirectory, 'consumer.ts'),
    `import {
  type AICatalog,
  type ParseResult,
  entryTypes,
  isEntryType,
  isInlineCatalogEntry,
  mediaTypes,
  safeParseCatalog,
} from '${pkg.name}';
import { aiCatalogSchema } from '${pkg.name}/zod';
import { aiCatalogJsonSchema, type JsonSchema } from '${pkg.name}/json-schema';
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
void result;
void pluginType;
void schema;
void rawSchema;
`,
  );
  await writeFile(
    join(consumerDirectory, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          strict: true,
          exactOptionalPropertyTypes: true,
          resolveJsonModule: true,
          skipLibCheck: false,
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
