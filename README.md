# @vercel-labs/ai-catalog-sdk

Parse, validate, and author JSON-native AI Catalog documents in TypeScript.

**Status:** This package is in private incubation. Publishing and public distribution are disabled until it completes the public graduation gate. The package name is a working identifier and does not claim an npm package.

## Parse a catalog

```ts
import {
  entryTypes,
  isEntryType,
  parseCatalogJson,
} from '@vercel-labs/ai-catalog-sdk';

const source = `{
  "specVersion": "1.0",
  "entries": [
    {
      "identifier": "example-agent-plugin",
      "type": "application/agent-plugins+zip",
      "url": "https://example.com/example-agent-plugin.zip"
    },
    {
      "identifier": "example-catalog",
      "type": "application/ai-catalog+json",
      "url": "https://example.com/catalog.json"
    }
  ]
}`;

const catalog = parseCatalogJson(source);
const pluginEntries = catalog.entries.filter(
  isEntryType(entryTypes.agentPlugin),
);
```

The parsed result is an ordinary mutable, JSON-shaped object. Parsing validates the catalog and Trust Manifest structure, but does not fetch or parse referenced artifacts.

## Parsing does not verify trust

Treat parsed Trust Manifest data as unverified input. Parsing does not verify signatures or digests, resolve identities, fetch attestations, evaluate provenance, or decide whether an artifact or publisher is trustworthy.

## Choose a validation API

| Input or goal | API | Import path |
| --- | --- | --- |
| Catalog JSON text | `parseCatalogJson()` or `safeParseCatalogJson()` | `@vercel-labs/ai-catalog-sdk` |
| An already-parsed JSON value representing a catalog | `parseCatalog()` or `safeParseCatalog()` | `@vercel-labs/ai-catalog-sdk` |
| An already-parsed JSON value representing one catalog entry | `parseCatalogEntry()` or `safeParseCatalogEntry()` | `@vercel-labs/ai-catalog-sdk` |
| Structural validation composed with Zod | `aiCatalogSchema`, `catalogEntrySchema`, or `trustManifestSchema` | `@vercel-labs/ai-catalog-sdk/zod` |
| JSON Schema as a TypeScript or JavaScript value | `aiCatalogJsonSchema` | `@vercel-labs/ai-catalog-sdk/json-schema` |
| Raw JSON Schema for another validator or tool | `ai-catalog.schema.json` | `@vercel-labs/ai-catalog-sdk/schema/ai-catalog.schema.json` |

The `parse*` functions throw `CatalogParseError` when input is invalid. The matching `safeParse*` functions return a discriminated `ParseResult` instead. All SDK parsers apply defensive input validation that the standalone schemas do not. `parseCatalog()` and `parseCatalogJson()` also perform catalog-wide checks. See [What gets validated](#what-gets-validated) for details.

## Handle invalid input

Use a safe parser when validation failures are expected and should be handled as values:

```ts
import { safeParseCatalogJson } from '@vercel-labs/ai-catalog-sdk';

function parseCatalogInput(source: string) {
  const result = safeParseCatalogJson(source);

  if (result.success) {
    return result.data;
  }

  for (const issue of result.error.issues) {
    console.error({
      code: issue.code, // Example: "invalid_value"
      path: issue.path, // Example: ["entries", 0]
      message: issue.message,
    });
  }

  return undefined;
}
```

Use `code` to classify an issue and `path` to locate it in the input. Present `message` to users, but do not branch on its exact wording.

## Schemas

Use the Zod schemas to compose AI Catalog validation in TypeScript. The package also provides a JSON Schema for other validators and tools. It follows the [2020-12 version of the JSON Schema standard](https://json-schema.org/draft/2020-12). This SDK maintains the schema as an interpretation of the pinned AI Catalog specification; it is not the official AI Catalog schema definition.

```ts
import { aiCatalogSchema } from '@vercel-labs/ai-catalog-sdk/zod';
import { aiCatalogJsonSchema } from '@vercel-labs/ai-catalog-sdk/json-schema';
```

Modern Node ESM consumers can import the raw artifact with a JSON import attribute:

```ts
import schema from '@vercel-labs/ai-catalog-sdk/schema/ai-catalog.schema.json' with { type: 'json' };
```

TypeScript NodeNext consumers also need `compilerOptions.resolveJsonModule: true` for the raw JSON import. Importing `aiCatalogJsonSchema` from `@vercel-labs/ai-catalog-sdk/json-schema` avoids that configuration.

## What gets validated

- `parseCatalog()` and `parseCatalogJson()` validate catalog structure, require an AI Catalog `1.x` version, and enforce entry uniqueness. The catalog and entry parsers also check that a Trust Manifest subject's type and URL match its entry. When validating JSON values, they reject circular or non-JSON data and limit work on unusually large or deeply nested inputs.
- The Zod schemas validate document structure with native Zod errors and behavior. They do not include the parser-specific resource limits or catalog-wide checks.
- The JSON Schema validates portable document structure. Some format details depend on the JSON Schema validator being used, and catalog-wide checks require `parseCatalog()` or `parseCatalogJson()`.

The SDK targets an exact prerelease specification snapshot. See [Specification snapshot interpretation](./docs/spec-interpretation.md) for the pinned revision and how conflicts in that snapshot are handled.

## Requirements

- Node.js `>=22.20.0`
- ES modules only
- TypeScript `>=5.5` for typed consumers
- Zod `^4.4.0` as a peer dependency

## Development

```sh
pnpm install
pnpm check
pnpm generate:schema
```

`pnpm package:check` creates and tests a tarball locally. It does not publish the package. The inactive release workflow template is retained only as a graduation aid; activating it requires explicit authorization.
