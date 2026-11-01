# ai-catalog-sdk

Parse, validate, and author JSON-native AI Catalog documents in TypeScript.

## Parse a catalog

```ts
import {
  entryTypes,
  isEntryType,
  parseCatalogJson,
} from 'ai-catalog-sdk';

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

The parsed result is an ordinary mutable, JSON-shaped object. Parsing checks field shapes and primitive types while preserving declaration values and unknown JSON-valued properties. It does not fetch or parse referenced artifacts.

## Parsing does not verify trust

Parsing provides structurally usable data, including declarations that may fail authoring validation or verification. Use [authoring validation](#author-a-catalog) to check an assembled document’s declarations and consistency, and verification to evaluate its artifacts and endorsements.

## Check a catalog signature

`checkCatalogSignature()` checks one catalog snapshot with a public key and expected algorithm selected by the caller:

```ts
import { checkCatalogSignature } from 'ai-catalog-sdk/verification';

const result = await checkCatalogSignature(catalog, {
  publicKey,
  expectedAlgorithm: 'ES256',
});

if (result.status !== 'valid') {
  throw new Error(`Catalog signature check failed: ${result.status}`);
}
```

A `valid` result means the exact caller-selected key verified the signature over the exact canonical catalog snapshot captured by this invocation. It does not authenticate the key as belonging to the catalog operator, verify entry Trust Manifests or artifacts referenced by URLs, establish freshness, or decide trust. See [Verification utilities](./docs/verification.md) for failure details and the complete boundary.

## Check a catalog entry

`checkCatalogEntry()` checks an entry's structure, its declared artifact digest, and each selected Trust Manifest. For the `did-web-v1` profile, it resolves the contributor's current DID document and selects an authorized assertion key:

```ts
import { checkCatalogEntry } from 'ai-catalog-sdk/verification';

const report = await checkCatalogEntry(entryWithUrl, artifactBytes);

if (report.status !== 'checked') {
  throw new Error(`Entry check failed: ${report.status}`);
}

const publisherEndorsements = report.manifests.filter(
  result => result.status === 'passed' && result.isPublisherEndorsement,
);
```

For an entry with `url`, supply the artifact bytes obtained by your application. For an entry with `data`, call `checkCatalogEntry(entryWithData)`; the SDK canonicalizes the inline artifact with JCS.

`checked` means the requested checks completed. Each attached manifest has its own result in the original array order; manifests excluded by the contributor options receive `not_checked`. The report may contain no manifests or no passing endorsements. A `passed` manifest result authenticates its contributor, binds its claims to the entry and artifact, and checks its time window. `isPublisherEndorsement: true` additionally establishes the `did:web` Publisher Profile's exact relationship to the entry's `urn:air` namespace. Applications choose which contributors and endorsements they require. See [Verification utilities](./docs/verification.md#check-a-catalog-entry) for filtering, results, and network controls.

## Check a Trust Manifest with a supplied key

Use `checkCatalogEntryTrustManifest()` when your application supplies the verification key, such as when implementing a different signer profile:

```ts
import { checkCatalogEntryTrustManifest } from 'ai-catalog-sdk/verification';

const result = await checkCatalogEntryTrustManifest(
  entryWithUrl,
  artifactBytes,
  manifest,
  { publicKey, expectedAlgorithm: 'ES256' },
);
```

For an entry with `data`, omit `artifactBytes`. A `passed` result means the manifest’s declarations and signature pass the supplied-key checks, its subject matches the entry and artifact, and its time window passes. The caller is responsible for selecting the signer profile and authenticating the key; the function performs no network requests. See [Verification utilities](./docs/verification.md#check-a-trust-manifest-with-a-supplied-key) for details.

## Author a catalog

Catalogs are ordinary JSON-shaped objects. Use `satisfies AICatalog` to check known fields at compile time, call `assertValidCatalog()` to validate the assembled document, and serialize it with `JSON.stringify()`:

```ts
import {
  mediaTypes,
  assertValidCatalog,
  type AICatalog,
} from 'ai-catalog-sdk';

const catalog = {
  specVersion: '1.0',
  entries: [
    {
      identifier: 'example-agent-plugin',
      type: mediaTypes.agentPluginZip,
      url: 'https://example.com/example-agent-plugin.zip',
    },
  ],
} satisfies AICatalog;

assertValidCatalog(catalog);
const json = JSON.stringify(catalog, null, 2);
```

The assertion checks declaration formats and internal consistency, including entry uniqueness and whether attached manifests describe their containing entries. It returns no value and throws `CatalogValidationError` with path-specific `issues` on failure. Unsigned catalogs are allowed. Artifact integrity, cryptographic authenticity, and current endorsement acceptance are evaluated by the [verification utilities](./docs/verification.md).

### Sign a Trust Manifest

To add a signed endorsement, declare the entry's artifact digest, sign a Trust Manifest, and attach the result to `trustManifests` before serializing the catalog. This example reads the artifact from a local file and uses your configured `privateKey` with the separately installed `jose` package:

```ts
import { readFile } from 'node:fs/promises';
import { CompactSign } from 'jose';
import { assertValidCatalog, mediaTypes, type AICatalog } from 'ai-catalog-sdk';
import { createDigest, signTrustManifest } from 'ai-catalog-sdk/verification';

const artifactBytes = await readFile('example-agent-plugin.zip');
const entry = {
  identifier: 'urn:air:example.com:agent:example-plugin',
  type: mediaTypes.agentPluginZip,
  url: 'https://example.com/example-agent-plugin.zip',
  digest: createDigest(artifactBytes),
};

const manifest = await signTrustManifest(
  entry,
  { contributor: 'did:web:example.com' },
  ({ payload, typ }) => new CompactSign(payload)
    .setProtectedHeader({ alg: 'ES256', typ, kid: 'did:web:example.com#release-key' })
    .sign(privateKey),
);

const catalogWithEndorsement = {
  specVersion: '1.0',
  entries: [{ ...entry, trustManifests: [manifest] }],
} satisfies AICatalog;

assertValidCatalog(catalogWithEndorsement);
const jsonWithEndorsement = JSON.stringify(catalogWithEndorsement, null, 2);
```

The digest must describe the exact bytes published at `entry.url`. For an inline entry, use `createDigest(entry.data)` to hash its JCS-canonicalized JSON value. The signed Trust Manifest endorses the entry's artifact; the containing catalog remains unsigned. See [Signing](./docs/verification.md#sign-a-trust-manifest) for signing with an explicit subject and supported callback formats.

## Choose a validation API

| Input or goal | API | Import path |
| --- | --- | --- |
| Catalog JSON text | `parseCatalogJson()` or `safeParseCatalogJson()` | `ai-catalog-sdk` |
| An already-parsed JSON value representing a catalog | `parseCatalog()` or `safeParseCatalog()` | `ai-catalog-sdk` |
| An already-parsed JSON value representing one catalog entry | `parseCatalogEntry()` or `safeParseCatalogEntry()` | `ai-catalog-sdk` |
| An assembled catalog before serialization | `assertValidCatalog()` | `ai-catalog-sdk` |
| A catalog, caller-selected public key, and expected algorithm | `checkCatalogSignature()` | `ai-catalog-sdk/verification` |
| An entry and its selected contributors' endorsements, with supplied artifact bytes for an entry with `url` | `checkCatalogEntry()` | `ai-catalog-sdk/verification` |
| An entry, explicit manifest, caller-selected public key, and the artifact representation | `checkCatalogEntryTrustManifest()` | `ai-catalog-sdk/verification` |
| Structural validation composed with Zod | `aiCatalogSchema`, `catalogEntrySchema`, or `trustManifestSchema` | `ai-catalog-sdk/zod` |
| JSON Schema as a TypeScript or JavaScript value | `aiCatalogJsonSchema` | `ai-catalog-sdk/json-schema` |
| Raw JSON Schema for another validator or tool | `ai-catalog.schema.json` | `ai-catalog-sdk/schema/ai-catalog.schema.json` |

The `parse*` functions throw `CatalogParseError` when input is invalid. The matching `safeParse*` functions return a discriminated `ParseResult` instead. All SDK parsers apply defensive input validation that the standalone schemas do not. See [What gets validated](#what-gets-validated) for the parsing, authoring, and schema boundaries.

## Handle invalid input

Use a safe parser when validation failures are expected and should be handled as values:

```ts
import { safeParseCatalogJson } from 'ai-catalog-sdk';

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

### Diagnostic codes

Parsing errors and authoring-validation errors use `CatalogIssue` diagnostics with these broad categories:

| Code | Meaning |
| --- | --- |
| `invalid_json` | Catalog text could not be decoded as JSON. |
| `invalid_json_value` | A value violates the required JSON or I-JSON representation. |
| `invalid_type` | A required value is missing or has the wrong JSON type. |
| `invalid_value` | A value violates a format, range, or allowed representation. |
| `unsupported_spec_version` | A well-formed catalog version declares an unsupported major. |
| `duplicate_entry` | Catalog entries violate identifier/version uniqueness. |
| `inconsistent_value` | Related declarations disagree, such as a Trust Manifest subject and its containing entry. |
| `resource_limit` | Input exceeds an SDK node or nesting limit. |
| `diagnostics_truncated` | Additional validation issues were omitted after the reporting limit was reached. |

Codes may be added in future releases. Keep a fallback for unknown codes, and do not depend on issue order or a lower-level `cause` for classification.

## Use lower-level verification utilities

Use the individual utilities when the composed catalog-entry check does not fit
your workflow:

| API | Use it for | Important boundary |
| --- | --- | --- |
| `canonicalizeJsonValueToBytes()` | Encoding a logical JSON value as RFC 8785 JCS UTF-8 bytes | Accepts an already-materialized JSON value, not JSON source text |
| `createCatalogSignaturePayload()` | Creating the canonical detached-JWS payload for an AI Catalog | Does not validate the catalog, construct or verify a JWS, fetch URL artifacts, or establish trust |
| `createTrustManifestSignaturePayload()` | Creating the canonical detached-JWS payload for a Trust Manifest | Does not validate the manifest, construct or verify a JWS, or establish trust |
| `checkTrustManifestSignature()` | Checking a manifest snapshot with one caller-selected public key and expected algorithm | Currently supports ES256; does not check the subject digest, identity, freshness, or trust |
| `checkDigest()` | Comparing exact caller-supplied bytes with a declared digest | Currently supports `sha256`, `sha384`, and `sha512`; a match does not authenticate the digest declaration |

These utilities do not fetch content or resolve keys. See [Verification utilities](./docs/verification.md) for their inputs, results, errors, security boundaries, and examples.

## Schemas

Use the Zod schemas to compose AI Catalog validation in TypeScript. The package also provides a JSON Schema for other validators and tools. It follows the [2020-12 version of the JSON Schema standard](https://json-schema.org/draft/2020-12). This SDK maintains the schema as an interpretation of the pinned AI Catalog specification; it is not the official AI Catalog schema definition.

```ts
import { aiCatalogSchema } from 'ai-catalog-sdk/zod';
import { aiCatalogJsonSchema } from 'ai-catalog-sdk/json-schema';
```

Modern Node ESM consumers can import the raw artifact with a JSON import attribute:

```ts
import schema from 'ai-catalog-sdk/schema/ai-catalog.schema.json' with { type: 'json' };
```

TypeScript NodeNext consumers also need `compilerOptions.resolveJsonModule: true` for the raw JSON import. Importing `aiCatalogJsonSchema` from `ai-catalog-sdk/json-schema` avoids that configuration.

## What gets validated

- The `parse*` and `safeParse*` functions check known field shapes and primitive types and reject non-JSON or excessively large or deeply nested inputs. Whole-catalog parsing also requires a supported specification major. Declaration formats, ranges, and relationships are preserved for explicit validation; a timestamp string such as `"yesterday"` is retained, while a number in that field fails parsing.
- `assertValidCatalog()` checks an assembled catalog’s declaration formats, constraints, and relationships, including entry uniqueness, subject/entry correspondence, signer/contributor equality, and timestamp ordering. It also checks digest declarations, signature representations and signed-payload eligibility, and locally checkable requirements of supported signer profiles. Unfamiliar but well-formed profiles and algorithms do not fail solely because the SDK cannot verify them.
- The Zod schemas validate their declared structure and constraints with native Zod errors and behavior. They do not apply the root parsers’ defensive input limits or the complete authoring assertion’s checks.
- The JSON Schema describes portable document constraints. Format enforcement depends on the validator; use `assertValidCatalog()` for the document relationships and signature/payload checks described above.

The SDK targets an exact prerelease specification snapshot. See [Specification snapshot interpretation](./docs/spec-interpretation.md) for the pinned revision and how conflicts in that snapshot are handled.

## Requirements

- Node.js `>=22.20.0`
- ES modules only
- TypeScript `>=5.5` for typed consumers
- Zod `^4.4.0` as a peer dependency

## Development

See [Contributing](CONTRIBUTING.md) for development setup, checks, schema generation, and documentation guidance.
