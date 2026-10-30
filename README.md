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

The parsed result is an ordinary mutable, JSON-shaped object. Parsing validates the catalog and Trust Manifest structure, but does not fetch or parse referenced artifacts.

## Parsing does not verify trust

Parsed catalogs and Trust Manifest data are structurally validated but unauthenticated. Parsing does not verify catalog or Trust Manifest signatures, check digests, resolve identities, fetch attestations, evaluate provenance, or decide whether an artifact, catalog operator, or publisher is trustworthy.

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
  result => result.status === 'valid' && result.isPublisherEndorsement,
);
```

For an entry with `url`, supply the artifact bytes obtained by your application. For an entry with `data`, call `checkCatalogEntry(entryWithData)`; the SDK canonicalizes the inline artifact with JCS.

`checked` means the requested checks completed. Each selected manifest has its own result, and the report can contain no manifests or no valid endorsements. A valid manifest result authenticates its contributor, binds its claims to the entry and artifact, and checks its time window. `isPublisherEndorsement: true` additionally establishes the `did:web` Publisher Profile's exact relationship to the entry's `urn:air` namespace. Applications choose which contributors and endorsements they require. See [Verification utilities](./docs/verification.md#check-a-catalog-entry) for filtering, results, and network controls.

## Check artifact binding with a supplied key

Use `checkCatalogEntryArtifactBinding()` when your application supplies the verification key, such as when implementing a different signer profile:

```ts
import { checkCatalogEntryArtifactBinding } from 'ai-catalog-sdk/verification';

const result = await checkCatalogEntryArtifactBinding(
  entryWithUrl,
  artifactBytes,
  manifest,
  { publicKey, expectedAlgorithm: 'ES256' },
);
```

For an entry with `data`, omit `artifactBytes`. A `valid` result means the caller-selected key signed the manifest and its subject matches the entry and artifact. The function performs no network requests, contributor authentication, or time-window checks. See [Verification utilities](./docs/verification.md#check-artifact-binding-with-a-supplied-key) for details.

## Sign a Trust Manifest

`signTrustManifest()` constructs the signed payload and completes the manifest using your signing callback. This example uses `jose`, which your application installs separately:

```ts
import { CompactSign } from 'jose';
import { signTrustManifest } from 'ai-catalog-sdk/verification';

const manifest = await signTrustManifest(
  entry,
  { contributor: 'did:web:example.com' },
  { profile: 'did-web-v1', issuedAt: new Date().toISOString() },
  ({ payload, typ }) => new CompactSign(payload)
    .setProtectedHeader({ alg: 'ES256', typ, kid: 'did:web:example.com#release-key' })
    .sign(privateKey),
);
```

The entry must already declare its artifact `digest`. The helper derives the subject from the entry, sets the signer to the contributor, and converts the callback's JWS to the required detached compact form. It does not fetch or hash the artifact or attach the returned manifest to the entry. You can also supply a manifest with an explicit subject. See [Signing](./docs/verification.md#sign-a-trust-manifest) for callback formats and guarantees.

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

## Choose a validation API

| Input or goal | API | Import path |
| --- | --- | --- |
| Catalog JSON text | `parseCatalogJson()` or `safeParseCatalogJson()` | `ai-catalog-sdk` |
| An already-parsed JSON value representing a catalog | `parseCatalog()` or `safeParseCatalog()` | `ai-catalog-sdk` |
| An already-parsed JSON value representing one catalog entry | `parseCatalogEntry()` or `safeParseCatalogEntry()` | `ai-catalog-sdk` |
| A catalog, caller-selected public key, and expected algorithm | `checkCatalogSignature()` | `ai-catalog-sdk/verification` |
| An entry and its selected contributors' endorsements, with supplied artifact bytes for an entry with `url` | `checkCatalogEntry()` | `ai-catalog-sdk/verification` |
| An entry, explicit manifest, caller-selected public key, and the artifact representation | `checkCatalogEntryArtifactBinding()` | `ai-catalog-sdk/verification` |
| Structural validation composed with Zod | `aiCatalogSchema`, `catalogEntrySchema`, or `trustManifestSchema` | `ai-catalog-sdk/zod` |
| JSON Schema as a TypeScript or JavaScript value | `aiCatalogJsonSchema` | `ai-catalog-sdk/json-schema` |
| Raw JSON Schema for another validator or tool | `ai-catalog.schema.json` | `ai-catalog-sdk/schema/ai-catalog.schema.json` |

The `parse*` functions throw `CatalogParseError` when input is invalid. The matching `safeParse*` functions return a discriminated `ParseResult` instead. All SDK parsers apply defensive input validation that the standalone schemas do not. `parseCatalog()` and `parseCatalogJson()` also perform catalog-wide checks. See [What gets validated](#what-gets-validated) for details.

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

Issue codes identify broad failure categories:

| Code | Meaning |
| --- | --- |
| `invalid_json` | Catalog text could not be decoded as JSON. |
| `invalid_json_value` | Input is not accepted as plain, acyclic JSON data. |
| `invalid_type` | A required value is missing or has the wrong JSON type. |
| `invalid_value` | A value violates another structural rule, such as a format, range, or allowed representation. |
| `unsupported_spec_version` | A well-formed catalog version declares an unsupported major. |
| `duplicate_entry` | Catalog entries violate identifier/version uniqueness. |
| `inconsistent_value` | Related fields disagree, currently a Trust Manifest subject and its containing entry. |
| `resource_limit` | Input exceeds a parser node or nesting limit. |
| `diagnostics_truncated` | Additional validation issues were omitted after the reporting limit was reached. |

Codes may be added in future releases. Keep a fallback for unknown codes, and do not depend on issue order or a lower-level `cause` for classification.

## Author a catalog

Catalogs are ordinary JSON-shaped objects. Use `satisfies AICatalog` to check known fields at compile time, `parseCatalog()` to perform runtime and catalog-wide validation, and `JSON.stringify()` to serialize the validated result:

```ts
import {
  mediaTypes,
  parseCatalog,
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

const json = JSON.stringify(parseCatalog(catalog), null, 2);
```

The SDK does not provide a builder abstraction or custom serializer. Authoring types expose fields known to this SDK. When parsing a compatible AI Catalog `1.x` document, the SDK preserves unknown JSON-valued properties.

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

- `parseCatalog()` and `parseCatalogJson()` validate catalog structure, require an AI Catalog `1.x` version, and enforce entry uniqueness. The catalog and entry parsers check each Trust Manifest subject against its entry, including identifier, type, digest, and the presence and value of version. A signed manifest requires an entry digest. Parsers also enforce matching contributor and signer values and require expiration to follow issuance. When validating JSON values, they reject circular or non-JSON data and limit work on unusually large or deeply nested inputs.
- The Zod schemas validate document structure with native Zod errors and behavior. They do not include the parser-specific resource limits or catalog-wide checks.
- The JSON Schema validates portable document structure. Some format details depend on the validator being used. Cross-field equality, timestamp ordering, and catalog-wide checks require the SDK parsers.

The SDK targets an exact prerelease specification snapshot. See [Specification snapshot interpretation](./docs/spec-interpretation.md) for the pinned revision and how conflicts in that snapshot are handled.

## Requirements

- Node.js `>=22.20.0`
- ES modules only
- TypeScript `>=5.5` for typed consumers
- Zod `^4.4.0` as a peer dependency

## Development

See [Contributing](CONTRIBUTING.md) for development setup, checks, schema generation, and documentation guidance.
