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

Treat parsed Trust Manifest data as unverified input. Parsing does not verify signatures or digests, resolve identities, fetch attestations, evaluate provenance, or decide whether an artifact or publisher is trustworthy.

## Canonicalize a logical JSON value

Use `canonicalizeJsonValueToBytes()` when an AI Catalog operation defines its
input as RFC 8785 JSON Canonicalization Scheme (JCS) bytes. For example, an
inline entry's digest is computed over the canonicalized `data` value:

```ts
import {
  canonicalizeJsonValueToBytes,
  checkDigest,
} from 'ai-catalog-sdk/verification';

const result = checkDigest(
  canonicalizeJsonValueToBytes(entry.data),
  expectedDigest,
);
```

The function accepts an already-materialized JSON value, not JSON source text,
and returns fresh UTF-8 bytes. It does not parse JSON, remove signature fields,
or recover details already lost during parsing. See
[Verification utilities](./docs/verification.md) for its input constraints and
source-level limitations.

## Create a Trust Manifest signature payload

Use `createTrustManifestSignaturePayload()` to produce the detached-JWS
payload defined by the AI Catalog Trust Manifest protocol:

```ts
import { createTrustManifestSignaturePayload } from 'ai-catalog-sdk/verification';

const payload = createTrustManifestSignaturePayload(trustManifest);
```

The function omits exactly the manifest's own, top-level, case-sensitive
`signature` member and returns fresh RFC 8785 UTF-8 bytes. It preserves all
other members, including unknown fields, extensions, and nested fields named
`signature`, without mutating the manifest. It does not validate the Trust
Manifest schema, construct or verify a JWS, choose a key or algorithm, or
establish trust. The entire input, including the omitted `signature` member,
must satisfy the canonicalizer's programmatic I-JSON restrictions. See
[Verification utilities](./docs/verification.md) for the complete boundary.

## Check a Trust Manifest signature

`checkTrustManifestSignature()` checks the manifest's detached JWS against one
public key and algorithm selected by the caller:

```ts
import { createPublicKey } from 'node:crypto';
import { checkTrustManifestSignature } from 'ai-catalog-sdk/verification';

const publicKey = createPublicKey(configuredPublisherPublicKeyPem);
const result = await checkTrustManifestSignature(trustManifest, {
  publicKey,
  expectedAlgorithm: 'ES256',
});

if (result.status !== 'valid') {
  throw new Error(`Signature check failed: ${result.status}`);
}
```

The function currently supports ES256 with a public P-256 `KeyObject` or
`CryptoKey`. The caller must obtain the key through an independently trusted
path; JWS header fields do not select a key, trigger network requests, or
override the expected algorithm. A `valid` result covers the exact canonical
manifest snapshot but does not prove who controls the key, establish trust,
validate the manifest schema, check the subject digest, or enforce timestamps.
See [Verification utilities](./docs/verification.md) for the complete result,
error, and JWS-profile semantics.

## Check exact bytes against a digest

Use the separate verification subpath to compare caller-supplied bytes with a
declared digest:

```ts
import { checkDigest } from 'ai-catalog-sdk/verification';

const result = checkDigest(artifactBytes, expectedDigest);
if (result.status !== 'match') {
  throw new Error(`Digest check failed: ${result.status}`);
}
```

`checkDigest()` currently implements the exact `sha256` algorithm token. It
does not fetch, decode, serialize, or JCS-canonicalize content, and a match does
not establish who declared the digest or whether it is trustworthy. See
[Verification utilities](./docs/verification.md) for the complete result and
error semantics.

## Choose a validation API

| Input or goal | API | Import path |
| --- | --- | --- |
| Catalog JSON text | `parseCatalogJson()` or `safeParseCatalogJson()` | `ai-catalog-sdk` |
| An already-parsed JSON value representing a catalog | `parseCatalog()` or `safeParseCatalog()` | `ai-catalog-sdk` |
| An already-parsed JSON value representing one catalog entry | `parseCatalogEntry()` or `safeParseCatalogEntry()` | `ai-catalog-sdk` |
| A logical JSON value requiring RFC 8785 bytes | `canonicalizeJsonValueToBytes()` | `ai-catalog-sdk/verification` |
| A Trust Manifest requiring its detached-JWS payload | `createTrustManifestSignaturePayload()` | `ai-catalog-sdk/verification` |
| A Trust Manifest, trusted public key, and expected signature algorithm | `checkTrustManifestSignature()` | `ai-catalog-sdk/verification` |
| Exact bytes and a declared digest | `checkDigest()` | `ai-catalog-sdk/verification` |
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
