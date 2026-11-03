# Verification utilities

Verification and signing utilities are available from `ai-catalog-sdk/verification`. Authoring validation checks a catalog’s declarations and internal consistency. Verification checks signatures, artifact binding, and the applicable authentication and time requirements. Applications decide which endorsements satisfy their requirements.

## Check a catalog entry

`checkCatalogEntry()` validates one captured entry and evaluates its selected Trust Manifests:

```ts
import { checkCatalogEntry } from 'ai-catalog-sdk/verification';

const report = await checkCatalogEntry(entryWithUrl, artifactBytes);

if (report.status === 'checked') {
  const passingManifests = report.manifests
    .filter(result => result.status === 'passed')
    .map(result => result.manifest);
}
```

For an entry with `url`, supply the artifact bytes obtained by your application as a `Uint8Array`. For an entry with `data`, call `checkCatalogEntry(entryWithData)`; the SDK applies JCS canonicalization to `entry.data` when checking the declared digest. Signed manifests require the digest to be present.

The function checks the entry’s fields and declared artifact digest, then evaluates each selected Trust Manifest independently. `trustManifests` must be an array when present. A selected manifest with invalid field shapes or declarations, or an unusable signed payload, receives `invalid_manifest` without preventing the other selected manifests from being checked. A `CatalogEntryCheckResult` with `report.status === 'checked'` can look like this:

```ts
{
  status: 'checked',
  manifests: [
    {
      manifest: {
        contributor: 'did:web:example.com',
        extensions: { 'example.com': true },
      },
      status: 'unsigned',
    },
  ],
}
```

The outer `report.status` of `checked` means the requested checks completed; it does not require a passing endorsement. `report.manifests` contains one result per attached manifest, in the same order, including repeated contributors. An entry without manifests produces an empty array.

In this example, `report.manifests[0].status` is `unsigned`, so the manifest is unsigned metadata. Manifests excluded by the contributor options receive `not_checked`.

If structural validation fails, the result has `report.status === 'invalid_entry'`:

```ts
{
  status: 'invalid_entry',
  error: parseError,
}
```

`parseError` is a `CatalogParseError`. Its `issues` identify the validation problems and their input paths.

When the entry declares a digest, the SDK checks it against the supplied artifact bytes for a URL entry or JCS-canonicalized `data` for an inline entry. These failures also return before manifest verification:

```ts
// The artifact bytes do not match the declared digest.
{ status: 'artifact_digest_mismatch' }

// The digest syntax or an implemented algorithm’s digest length is invalid.
{ status: 'invalid_digest' }

// The digest names an algorithm the SDK does not implement.
{
  status: 'digest_algorithm_not_implemented',
  algorithm: 'blake3',
}
```

### Interpret manifest results

In a `checkCatalogEntry()` report, `passed` means the selected signer profile authenticated the contributor, the signed subject matches the entry and artifact, and the endorsement satisfies its time window with the configured tolerance. The result's `isPublisherEndorsement` is true only when that contribution also satisfies the `did:web` Publisher Profile. For example, the publisher for `urn:air:example.com:agent:billing` is exactly `did:web:example.com`. The SDK does not infer this relationship from an artifact URL or informational publisher metadata.

A passing assessor contribution, or a passing contribution for an entry outside the Publisher Profile's identifier syntax, has `isPublisherEndorsement: false`. That value means the SDK did not establish the profile-defined publisher relationship. Applications can require a passing publisher result, particular assessors, or their own combination of evidence by inspecting the report.

For example, a report with passing publisher and assessor contributions can look like this. `publisherManifest` and `assessorManifest` represent their captured manifest objects:

```ts
{
  status: 'checked',
  manifests: [
    {
      manifest: publisherManifest,
      status: 'passed',
      isPublisherEndorsement: true,
    },
    {
      manifest: assessorManifest,
      status: 'passed',
      isPublisherEndorsement: false,
    },
  ],
}
```

See [Check results](#check-results) for the complete status reference.

### Select contributors

Ordinary calls evaluate all contributors. Use `CatalogEntryCheckOptions` to limit which manifests are verified:

```ts
const report = await checkCatalogEntry(entryWithUrl, artifactBytes, {
  contributors: ['did:web:assessor.example'],
  alwaysCheckPublisherManifests: true,
});
```

| Options | Manifests to verify |
| --- | --- |
| `contributors` omitted | All manifests. |
| `contributors: []` | None. |
| `contributors: [contributor]` | Every exact, case-sensitive contributor match. |
| `contributors: [], alwaysCheckPublisherManifests: true` | Publisher manifests only. |
| `contributors: [contributor], alwaysCheckPublisherManifests: true` | Listed contributors plus publisher manifests. |

`alwaysCheckPublisherManifests: true` adds publisher manifests to the selection. False or omission leaves the contributor selection unchanged; it does not exclude a publisher already selected. Publisher selection includes unsigned manifests attributed to that contributor, which receive `unsigned`.

Publisher-only selection does not require such a manifest to exist: when none match, every attached manifest receives `not_checked`. If the SDK cannot derive a publisher identity from the entry identifier, the option adds no manifests to the contributor selection.

### Network and time controls

The SDK supports the [`did-web-v1` Signer Profile](https://github.com/Agent-Card/ai-catalog/blob/9aac2c1bfa622356e45a31f3dc1d342bdb329e00/specification/ai-catalog.md#the-did-web-signer-profile) for root `did:web` contributors using ES256. It resolves the contributor's current DID document and checks that the signing key is authorized for assertions.

```ts
const report = await checkCatalogEntry(entryWithUrl, artifactBytes, {
  resolutionTimeoutMs: 60_000,
  maxResponseBytes: 16 * 1024 * 1024,
  clockToleranceMs: 60_000,
  signal: abortController.signal,
});
```

`resolutionTimeoutMs` sets the deadline for each DID resolution, covering DNS, redirects, and reading and parsing the response; it defaults to 60,000 ms. The decoded body limit defaults to 16 MiB. Requests use HTTPS and check resolved addresses, including after redirects. A resolution timeout or size failure becomes that manifest's `issuer_check_failed` result. Selected manifests sharing a signer reuse one DID resolution within the invocation; calls do not share a DID cache. The number of selected contributors therefore affects total latency. Use `signal` to cancel the entire operation or impose an overall deadline.

`checkCatalogEntry()` accepts `nowMs`, an optional safe integer UTC epoch time in milliseconds used to evaluate the time window. When omitted, the SDK samples the machine's UTC clock near completion; `checkCatalogEntry()` applies the same instant to all selected endorsements. `clockToleranceMs` defaults to 60,000 and accepts non-negative safe integer milliseconds, including zero. Issuance beyond the tolerance produces `not_yet_valid`; reaching expiration plus tolerance produces `expired`. Tolerance does not repair an expiration that is at or before issuance. `issuedAt` remains an authenticated assertion by the signer, not an independently trusted timestamp.

Entry, manifest, option, and artifact inputs are captured before asynchronous work. Later caller mutations do not change what an invocation checks. Returned manifests are the captured values. Expected verification failures return results; invalid call shapes or options, explicit cancellation, and unexpected cryptographic or runtime failures reject. Diagnostic `Error` objects can carry causes, but their message text is not a stable classification API. Branch on result discriminators.

## Check a Trust Manifest with a supplied key

`checkCatalogEntryTrustManifest()` checks one explicit manifest against an entry and its artifact representation using your application's verification key:

```ts
import { checkCatalogEntryTrustManifest } from 'ai-catalog-sdk/verification';

const resultForEntryWithUrl = await checkCatalogEntryTrustManifest(
  entryWithUrl,
  artifactBytes,
  manifest,
  { publicKey, expectedAlgorithm: 'ES256' },
);

const resultForEntryWithData = await checkCatalogEntryTrustManifest(
  entryWithData,
  manifest,
  { publicKey, expectedAlgorithm: 'ES256' },
);
```

The manifest need not already be attached to the entry. The function validates the entry’s field shapes while ignoring its attached `trustManifests`. It then checks the entry’s declared artifact digest, followed by the supplied manifest’s field shapes, declarations and subject correspondence, signature, and time window. See the shared [check results](#check-results) for statuses and precedence.

A `passed` result means those checks passed under the caller-selected key. A `not_yet_valid` or `expired` result means the preceding declaration, signature, and binding checks passed.

This utility performs no network requests. The caller is responsible for selecting and applying the signer profile and authenticating and authorizing the supplied key. It accepts the same [`nowMs` and `clockToleranceMs` controls](#network-and-time-controls) as `checkCatalogEntry()`. Invalid call shapes or options and unexpected runtime failures reject, as with that operation.

## Check results

`checkCatalogEntry()` returns entry-precheck failures directly, or a `checked` report containing the individual results in `manifests`. After the entry prechecks pass, a failure result for one manifest does not stop `checkCatalogEntry()` from checking the other selected manifests.

In a `checked` report, `report.manifests[i].manifest` has type `JsonValue` for `invalid_manifest` and `not_checked`, and type `TrustManifest` for all other manifest statuses.

For a single explicit manifest, `checkCatalogEntryTrustManifest()` returns one result directly.

Field paths are relative to each function’s return value; `—` means the function does not return that status. Rows follow failure precedence within the applicable checks.

| Status | `checkCatalogEntry()` | <code>checkCatalogEntry<br>TrustManifest()</code> | Description |
| --- | --- | --- | --- |
| `invalid_entry` | `status` | `status` | Entry fields have invalid shapes, or inline data cannot satisfy JCS for the declared digest. `error` is a `CatalogParseError` with path-specific `issues`. |
| `invalid_digest` | `status` | `status` | The entry’s declared artifact digest has invalid syntax or an incorrect length for an implemented algorithm. |
| `digest_algorithm_not_implemented` | `status` | `status` | The entry’s artifact digest names an algorithm the SDK does not implement. Includes `algorithm`. |
| `artifact_digest_mismatch` | `status` | `status` | The supplied artifact bytes, or JCS-canonicalized inline data, do not match the entry’s declared digest. |
| `not_checked` | `manifests[i].status` | — | The contributor options excluded this manifest. This is a selection outcome. |
| `invalid_manifest` | `manifests[i].status` | `status` | The manifest or one of its fields has the wrong type, its metadata, required content, or subject/entry correspondence is invalid, or its signed payload cannot satisfy JCS. `error` is a `CatalogValidationError` with path-specific `issues`. |
| `unsigned` | `manifests[i].status` | `status` | The manifest has no `signature` of its own to verify. |
| `profile_not_implemented` | `manifests[i].status` | — | The selected signer profile is not implemented. Includes `profile`; no fallback profile is tried. |
| `invalid_jws` | `manifests[i].status` | `status` | The JWS is malformed or violates its required representation or common headers. |
| `algorithm_mismatch` | `manifests[i].status` | `status` | The protected `alg` differs from the expected algorithm. Includes the claimed `algorithm`. |
| `jws_feature_not_implemented` | `manifests[i].status` | `status` | A well-formed critical JWS extension is unsupported. |
| `profile_check_failed` | `manifests[i].status` | — | The manifest or JWS does not satisfy the supported signer profile. `error` explains the failure. |
| `issuer_check_failed` | `manifests[i].status` | — | DID resolution, DID document validation, or key authorization failed. `error` explains the failure. |
| `invalid_signature` | `manifests[i].status` | `status` | The signature does not verify under the selected key. |
| `not_yet_valid` | `manifests[i].status` | `status` | Issuance is later than the evaluation time plus tolerance. The preceding checks passed. |
| `expired` | `manifests[i].status` | `status` | The evaluation time has reached expiration plus tolerance. The preceding checks passed. |
| `passed` | `manifests[i].status` | `status` | The individual manifest passed the operation’s checks. In a `checkCatalogEntry()` report, includes `isPublisherEndorsement`. |
| `checked` | `status` | — | The entry report completed, and `manifests` contains its individual outcomes. This can include no passing contributions or no manifests. |

`checkCatalogEntry()` selects and applies the supported signer profile and authenticates and authorizes the verification key. With `checkCatalogEntryTrustManifest()`, the caller selects and applies the signer profile and authenticates and authorizes the supplied key. Neither establishes claim accuracy, publisher reputation, attestation validity, or artifact safety. These operations do not authenticate the surrounding catalog or validate the artifact’s format-specific schema.

## Check signatures with a supplied key

`checkCatalogSignature()` and `checkTrustManifestSignature()` verify a detached compact JWS with one caller-selected public key and expected algorithm:

```ts
import { checkCatalogSignature } from 'ai-catalog-sdk/verification';

const result = await checkCatalogSignature(catalog, {
  publicKey,
  expectedAlgorithm: 'ES256',
});
```

They share `SignatureCheckOptions` and `SignatureCheckResult`. The SDK implements the exact algorithm token `ES256`; supply a native public P-256 `KeyObject` or a P-256 `CryptoKey` usable for verification. Typed consumers of this Node-only subpath need compatible Node.js declarations, such as `@types/node`.

A `valid` result establishes only that the supplied key verifies the captured payload. It does not authenticate the claimed contributor or catalog operator, enforce issuance or expiration, check artifact binding, or establish trust. Header fields do not select a key or trigger network requests.

The JWS must use canonical, unpadded base64url segments and a valid UTF-8 protected header. The required `typ` is exactly `ai-catalog+jws` for catalogs or `ai-catalog-trust-manifest+jws` for manifests. Any protected `b64` is forbidden. The expected algorithm is trusted caller input; the unverified `alg` is compared against it and never selects an algorithm.

| Signature status | Meaning |
| --- | --- |
| `valid` | The supplied key verifies the signature over the captured payload. |
| `unsigned` | The containing catalog or manifest has no `signature` of its own to verify. |
| `invalid_jws` | The JWS is malformed or violates its required representation or headers. |
| `algorithm_mismatch` | The protected `alg` differs from the caller's expectation. Includes the claimed algorithm for diagnostics. |
| `jws_feature_not_implemented` | A well-formed critical extension is unsupported. |
| `invalid_signature` | The signature representation or cryptographic check failed. |

These functions validate the materialized JSON value without performing catalog or manifest schema validation. Wrong runtime argument types, incompatible keys, and malformed programmatic inputs reject with `TypeError`; resource limits reject with `RangeError`. Unexpected backend failures reject rather than becoming verification results.

## Check a digest

`checkDigest(value, expectedDigest)` compares exact bytes or a JCS-canonicalized JSON value with an AI Catalog digest:

```ts
import { checkDigest } from 'ai-catalog-sdk/verification';

const result = checkDigest(
  artifactBytes,
  'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
);

if (result.status !== 'match') {
  // Do not use the bytes as the declared artifact.
}

const resultForInlineData = checkDigest(entry.data, expectedDigest);
```

`Uint8Array` and `Buffer` inputs are hashed as their exact byte range. Other JSON values are JCS-canonicalized before hashing. Pass retrieved bytes for a URL artifact and `entry.data` for an inline artifact. Strings are JSON string values, including their JSON quotes and escapes; to check raw text bytes, encode them with `TextEncoder` first.

The result statuses have deliberately narrow meanings:

| Status | Meaning |
| --- | --- |
| `match` | The supplied bytes or JCS-canonicalized JSON value match the declared digest. |
| `mismatch` | The digest is implemented and well-formed, but the supplied bytes or JCS-canonicalized JSON value do not match. |
| `invalid_digest` | The declaration is malformed, or a known algorithm has an invalid output length. |
| `algorithm_not_implemented` | The declaration is syntactically valid, but the SDK does not implement its exact algorithm token. |

The SDK currently implements the exact, case-sensitive `sha256`, `sha384`, and `sha512` tokens with 64, 96, and 128 lowercase hexadecimal characters, respectively. This is an SDK capability boundary, not a claim that other algorithms are forbidden or insecure. If the runtime cannot execute a registered implementation, the function throws `DigestAlgorithmUnavailableError` and preserves the underlying error as `cause`.

`Buffer` values and `Uint8Array` subviews are accepted. Shared or detached backing buffers are rejected because they cannot provide a stable byte view for the check. Wrong JavaScript argument types, shared or detached byte views, and JSON values that cannot satisfy JCS throw `TypeError`. JSON values beyond the SDK's node or nesting-depth limits throw `RangeError`.

A `match` result establishes only that the supplied bytes or JCS-canonicalized JSON value match a declared digest. It does not establish who made the declaration, whether the digest is authoritative, or whether the content is trustworthy.

## Create a digest

`createDigest(value, algorithm?)` returns an artifact digest in `algorithm:lowercase-hex` form. The algorithm defaults to `sha256`; `sha384` and `sha512` are also supported:

```ts
import { createDigest } from 'ai-catalog-sdk/verification';

const artifactDigest = createDigest(artifactBytes);
const inlineDigest = createDigest(entry.data);
const sha384Digest = createDigest(artifactBytes, 'sha384');
```

A `Uint8Array` or `Buffer` is hashed as its exact byte range. Other logical JSON values are JCS-canonicalized before hashing. Strings are JSON string values, including their JSON quotes and escapes; ordinary arrays are JSON arrays. To hash text as raw bytes, encode it with `TextEncoder` first.

## Sign a Trust Manifest

`signTrustManifest()` prepares the payload, calls your signer, and returns a completed `SignedTrustManifest`:

```ts
import { CompactSign } from 'jose';
import { signTrustManifest } from 'ai-catalog-sdk/verification';

const manifest = await signTrustManifest(
  entry,
  { contributor: 'did:web:example.com' },
  ({ payload, typ }) => new CompactSign(payload)
    .setProtectedHeader({ alg: 'ES256', typ, kid: 'did:web:example.com#release-key' })
    .sign(privateKey),
);
```

The callback receives `{ payload, typ }`, where `payload` contains the exact canonical UTF-8 bytes and `typ` is `ai-catalog-trust-manifest+jws`.

The entry-based overload copies only `identifier`, `type`, `digest`, and a present `version` into the subject. The entry must already declare a digest; the helper does not retrieve or hash the artifact or attach the result to the entry. The contributor can be an assessor or any other signer, independent of the entry's publisher.

For a separately distributed manifest or a subject containing additional fields, supply the subject explicitly:

```ts
const manifest = await signTrustManifest(
  { contributor, subject, attestations },
  createJws,
  { profile, issuedAt, expiresAt },
);
```

Both overloads accept an optional trailing `signatureMetadata` argument supplying `profile`, `issuedAt`, and `expiresAt`. An omitted `profile` defaults to `did-web-v1`; an omitted `issuedAt` uses the current time, captured before the callback. `expiresAt` is absent unless supplied. The helper sets `signer` to `contributor`.

The callback may return any of these JWS representations, synchronously or through a promise:

| Callback result | Handling |
| --- | --- |
| Ordinary compact JWS string (`protected.payload.signature`) | Checks that the embedded payload matches and removes it. |
| Detached compact JWS string (`protected..signature`) | Retains the detached form. The callback is responsible for signing the supplied payload. |
| Flattened JWS object (`{ protected, payload, signature }`) | Checks the embedded payload and constructs detached compact JWS. |

These are standard JWS representations. The helper rejects unprotected headers, checks the required protected `typ` and `alg`, forbids `alg: 'none'` and any `b64`, and preserves the captured manifest contents. It does not verify the callback's cryptographic signature or authenticate the chosen key. The callback is responsible for selecting the correct algorithm, headers, and signing key for the requested profile.

## Create signature payloads

`createCatalogSignaturePayload(catalog)` and `createTrustManifestSignaturePayload(manifest)` return the exact RFC 8785 JCS UTF-8 payload bytes for their containing object:

```ts
import {
  createCatalogSignaturePayload,
  createTrustManifestSignaturePayload,
} from 'ai-catalog-sdk/verification';

const catalogPayload = createCatalogSignaturePayload(catalog);
const manifestPayload = createTrustManifestSignaturePayload(manifest);
```

Each helper omits only the immediate `signature.jws` and immediate `additionalSignatures`. Signature metadata, unknown fields, extensions, and nested members with those names remain covered. A catalog payload includes complete nested manifest signatures. Inputs can contain a complete signature or pre-signing metadata without `jws`; the helpers do not mutate them.

The helpers accept plain JSON objects and do not perform schema validation. Their output is the JWS payload, not a complete signing input or base64url-encoded text. They do not select keys or algorithms, fetch content, enforce time windows, or establish trust.

## Canonicalize a logical JSON value

`canonicalizeJsonValueToBytes(value)` produces fresh RFC 8785 JCS UTF-8 bytes from a materialized JSON value:

```ts
import { canonicalizeJsonValueToBytes } from 'ai-catalog-sdk/verification';

const bytes = canonicalizeJsonValueToBytes({ b: 2, a: 1 });
// UTF-8 bytes for {"a":1,"b":2}
```

Property names are sorted by UTF-16 code units, array order and Unicode normalization are preserved, and numbers use JCS's ECMAScript representation. Strings are canonicalized as JSON string values; parse JSON source text before passing it.

Inputs must contain plain JSON objects, arrays, and primitives. Non-finite numbers, lone Unicode surrogates, noncharacters, cycles, sparse or decorated arrays, accessors, proxies, exotic objects, and other non-JSON values throw `TypeError`. Fixed node or nesting-depth limits produce `RangeError`. Canonicalization uses accepted own data properties without invoking inherited `toJSON` hooks or overridden array methods.

## Validation diagnostics

`CatalogParseError` and `CatalogValidationError` use these `CatalogIssue.code` categories for parsing and authoring-validation problems, including validation errors attached to verification results. These codes are distinct from verification result statuses.

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
