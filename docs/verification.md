# Verification utilities

Verification and signing utilities are available from `ai-catalog-sdk/verification`. Parsing establishes structure; verification establishes only the claims described by each operation. Applications decide which endorsements and contributors satisfy their requirements.

## Check a catalog entry

`checkCatalogEntry()` validates one captured entry and evaluates its selected Trust Manifests:

```ts
import { checkCatalogEntry } from 'ai-catalog-sdk/verification';

const report = await checkCatalogEntry(entryWithUrl, artifactBytes);
// Inline entries need no separate artifact bytes:
const inlineReport = await checkCatalogEntry(entryWithData);

if (report.status === 'checked') {
  const acceptedManifests = report.manifests
    .filter(result => result.status === 'valid')
    .map(result => result.manifest);
}
```

For a URL entry, supply a `Uint8Array` containing the exact artifact representation; the SDK does not download, decode, or parse it. For an inline entry, the SDK uses JCS-canonicalized `data`. A declared entry digest is checked against that representation. Signed manifests require the digest to be present.

The function performs bounded structural validation across the entire entry, including unselected manifests. Structural or artifact failures return an entry-level failure. Otherwise, `status: 'checked'` means every selected manifest received an outcome. Empty manifest arrays, empty selections, and reports in which every endorsement failed can all be `checked`. There is no aggregate requirement for a publisher endorsement or any other accepted contribution.

The entry-level result is `CatalogEntryCheckResult`:

| Status | Meaning |
| --- | --- |
| `checked` | The requested checks completed; `manifests` contains the selected outcomes. |
| `invalid_entry` | Bounded structural validation failed; `error` is a `CatalogParseError` with issue paths. |
| `artifact_check_failed` | The declared entry digest could not be verified; `digestResult` explains the failure. |
| `publisher_selection_failed` | The requested publisher selection cannot be derived from the entry identifier; `error` explains the failure. |

Each report item contains the original array `index`, the captured `manifest` that was checked, and a result discriminator. Repeated contributors are evaluated independently in source order; the SDK does not select a preferred update or merge their claims.

### Interpret manifest results

A manifest result of `valid` means the selected signer profile authenticated the contributor, the signed subject matches the entry and artifact, and the endorsement satisfies its time window with the configured tolerance. The result's `isPublisherEndorsement` is true only when that contribution also satisfies the `did:web` Publisher Profile. For example, the publisher for `urn:air:example.com:agent:billing` is exactly `did:web:example.com`. The SDK does not infer this relationship from an artifact URL or informational publisher metadata.

A valid assessor contribution, or a valid contribution for an entry outside the Publisher Profile's identifier syntax, has `isPublisherEndorsement: false`. That value means the SDK did not establish the profile-defined publisher relationship. Applications can require a valid publisher result, particular assessors, or their own combination of evidence by inspecting the report.

| Manifest status | Meaning |
| --- | --- |
| `valid` | Contributor authentication, signature, subject binding, and current acceptance passed. Includes `isPublisherEndorsement`. |
| `missing_signature` | The manifest is unsigned metadata. |
| `profile_not_implemented` | The exact selected `profile` is not implemented. No fallback profile is tried. |
| `profile_check_failed` | The manifest or JWS does not satisfy the supported profile. `error` explains the failure. |
| `issuer_check_failed` | DID resolution, DID document validation, or key authorization failed. `error` explains the failure. |
| `signature_check_failed` | `signatureResult` contains the lower-level signature failure. |
| `subject_check_failed` | `subjectResult` contains the lower-level binding failure. |
| `not_yet_valid` | The authenticated issuance time is later than the current time plus tolerance. |
| `expired` | The current time has reached expiration plus tolerance. |

Only `valid` results authenticate an endorsement for this entry. None of these results establish claim accuracy, publisher reputation, attestation validity, or artifact safety. The operation does not authenticate the surrounding catalog or validate the artifact's format-specific schema.

### Select contributors

Ordinary calls evaluate all contributors. Use `CatalogEntryCheckOptions` to limit the work:

```ts
const report = await checkCatalogEntry(entryWithUrl, artifactBytes, {
  contributors: ['did:web:assessor.example'],
  alwaysCheckPublisherManifests: true,
});
```

| Options | Selected manifests |
| --- | --- |
| `contributors` omitted | All manifests. |
| `contributors: []` | None. |
| `contributors: [contributor]` | Every exact, case-sensitive contributor match. |
| `contributors: [], alwaysCheckPublisherManifests: true` | Publisher manifests only. |
| `contributors: [contributor], alwaysCheckPublisherManifests: true` | Listed contributors plus publisher manifests. |

`alwaysCheckPublisherManifests: true` adds publisher manifests to the selection. False or omission leaves the contributor selection unchanged; it does not exclude a publisher already selected. Publisher selection includes unsigned manifests attributed to that contributor, which receive `missing_signature`.

Publisher-only selection does not require such a manifest to exist: no matches produces `checked` with an empty list. If the SDK cannot derive a publisher identity from the entry identifier, a finite contributor selection plus `alwaysCheckPublisherManifests: true` returns a selection failure. With contributors omitted, all manifests are already selected and the option adds no requirement.

### Network and time controls

The implemented `did-web-v1` Signer Profile authenticates root `did:web` contributors using ES256. It resolves the signer's current DID document and requires the protected `kid` to identify a suitable P-256 assertion key controlled by that signer. A removed assertion key fails current-state verification even if it was authorized when signing. The profile forbids key material or key sources supplied through `jku`, `jwk`, `x5u`, and `x5c`.

```ts
const report = await checkCatalogEntry(entryWithUrl, artifactBytes, {
  timeoutMs: 60_000,
  maxResponseBytes: 16 * 1024 * 1024,
  clockToleranceMs: 60_000,
  signal: abortController.signal,
});
```

Each DID resolution has a 60-second default deadline covering DNS, redirects, and body reading, with a 16 MiB decoded body limit. Requests use HTTPS and check resolved addresses, including after redirects. A resolution timeout or size failure becomes that manifest's `issuer_check_failed` result. Selected manifests sharing a signer reuse one DID resolution within the invocation; calls do not share a DID cache. The number of selected contributors therefore affects total latency. Use `signal` to cancel the entire operation or impose an overall deadline.

The SDK samples the machine's UTC clock near completion and applies that same instant to the selected endorsements. `clockToleranceMs` defaults to 60,000 and accepts non-negative safe integer milliseconds, including zero. Issuance beyond the tolerance produces `not_yet_valid`; reaching expiration plus tolerance produces `expired`. Tolerance does not repair an expiration that is at or before issuance. `issuedAt` remains an authenticated assertion by the signer, not an independently trusted timestamp.

Entry, manifest, option, and artifact inputs are captured before asynchronous work. Later caller mutations do not change what an invocation checks. Returned manifests are the captured values. Expected verification failures return results; invalid call shapes or options, explicit cancellation, and unexpected cryptographic or runtime failures reject. Diagnostic `Error` objects can carry causes, but their message text is not a stable classification API. Branch on result discriminators.

## Sign a Trust Manifest

`signTrustManifest()` prepares the payload, calls your signer, and returns a completed `SignedTrustManifest`:

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

The entry-based overload copies only `identifier`, `type`, `digest`, and a present `version` into the subject. The entry must already declare a digest; the helper does not retrieve or hash the artifact or attach the result to the entry. The contributor can be an assessor or any other signer, independent of the entry's publisher.

For a separately distributed manifest or a subject containing additional fields, supply the subject explicitly:

```ts
const manifest = await signTrustManifest(
  { contributor, subject, attestations },
  { profile, issuedAt, expiresAt },
  createJws,
);
```

The manifest input has no existing signature. Signature metadata supplies `profile`, `issuedAt`, and optional `expiresAt`; the helper sets `signer` to `contributor`. The callback receives `{ payload, typ }`, where `payload` contains the exact canonical UTF-8 bytes and `typ` is `ai-catalog-trust-manifest+jws`. It may return a value synchronously or through a promise:

| Callback result | Handling |
| --- | --- |
| Ordinary compact JWS string, `protected.payload.signature` | Checks that the embedded payload matches and removes it. |
| Detached compact JWS string, `protected..signature` | Retains the detached form. The callback is responsible for signing the supplied payload. |
| Flattened JWS object, `{ protected, payload, signature }` | Checks the embedded payload and constructs detached compact JWS. |

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

The helpers accept materialized values and do not perform schema validation. Their output is the JWS payload, not a complete signing input or base64url-encoded text. They do not select keys or algorithms, fetch content, enforce time windows, or establish trust. Plain-JSON input defenses and resource limits apply to the complete input. JCS's I-JSON constraints apply to the retained payload after the two omissions.

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
| `missing_signature` | The containing object has no signature. |
| `invalid_jws` | The JWS is malformed or violates its required representation or headers. |
| `algorithm_mismatch` | The protected `alg` differs from the caller's expectation. Includes the claimed algorithm for diagnostics. |
| `jws_feature_not_implemented` | A well-formed critical extension is unsupported. |
| `invalid_signature` | The signature representation or cryptographic check failed. |

These functions validate the materialized JSON value without performing catalog or manifest schema validation. Wrong runtime argument types, incompatible keys, and malformed programmatic inputs reject with `TypeError`; resource limits reject with `RangeError`. Unexpected backend failures reject rather than becoming verification results.

## Check artifact binding with a supplied key

`checkCatalogEntryArtifactBinding()` checks one explicit signed manifest against an entry and its artifact representation:

```ts
import { checkCatalogEntryArtifactBinding } from 'ai-catalog-sdk/verification';

const urlResult = await checkCatalogEntryArtifactBinding(
  entryWithUrl,
  artifactBytes,
  manifest,
  { publicKey, expectedAlgorithm: 'ES256' },
);

const inlineResult = await checkCatalogEntryArtifactBinding(
  entryWithData,
  manifest,
  { publicKey, expectedAlgorithm: 'ES256' },
);
```

The manifest need not already be attached to the entry. A `valid` result means its signature verifies under the supplied key, its subject identifier and type equal the entry's, version presence and value match, its digest matches the entry's declared digest, and the artifact representation matches that digest. Artifact retrieval URLs do not participate in subject binding, so identical bytes can be served from mirrors.

`signature_check_failed` carries the lower-level `signatureResult`; `subject_check_failed` carries `missing_subject`, `identifier_mismatch`, `version_mismatch`, `type_mismatch`, `digest_mismatch`, or a lower-level digest failure as `subjectResult`. Version mismatch includes presence on only one side. A signature failure takes precedence over a subject failure. The function expects a typed or previously parsed entry and does not rerun whole-entry structural validation.

This utility performs no network requests, contributor authentication, or time-window checks. A custom signer-profile implementation must supply those checks around it. Wrong runtime argument types, hostile programmatic inputs, and shared or detached artifact buffers reject with `TypeError`; canonicalization limits reject with `RangeError`, and unexpected backend errors propagate.

## Canonicalize a logical JSON value

`canonicalizeJsonValueToBytes(value)` produces fresh RFC 8785 JCS UTF-8 bytes from a materialized JSON value:

```ts
import { canonicalizeJsonValueToBytes, checkDigest } from 'ai-catalog-sdk/verification';

const result = checkDigest(
  canonicalizeJsonValueToBytes(entry.data),
  expectedDigest,
);
```

Property names are sorted by UTF-16 code units, array order and Unicode normalization are preserved, and numbers use JCS's ECMAScript representation. The function does not parse source text: passing `'{"x":1}'` canonicalizes a JSON string. It cannot recover duplicate names, original number spelling or precision, or invalid source UTF-8 lost during parsing. It does not omit any signature fields.

Inputs must contain plain JSON objects, arrays, and primitives. Non-finite numbers, lone Unicode surrogates, noncharacters, cycles, sparse or decorated arrays, accessors, proxies, exotic objects, and other non-JSON values throw `TypeError`. Fixed node or nesting-depth limits produce `RangeError`. Canonicalization uses accepted own data properties without invoking inherited `toJSON` hooks or overridden array methods.

## Check a digest

`checkDigest(bytes, expectedDigest)` compares the exact byte range supplied by the caller with an AI Catalog digest:

```ts
import { checkDigest } from 'ai-catalog-sdk/verification';

const result = checkDigest(
  artifactBytes,
  'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
);

if (result.status !== 'match') {
  // Do not use the bytes as the declared artifact.
}
```

The function hashes bytes verbatim. It does not fetch content, decode a representation, serialize JSON, or apply JCS canonicalization. In particular, callers must not pass an ordinary JSON serialization for an entry with `data`, whose inline artifact digest is defined over JCS-canonicalized `data`.

The result statuses have deliberately narrow meanings:

| Status | Meaning |
| --- | --- |
| `match` | The supplied bytes match the declared digest. |
| `mismatch` | The digest is implemented and well-formed, but the bytes do not match. |
| `invalid_digest` | The declaration is malformed, or a known algorithm has an invalid output length. |
| `algorithm_not_implemented` | The declaration is syntactically valid, but the SDK does not implement its exact algorithm token. |

The SDK currently implements the exact, case-sensitive `sha256`, `sha384`, and `sha512` tokens with 64, 96, and 128 lowercase hexadecimal characters, respectively. This is an SDK capability boundary, not a claim that other algorithms are forbidden or insecure. If the runtime cannot execute a registered implementation, the function throws `DigestAlgorithmUnavailableError` and preserves the underlying error as `cause`.

`Buffer` values and `Uint8Array` subviews are accepted. Shared or detached backing buffers are rejected because they cannot provide a stable byte view for the check. Wrong JavaScript argument types and shared or detached byte views throw `TypeError`.

A `match` result establishes only equality between caller-supplied bytes and a declared digest. It does not establish who made the declaration, whether the digest is authoritative, or whether the content is trustworthy.
