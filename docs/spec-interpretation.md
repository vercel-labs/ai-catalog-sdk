# Specification snapshot interpretation

AI Catalog is still prerelease, so this SDK targets one exact [upstream specification snapshot](https://github.com/Agent-Card/ai-catalog/blob/9aac2c1bfa622356e45a31f3dc1d342bdb329e00/specification/ai-catalog.md) rather than a moving branch. The authoritative revision metadata lives in [`src/spec-revision.ts`](https://github.com/vercel-labs/ai-catalog-sdk/blob/main/src/spec-revision.ts); the generated [JSON Schema](../schema/ai-catalog.schema.json) copies it under `x-ai-catalog-specification`.

The upstream specification and documentation are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this SDK is an independent implementation. This document records consequential interpretation choices and differences from the pinned snapshot.

## Duplicate JSON member names

The pinned snapshot requires duplicate-name rejection when processing signed payloads. The SDK instead uses the final occurrence retained by `JSON.parse()` and verifies that same resulting value. This follows the consumer-side relaxation proposed in [upstream PR #122](https://github.com/Agent-Card/ai-catalog/pull/122), which remains outside the pinned snapshot. The retained signed payload remains subject to JCS's I-JSON constraints.

## Structural validation

The parsers enforce the specification's substantive-manifest, signed-manifest, subject consistency, contributor/signer equality, and timestamp-ordering rules. A Trust Manifest must contain a signature, a trust schema, non-empty attestations, non-empty provenance, or non-empty extensions. An absent or empty `trustManifests` array is permitted.

The exported JSON Schema represents portable structural constraints. It cannot establish equality between related fields or compare timestamp instants; use the SDK parsers for those checks. Digest strings are checked structurally for `algorithm:lowercase-hex`, without judging algorithm strength or requiring an algorithm-specific length. An attestation size must be a non-negative safe integer.

## Forward compatibility

The parser accepts AI Catalog `1.x` documents and preserves unknown JSON-valued fields. A manifest containing only `contributor` plus an unrecognized evidence field is rejected until that field is recognized as substantive; contributors can use the namespaced `extensions` object for additional claims.

## Verification

Parsing validates structure without verifying signatures, artifact content, identities, evidence, or current acceptance. `checkCatalogEntry()` evaluates selected contributions independently and reports their outcomes without requiring a publisher endorsement or deciding application trust policy. Its default 60-second clock tolerance is an SDK choice permitted by the snapshot; callers can override it, including with zero.

Automatic catalog-signer authentication is not implemented. The supplied-key catalog checker establishes snapshot integrity under the caller's selected key, without assigning catalog-operator authority.
