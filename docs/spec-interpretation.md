# Specification snapshot interpretation

AI Catalog is still prerelease, so this SDK targets one exact [upstream specification snapshot](https://github.com/Agent-Card/ai-catalog/blob/9aac2c1bfa622356e45a31f3dc1d342bdb329e00/specification/ai-catalog.md) rather than a moving branch. The authoritative revision metadata lives in [`src/spec-revision.ts`](https://github.com/vercel-labs/ai-catalog-sdk/blob/main/src/spec-revision.ts); the generated [JSON Schema](../schema/ai-catalog.schema.json) copies it under `x-ai-catalog-specification`.

The upstream specification and documentation are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this SDK is an independent implementation. This document records consequential interpretation choices and differences from the pinned snapshot.

## Duplicate JSON member names

The pinned snapshot requires duplicate-name rejection when processing signed payloads. The SDK instead uses the final occurrence retained by `JSON.parse()` and verifies that same resulting value. This follows the consumer-side relaxation proposed in [upstream PR #122](https://github.com/Agent-Card/ai-catalog/pull/122), which remains outside the pinned snapshot. The retained signed payload remains subject to JCS's I-JSON constraints.

## Forward compatibility

The parser accepts AI Catalog `1.x` documents and preserves unknown JSON-valued fields. A manifest containing only `contributor` plus an unrecognized evidence field is rejected until that field is recognized as substantive; contributors can use the namespaced `extensions` object for additional claims.

## Verification

The default 60-second clock tolerance for `checkCatalogEntry()` is an SDK choice permitted by the snapshot; callers can override it, including with zero.

Automatic catalog-signer authentication is not implemented. The supplied-key catalog checker establishes snapshot integrity under the caller's selected key, without assigning catalog-operator authority.
