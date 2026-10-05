# Specification snapshot interpretation

AI Catalog is still prerelease, so this SDK targets one exact [upstream specification snapshot](https://github.com/Agent-Card/ai-catalog/blob/8d05e7f9086d0483d9fb30fa96b528e8e7ade53d/specification/ai-catalog.md) rather than a moving branch. The authoritative revision metadata lives in [`src/spec-revision.ts`](https://github.com/vercel-labs/ai-catalog-sdk/blob/main/src/spec-revision.ts); the generated [JSON Schema](../schema/ai-catalog.schema.json) copies it under `x-ai-catalog-specification`.

The upstream specification and documentation are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); this SDK is an independent implementation, and this document records where its interpretation differs from the pinned snapshot.

## Where the snapshot disagrees

The snapshot's normative CDDL omits the top-level catalog `signature` and does not express the substantive-manifest and signed-manifest conditional rules. The SDK follows the prose plus ADR-0019 and ADR-0020 because that interpretation preserves signed artifact binding and rejects misleading empty manifests.

The specification says that a Trust Manifest's identity domain must match the publisher domain in its entry identifier, but it does not define how to compare arbitrary identifier schemes. The SDK therefore leaves that check to applications. Entry parsers require a manifest subject's identifier, type, and optional URL to match its catalog entry. For signed manifests, entry and subject versions must either both be absent or both be present and exactly equal.

## Forward compatibility

The parser accepts AI Catalog `1.x` documents and preserves unknown JSON-valued fields. One rule cannot be made open-ended: a Trust Manifest must contain substantive evidence. At this snapshot, the recognized evidence is a `signature`, a non-empty `attestations` array, a non-empty `provenance` array, or a `trustSchema`. A future `1.x` manifest containing only `identity` plus a newly introduced evidence field will be rejected until the SDK is updated to recognize that field.

## Other structural choices

Digest strings are checked only for the form `algorithm:lowercase-hex`. Parsing does not judge algorithm strength, require an algorithm-specific length, or compare a digest with artifact bytes. An attestation size must be a non-negative integer that JavaScript can represent exactly.

## Trust verification

Parsing a Trust Manifest validates structure only. It does not verify signatures, digests, identities, trust anchors, attestations, provenance, expiration policy, or artifact content.
