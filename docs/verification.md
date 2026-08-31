# Verification utilities

Verification utilities are available from the `ai-catalog-sdk/verification`
subpath. They are separate from parsing so applications can distinguish
structural validation from checks performed against external content.

## Check a digest

`checkDigest(bytes, expectedDigest)` compares the exact byte range supplied by
the caller with an AI Catalog digest:

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

The function hashes bytes verbatim. It does not fetch content, decode a
representation, serialize JSON, or apply JCS canonicalization. In particular,
callers must not pass an ordinary JSON serialization for an inline artifact
whose digest is defined over JCS-canonicalized `data`.

The result statuses have deliberately narrow meanings:

| Status | Meaning |
| --- | --- |
| `match` | The supplied bytes match the declared digest. |
| `mismatch` | The digest is implemented and well-formed, but the bytes do not match. |
| `invalid_digest` | The declaration is malformed, or a known algorithm has an invalid output length. |
| `algorithm_not_implemented` | The declaration is syntactically valid, but the SDK does not implement its exact algorithm token. |

The SDK currently implements only the exact, case-sensitive `sha256` token
with 64 lowercase hexadecimal characters. This is an SDK capability boundary,
not a claim that other algorithms are forbidden or insecure. If the runtime
cannot execute a registered implementation, the function throws
`DigestAlgorithmUnavailableError` and preserves the underlying error as
`cause`.

`Buffer` values and `Uint8Array` subviews are accepted. Shared or detached
backing buffers are rejected because they cannot provide a stable byte view for
the check. Wrong JavaScript argument types and shared or detached byte views
throw `TypeError`.

A `match` result establishes only equality between caller-supplied bytes and a
declared digest. It does not establish who made the declaration, whether the
digest is authoritative, or whether the content is trustworthy.
