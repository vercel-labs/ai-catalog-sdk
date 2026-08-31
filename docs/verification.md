# Verification utilities

Verification utilities are available from the `ai-catalog-sdk/verification`
subpath. They are separate from parsing so applications can distinguish
structural validation from checks performed against external content.

## Canonicalize a logical JSON value

`canonicalizeJsonValueToBytes(value)` encodes an already-materialized logical
JSON value as fresh RFC 8785 JSON Canonicalization Scheme (JCS) UTF-8 bytes:

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

The function sorts object property names by UTF-16 code units, recursively,
while preserving array order and Unicode normalization form. It uses the JCS
ECMAScript number representation; for example, the JavaScript value `-0`
canonicalizes as `0`.

The input is a value, not source text. Passing `'{"x":1}'` canonicalizes a JSON
string value; it does not parse an object. By the time a normal JSON parser has
produced a value, duplicate member names, original number spelling and
precision, invalid source UTF-8, and a source spelling of negative zero can no
longer be recovered. Callers that need to authenticate those source-level
properties need a separate I-JSON-aware parsing boundary.

Programmatic input must consist of plain JSON objects, arrays, and JSON
primitives. The function rejects non-finite numbers, lone Unicode surrogates,
noncharacters, cycles, sparse or decorated arrays, accessors, proxies, exotic
objects, and other non-JSON values with `TypeError`. Inputs beyond the SDK's
fixed node or nesting-depth limits throw `RangeError`.

Canonicalization does not remove or reinterpret any member. In particular,
this function does not remove a `signature` member. Use
`createTrustManifestSignaturePayload()` for the AI Catalog Trust Manifest
rule described below.

## Create a Trust Manifest signature payload

`createTrustManifestSignaturePayload(manifest)` returns the exact RFC 8785
UTF-8 payload covered by a Trust Manifest's detached JWS:

```ts
import { createTrustManifestSignaturePayload } from 'ai-catalog-sdk/verification';

const payload = createTrustManifestSignaturePayload(trustManifest);
```

The function omits exactly an own, top-level member whose name is the
case-sensitive string `signature`. It preserves every other member, including
unknown future fields, extensions, a differently cased top-level name such as
`Signature`, and nested fields named `signature`. It does not mutate the input,
and signed and otherwise-identical unsigned manifests produce the same bytes.

The input is an already-materialized Trust Manifest value. This function does
not parse or structurally validate it, so validate untrusted catalog input at
the appropriate boundary first. It cannot recover source-level information
already lost during parsing, such as duplicate member names or original number
spellings. The same programmatic I-JSON restrictions and fixed resource limits
as `canonicalizeJsonValueToBytes()` apply, producing `TypeError` or `RangeError`
respectively. Those restrictions apply to the entire input, including the
omitted `signature` member. Accessors and proxies are rejected without invoking
them; non-enumerable and non-JSON `signature` values are rejected rather than
silently ignored.

The result is only the detached JWS payload. It is not base64url-encoded and is
not the complete JWS signing input. The function does not create or verify a
JWS, select or evaluate keys, algorithms, or key identifiers, check a subject
digest, enforce timestamps, resolve an identity, or establish trust.

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
