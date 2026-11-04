export const DIGEST_PATTERN = /^[A-Za-z0-9][A-Za-z0-9+._-]*:[0-9a-f]+$/;

/** Hexadecimal output lengths for the SDK's recognized digest algorithms. */
export const DIGEST_HEX_LENGTHS = {
  sha256: 64,
  sha384: 96,
  sha512: 128,
} as const;
