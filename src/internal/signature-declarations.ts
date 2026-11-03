import type { CatalogIssue, JsonValue } from '../types.js';
import { preflightJsonValue } from './json-value.js';
import { isDidWebDomain } from './did-web-domain.js';
import { absoluteUriSchema } from './schemas.js';

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const registeredHeaderParameters = new Set([
  'alg',
  'jku',
  'jwk',
  'kid',
  'x5u',
  'x5c',
  'x5t',
  'x5t#S256',
  'typ',
  'cty',
  'crit',
]);
const fragmentPattern = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+$/;

function issue(
  path: readonly (string | number)[],
  message: string,
): CatalogIssue {
  return { code: 'invalid_value', path, message };
}

function isObject(value: unknown): value is Record<string, JsonValue> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function own(
  value: Record<string, JsonValue>,
  name: string,
): JsonValue | undefined {
  return Object.hasOwn(value, name) ? value[name] : undefined;
}

function decodeBase64Url(segment: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(segment) || segment.length % 4 === 1)
    return undefined;
  let binary: string;
  try {
    binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return undefined;
  }
  const canonical = btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  if (canonical !== segment) return undefined;
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function inspectJws(value: JsonValue | undefined):
  | {
      header: Record<string, JsonValue>;
      signature: Uint8Array;
    }
  | undefined {
  if (typeof value !== 'string') return undefined;
  const parts = value.split('.');
  if (parts.length !== 3 || parts[1] !== '') return undefined;
  const protectedBytes = decodeBase64Url(parts[0] ?? '');
  const signature = decodeBase64Url(parts[2] ?? '');
  if (protectedBytes === undefined || signature === undefined) return undefined;
  let header: unknown;
  try {
    header = JSON.parse(utf8Decoder.decode(protectedBytes));
  } catch {
    return undefined;
  }
  if (!isObject(header)) return undefined;
  const inputIssue = preflightJsonValue(header, {
    allowOwnProtoMember: true,
    isDisallowedObject: undefined,
    requireIJsonStrings: false,
  });
  return inputIssue === undefined ? { header, signature } : undefined;
}

function isRootDidWeb(signer: string): boolean {
  if (!signer.startsWith('did:web:')) return false;
  return isDidWebDomain(signer.slice('did:web:'.length));
}

/** Check the captured object's exact signed payload, without producing bytes. */
export function validateSignedPayload(
  value: Record<string, JsonValue>,
): CatalogIssue | undefined {
  const signature = own(value, 'signature');
  if (!isObject(signature)) return undefined;
  const payload: Record<string, JsonValue> = Object.create(null);
  for (const name of Object.keys(value)) {
    if (name === 'additionalSignatures') continue;
    if (name === 'signature') {
      const metadata: Record<string, JsonValue> = Object.create(null);
      for (const key of Object.keys(signature))
        if (key !== 'jws') metadata[key] = signature[key] as JsonValue;
      payload.signature = metadata;
    } else payload[name] = value[name] as JsonValue;
  }
  return preflightJsonValue(payload, {
    allowOwnProtoMember: true,
    isDisallowedObject: undefined,
    requireIJsonStrings: true,
  });
}

/** Validate declarations of a present signature; does not authenticate its key. */
export function validateSignatureDeclarations(
  value: Record<string, JsonValue>,
  kind: 'catalog' | 'manifest',
): CatalogIssue[] {
  const metadata = own(value, 'signature');
  if (metadata === undefined) return [];
  if (!isObject(metadata))
    return [issue(['signature'], 'Signature metadata must be an object.')];
  const issues: CatalogIssue[] = [];
  const profile = own(metadata, 'profile');
  if (profile !== 'did-web-v1' && !absoluteUriSchema.safeParse(profile).success)
    issues.push(
      issue(
        ['signature', 'profile'],
        'An independently defined profile must use an absolute URI identifier.',
      ),
    );
  const jws = inspectJws(own(metadata, 'jws'));
  if (jws === undefined) {
    issues.push(
      issue(
        ['signature', 'jws'],
        'The signature must use canonical detached compact JWS.',
      ),
    );
  } else {
    const { header } = jws;
    const algorithm = own(header, 'alg');
    const headerIssue = (message: string): void => {
      issues.push(issue(['signature', 'jws'], message));
    };
    if (
      typeof algorithm !== 'string' ||
      algorithm.length === 0 ||
      algorithm === 'none'
    )
      headerIssue(
        'The protected alg must name a signature algorithm other than none.',
      );
    if (
      own(header, 'typ') !==
      (kind === 'catalog' ? 'ai-catalog+jws' : 'ai-catalog-trust-manifest+jws')
    )
      headerIssue(
        'The protected typ must identify the containing object kind.',
      );
    if (Object.hasOwn(header, 'b64'))
      headerIssue('AI Catalog signatures forbid the protected b64 parameter.');
    if (Object.hasOwn(header, 'crit')) {
      const critical = own(header, 'crit');
      if (
        !Array.isArray(critical) ||
        critical.length === 0 ||
        critical.some(
          (name) => typeof name !== 'string' || name.length === 0,
        ) ||
        new Set(critical).size !== critical.length ||
        critical.some(
          (name) =>
            typeof name !== 'string' ||
            !Object.hasOwn(header, name) ||
            registeredHeaderParameters.has(name),
        )
      )
        headerIssue(
          'The protected crit must name unique, present extension parameters.',
        );
    }

    if (own(metadata, 'profile') === 'did-web-v1') {
      const signer = own(metadata, 'signer');
      if (typeof signer !== 'string' || !isRootDidWeb(signer))
        issues.push(
          issue(
            ['signature', 'signer'],
            'The did-web-v1 signer must be a root did:web DID with a lowercase ASCII domain.',
          ),
        );
      if (algorithm !== 'ES256')
        headerIssue('The did-web-v1 profile requires ES256.');
      const kid = own(header, 'kid');
      if (
        typeof signer !== 'string' ||
        typeof kid !== 'string' ||
        !kid.startsWith(`${signer}#`) ||
        !fragmentPattern.test(kid.slice(signer.length + 1))
      )
        headerIssue(
          'The protected kid must be the exact signer DID followed by a nonempty fragment.',
        );
      if (
        ['jku', 'jwk', 'x5u', 'x5c'].some((name) => Object.hasOwn(header, name))
      )
        headerIssue(
          'The did-web-v1 profile forbids protected key-source headers.',
        );
      if (algorithm === 'ES256' && jws.signature.length !== 64)
        headerIssue('An ES256 signature must contain 64 signature bytes.');
    }
  }
  const payloadIssue = validateSignedPayload(value);
  if (payloadIssue !== undefined) issues.push(payloadIssue);
  return issues;
}
