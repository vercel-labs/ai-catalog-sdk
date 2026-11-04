import type { CatalogIssue, JsonValue } from '../types.js';
import { preflightJsonValue } from './json-value.js';

function isObject(value: unknown): value is Record<string, JsonValue> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function own(
  value: Record<string, JsonValue>,
  name: string,
): JsonValue | undefined {
  return Object.hasOwn(value, name) ? value[name] : undefined;
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
