const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayName = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const typedArrayBuffer = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  'buffer',
)?.get;
const arrayBufferLength = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  'byteLength',
)?.get;

export function isUint8Array(value: unknown): value is Uint8Array {
  return typedArrayName?.call(value) === 'Uint8Array';
}

export function assertStableBytes(bytes: unknown): asserts bytes is Uint8Array {
  if (!isUint8Array(bytes)) throw new TypeError('bytes must be a Uint8Array.');
  const buffer = typedArrayBuffer?.call(bytes);
  try {
    arrayBufferLength?.call(buffer);
  } catch {
    throw new TypeError('bytes must not be backed by a SharedArrayBuffer.');
  }
  try {
    Uint8Array.prototype.values.call(bytes);
  } catch {
    throw new TypeError('bytes must not have a detached ArrayBuffer.');
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1)
    binary += String.fromCharCode(bytes[index] as number);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeBase64Url(value: string): Uint8Array {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1)
    bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function hex(bytes: Uint8Array): string {
  let result = '';
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0');
  return result;
}
