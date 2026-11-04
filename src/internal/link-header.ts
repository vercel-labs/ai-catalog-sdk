/** Splits Link values without treating quoted or URI-reference commas as separators. */
function splitLinks(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  let inTarget = false;
  for (let index = 0; index < value.length; index++) {
    const character = value[index];
    if (escaped) {
      escaped = false;
    } else if (quoted && character === '\\') {
      escaped = true;
    } else if (!inTarget && character === '"') {
      quoted = !quoted;
    } else if (!quoted && character === '<') {
      inTarget = true;
    } else if (!quoted && character === '>') {
      inTarget = false;
    } else if (!quoted && !inTarget && character === ',') {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function splitParameters(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index++) {
    const character = value[index];
    if (escaped) {
      escaped = false;
    } else if (quoted && character === '\\') {
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
    } else if (!quoted && character === ';') {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function parameterValue(value: string): string | undefined {
  if (!value.startsWith('"')) {
    return /^[!#$%&'*+\-.^_`|~\da-z]+$/i.test(value) ? value : undefined;
  }
  let result = '';
  for (let index = 1; index < value.length; index++) {
    const character = value[index];
    if (character === '"') {
      return value.slice(index + 1).trim() === '' ? result : undefined;
    }
    if (character === '\\') {
      index++;
      if (index >= value.length) return undefined;
      result += value[index];
    } else {
      result += character;
    }
  }
  return undefined;
}

/**
 * Returns the first ai-catalog target, retaining it even when its URL is unsafe.
 * Anchored links have a different context and cannot advertise this website.
 */
export function firstCatalogLink(
  header: string | readonly string[] | undefined,
): string | undefined {
  if (header === undefined) return undefined;
  const lines = typeof header === 'string' ? [header] : header;
  for (const line of lines) {
    for (const rawLink of splitLinks(line)) {
      const link = rawLink.trim();
      if (!link.startsWith('<')) continue;
      const targetEnd = link.indexOf('>');
      if (targetEnd < 0) continue;
      const parameters = link.slice(targetEnd + 1).trim();
      if (parameters !== '' && !parameters.startsWith(';')) continue;
      let relation: string | undefined;
      let hasRelation = false;
      let anchored = false;
      for (const parameter of splitParameters(parameters)) {
        const equals = parameter.indexOf('=');
        const name = (equals < 0 ? parameter : parameter.slice(0, equals))
          .trim()
          .toLowerCase();
        if (name === 'anchor') anchored = true;
        if (name === 'rel' && !hasRelation) {
          hasRelation = true;
          relation = equals < 0 ? undefined : parameterValue(parameter.slice(equals + 1).trim());
        }
      }
      if (
        !anchored &&
        relation?.split(/\s+/).some((token) => token.toLowerCase() === 'ai-catalog')
      ) {
        return link.slice(1, targetEnd);
      }
    }
  }
  return undefined;
}
