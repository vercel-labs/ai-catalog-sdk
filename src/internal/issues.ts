import type * as z from 'zod';
import type { CatalogIssue } from '../types.js';

const MAX_ISSUES = 100;

export type Path = readonly (string | number)[];

export function issue(code: string, path: Path, message: string): CatalogIssue {
  return { code, path, message };
}

function stableZodIssue(raw: z.core.$ZodIssue, prefix: Path): CatalogIssue {
  const rawPath = raw.path.filter(
    (part): part is string | number =>
      typeof part === 'string' || typeof part === 'number',
  );
  const path = [...prefix, ...rawPath];

  switch (raw.code) {
    case 'invalid_type':
      return issue(
        'invalid_type',
        path,
        'The value is not the required JSON type.',
      );
    case 'invalid_format':
      return issue(
        'invalid_value',
        path,
        'The string does not use the required format.',
      );
    case 'invalid_union':
      return issue(
        'invalid_value',
        path,
        'The value does not match any allowed structure.',
      );
    case 'too_big':
    case 'too_small':
      return issue(
        'invalid_value',
        path,
        'The value is outside the allowed range.',
      );
    default:
      return issue(
        'invalid_value',
        path,
        'The value violates an AI Catalog structural rule.',
      );
  }
}

export class IssueCollector {
  readonly issues: CatalogIssue[] = [];
  cause: unknown;
  truncated = false;

  get stopped(): boolean {
    return this.truncated;
  }

  add(catalogIssue: CatalogIssue, cause?: unknown): void {
    if (this.truncated) return;
    if (this.cause === undefined && cause !== undefined) this.cause = cause;
    if (this.issues.length < MAX_ISSUES) {
      this.issues.push(catalogIssue);
      return;
    }
    this.truncated = true;
  }

  addZod(error: z.ZodError, prefix: Path): void {
    if (this.cause === undefined) this.cause = error;
    for (const rawIssue of error.issues) {
      this.add(stableZodIssue(rawIssue, prefix));
      if (this.stopped) break;
    }
  }

  finish<E extends Error>(
    ErrorClass: new (issues: readonly CatalogIssue[], cause?: unknown) => E,
  ): E | undefined {
    if (this.truncated) {
      this.issues.push(
        issue(
          'diagnostics_truncated',
          [],
          'Additional validation issues were omitted.',
        ),
      );
    }
    if (this.issues.length === 0) return undefined;
    return new ErrorClass(this.issues, this.cause);
  }
}
