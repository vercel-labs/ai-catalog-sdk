# Contributing

## Development

Use a Node.js version supported by `engines` in [`package.json`](package.json) and the pnpm version declared by `packageManager` in that file.

```sh
pnpm install --frozen-lockfile
```

Run the checks before handing off package changes:

```sh
pnpm check
```

This runs linting, typechecking, tests, generated-schema checks, builds, and package validation. The package checks install a locally packed tarball in a temporary consumer and check runtime imports and TypeScript compatibility. They require package-registry access and do not publish the package.

Use `pnpm test` or `pnpm test:watch` for focused iteration.

## Changing the SDK

Before changing parsing or schema behavior, read [What gets validated](README.md#what-gets-validated) and [Specification snapshot interpretation](docs/spec-interpretation.md). Preserve the distinction between defensive SDK parsing and standalone schema validation. Authoring types describe known fields; parsing preserves unknown JSON-valued properties for supported specification majors.

The authoritative upstream revision is recorded in [`src/spec-revision.ts`](src/spec-revision.ts). When updating it, keep the interpretation document, changelog revision, and affected fixtures aligned with the new snapshot.

Before changing verification utilities, read [Verification utilities](docs/verification.md), including what successful results establish and how invocation snapshots affect those results. Preserve the distinction between structural validation, cryptographic checks, and application trust decisions.

The JSON Schema is generated from [`src/internal/schemas.ts`](src/internal/schemas.ts) and the specification metadata by [`scripts/generate-schema.mjs`](scripts/generate-schema.mjs). When changing those inputs or the generation template, regenerate the artifacts:

```sh
pnpm generate:schema
```

Include the generated changes in the same PR. Do not edit `schema/ai-catalog.schema.json` or `src/generated/ai-catalog-json-schema.ts` manually.

Cover new output formats or runtime conditions in the packed-consumer tests in [`scripts/smoke-package.mjs`](scripts/smoke-package.mjs), so those changes are exercised through the distributed package.

## Documentation

Every documentation edit must serve a concrete need of its intended reader. Include technical detail when it helps that reader perform a task, make a relevant decision, or interpret observable behavior. Accuracy and topical relevance alone do not justify inclusion. For unusual scenarios, establish a credible user workflow before treating them as documentation requirements.

Treat each document's audience, purpose, and depth as requirements. Update or remove existing explanations rather than accumulating caveats and sections. Code or test changes alone do not require additional prose, and existing excessive detail is not precedent.

| Surface | Intended reader | Purpose and depth |
| --- | --- | --- |
| `README.md` | Prospective and current SDK users | Introduce common workflows, API choices, and consequential boundaries; link to details. |
| `docs/verification.md` | Users applying verification utilities | Explain how to use the operations and interpret their results and limitations. |
| `docs/spec-interpretation.md` | Readers evaluating the SDK's interpretation of the pinned specification | Explain consequential ambiguities, differences, and interpretation choices. |
| Public TSDoc | API users working in an editor | Explain local API contracts and non-obvious semantics. |
| Implementation comments | Contributors changing code | Explain non-obvious decisions, their rationale, and their consequences beside the responsible code. |

When product behavior changes, correct affected high-level explanations so the human maintainer can assess the resulting behavior and tradeoffs without reading implementation code. Preserve useful public-interface examples and material guarantees or limitations. Keep developer-only mechanics beside the code that owns them.

Verify factual claims against their owning sources, including the pinned specification where applicable. Distinguish specification requirements from SDK choices. Review whether proposed explanations earn their place, then read revised passages in the context of the whole document for ambiguity, repetition, and misleading placement.

Use task-oriented headings, concrete examples, and precise language. Keep each prose paragraph on one source line, separate paragraphs with blank lines, and use compact Markdown tables with one space around cell contents and `---` separators.

## Pull requests

Prefer focused changes and logical, atomic commits. Explain the problem and resulting behavior, preserve lasting rationale in commit messages, and report the relevant verification performed. Investigation history and rejected alternatives can supplement the actionable rationale beside the code.
