# Repository instructions

- Use pnpm and run `pnpm check` before handing off package changes.
- Before changing specification behavior, read `docs/spec-interpretation.md`. `src/spec-revision.ts` identifies the exact upstream snapshot this SDK interprets; keep the interpretation and affected fixtures aligned when updating it.
- Root parsers intentionally perform bounded, defensive validation; standalone Zod schemas retain native Zod behavior. See `README.md#what-gets-validated` for the validation boundaries.
- Preserve unknown JSON-valued properties for supported specification majors, while keeping authoring types closed.
- Before changing verification utilities, read `docs/verification.md`, especially the meaning of successful results and invocation snapshots. Parsing validates structure; successful cryptographic checks do not by themselves establish identity or trust.
- Regenerate schema artifacts with `pnpm generate:schema`; do not manually edit `schema/ai-catalog.schema.json` or `src/generated/ai-catalog-json-schema.ts`.
- Cover new output formats or runtime conditions with packed-consumer tests in `scripts/smoke-package.mjs`.
