# Repository instructions

- Use pnpm; keep the exact root `packageManager` pin and lockfile synchronized.
- Keep authored code in `src/`, generated JavaScript and declarations in `dist/`, and the generated JSON Schema in `schema/`; do not edit generated artifacts manually.
- Treat `package.json` exports, wire types, parser diagnostics, schemas, engines, and files as the public compatibility contract.
- Keep root parsing defensive and bounded. Direct `/zod` schema use intentionally retains native Zod behavior.
- Preserve unknown JSON-valued properties for supported specification majors, while keeping authoring types closed.
- Keep `src/spec-revision.ts`, generated schema metadata, fixtures, and changelog entries aligned to one exact AI Catalog specification commit.
- Add output formats or runtime conditions only with a packed-consumer test for that condition.
- Run `pnpm check` before handing off changes that affect the package.
- This repository starts in private incubation. Do not make it public, claim an npm name, install the release workflow, or publish without an approved graduation gate.
- After graduation, publish only through the approved tokenless release workflow. Never add a long-lived npm publishing token.
