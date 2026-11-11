# Third-party notices

## Runtime dependencies

**Zero.** This bundle has no `package.json`, no npm dependencies, and no vendored third-party code.
Every module imports only:

- Node.js built-in modules (`node:fs`, `node:path`, `node:os`, `node:child_process`, `node:url`,
  `node:crypto`, `node:http`, `node:https`, `node:perf_hooks`, `node:test`, `node:assert`, `node:events`),
- and its own siblings in this directory via `./name.mjs`.

`node --test` and `node verify-payments.mjs` therefore need no install step and no network access.

## Demo media provenance

The demonstration video and voice narration shown alongside this repository are **not** part of
this code bundle and carry their own provenance:

| asset | source | licence |
|---|---|---|
| live browser & terminal screen capture | Chromium (BSD-3-Clause) | rendered demonstration footage |
| voice synthesis | Microsoft Edge Neural TTS (edge-tts, $0.00) | free TTS narration (not distributed in bundle) |

Neither is redistributed here. No model weights, sample audio, or generated image is included in this
directory, so no upstream notice obligation attaches to these files.

## Licence of this bundle

MIT — see `LICENSE` for the full MIT licence text and copyright notice. The MIT text is unmodified.
