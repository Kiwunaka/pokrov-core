# POKROV Core Repository Contract

This repository owns the POKROV client runtime core. It produces the Android, Windows, and future Apple runtime libraries consumed by `POKROV-app`. Server-side Xray and panel behavior are outside this repository.

## Start Every Task

1. Inspect `git status --short --branch` and the scoped diff before changing files.
2. Identify the affected layer: public ABI, platform adapter, core service, embedded engine, build tooling, or documentation.
3. Preserve unrelated work and existing release evidence.
4. Run the smallest checks that prove the changed behavior.

## Proportional Engineering

- Apply KISS, YAGNI, and the Pareto principle. Make the smallest maintainable change that satisfies the explicit acceptance criteria and current evidence; prefer existing patterns and code paths.
- Do not add speculative abstractions, dependencies, compatibility layers, fallbacks, configuration, cleanup, documentation, or future-proofing outside the assigned scope.
- Keep verification proportional. Add or update only the smallest focused tests needed to prove changed behavior or prevent a concrete observed regression. Do not add redundant unit/integration/E2E coverage, exhaustive edge-case matrices, broad regression suites, or unrelated test refactors unless the task, affected shared contract, or observed failure requires them.
- Keep security work proportional to the actual trust boundary and concrete threat model. Preserve mandatory safeguards and fix vulnerabilities introduced or exposed by the task, but do not add speculative hardening, new security frameworks, or unrelated defenses without evidence or an explicit requirement.
- Before expanding scope, identify the concrete acceptance criterion, failure, or risk that requires it. If none exists, omit the extra work. If expansion would materially change the solution, request owner direction first.
- These rules do not authorize skipping an explicit release gate or a focused regression test for changed runtime behavior.

## Architecture Rules

- Keep `platform/mobile` and `platform/desktop` as thin adapters.
- Put lifecycle and runtime behavior in `v2/`; keep embedded transport changes in `engine/sing-box`.
- Keep the desktop C ABI small, caller-owned, and backward compatible within a major release.
- Do not add server-side behavior or application UI to this repository.
- Import reference fixes one at a time with the source issue or commit recorded in the pull request. Do not bulk-merge another codebase.

## Runtime Security

- Never log raw profiles, full generated configurations, credentials, private keys, tokens, WARP registration data, or provider payloads.
- Runtime configuration files must remain owner-only where the platform supports it.
- Treat FFI allocation ownership, shutdown ordering, resolver behavior, and VPN lifecycle as security-sensitive contracts.
- Do not silently downgrade encrypted DNS or weaken TLS verification.

## Universal Safety

- Integrity and safety checks are authorized only for local POKROV repositories, POKROV-owned runtime surfaces, and isolated fixtures named by the task. Third-party systems, accounts, credentials, and data are out of scope.
- Never print, commit, move, copy into artifacts, or expose secrets, tokens, credentials, private keys, raw connection material, customer data, or unredacted provider payloads.
- Do not perform broad deletion, destructive Git operations, production mutation, deploy, external communication, or release publication unless the task explicitly authorizes it.
- Preserve audit evidence, rollback material, license notices, and generated provenance.
- Treat dirty files and other worktrees as concurrent work. Do not overwrite, revert, stage, or reformat changes outside the assigned scope.
- Keep cleanup targeted, reviewable, and reversible.

## Verification And Release

- Format changed Go files with `gofmt`.
- Run focused package tests first. Run `scripts/test.ps1` before a release commit.
- Rebuild only affected platform artifacts, then verify exported ABI, package names, architecture coverage, and hashes.
- Physical-device, signing, notarization, store, and RU-origin checks remain manual until executed.
- A release requires a clean tree, an exact version in `VERSION` and `config/release.json`, retained artifact hashes, and a matching annotated tag.
