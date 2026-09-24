# POKROV Core Repository Contract

This repository owns the POKROV client runtime core. It produces the Android, Windows and future Apple runtime libraries consumed by `POKROV-app`. Server-side behavior belongs to `C:/Users/kiwun/Documents/ai/POKROV-node`, not here. Current work follows the owner's execution plan `C:/Users/kiwun/Downloads/POKROV_EXECUTION_PLAN_2026-09-24.md`.

## How To Work

- Check `git status` and the scoped diff first. Other agents may work in the same repos; never overwrite, revert or reformat work outside your task.
- Make the smallest maintainable change; prefer existing patterns. No speculative abstractions, dependencies, compatibility layers or future-proofing.
- Test only the changed behavior: focused package tests first, `scripts/test.ps1` before a release commit. Repeat a check only after a change or a failure.
- Build only after code changes, and only the affected platform artifacts. Check the exported ABI when it changes.
- Do not create evidence folders, ledgers or decision diaries.

## Architecture Rules

- Keep `platform/mobile` and `platform/desktop` as thin adapters.
- Put lifecycle and runtime behavior in `v2/`; keep embedded transport changes in `engine/sing-box`.
- Keep the desktop C ABI small, caller-owned and backward compatible within a major release.
- Do not add server-side behavior or application UI to this repository.
- Import reference fixes one at a time with the source issue or commit recorded in the commit message. Do not bulk-merge another codebase.

## Runtime Security

- Never log raw profiles, full generated configurations, credentials, private keys, tokens, WARP registration data or provider payloads.
- Runtime configuration files stay owner-only where the platform supports it.
- Treat FFI allocation ownership, shutdown ordering, resolver behavior and VPN lifecycle as security-sensitive.
- Do not silently downgrade encrypted DNS or weaken TLS or REALITY verification.

## Git And GitHub

- GitHub is plain storage for code and history. Actions results, PR reviews, commit signatures and LFS are not gates, and nothing paid is used.
- Work on `main` or a short-lived branch; merge right after local checks and delete the branch. Never force-push `main`.
- Do not commit build outputs. Release libraries go to GitHub Releases.
- A release: version in `VERSION` and `config/release.json`, a tag, libraries attached to the GitHub Release.

## Safety

- Never print, commit or expose secrets, keys, tokens or raw connection material. Keep license notices.
- Work only on POKROV-owned repos, servers and devices. Third-party systems are out of scope.
- No destructive Git operations, deploys or release publication without explicit owner approval.
- Never claim a check, build or release that did not happen. State plainly what was not checked.
