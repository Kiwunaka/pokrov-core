# Contributing

Keep changes small and tied to a reproducible issue.

1. Add or update the narrowest test that demonstrates the bug.
2. Change the owning layer only.
3. Run `scripts/test.ps1`.
4. Record manual platform checks separately; do not present them as automated passes.

Transport fixes that are useful outside POKROV should also be prepared as a focused upstream contribution. POKROV release work does not wait on that contribution unless the change depends on upstream review.
