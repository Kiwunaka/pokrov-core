# Reference review

External core and transport projects are advisory inputs, not automatic dependencies.

For each candidate update:

1. Identify the exact issue and fixing commit.
2. Reproduce the failure against the current POKROV release when possible.
3. Import the smallest relevant change.
4. Run the affected package tests and platform backtest.
5. Record whether the change is POKROV-only or suitable for an upstream contribution.

Do not merge a reference branch wholesale into `main`. Release ownership and versioning remain under POKROV.
