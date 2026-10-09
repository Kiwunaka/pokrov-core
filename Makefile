GO ?= go

.PHONY: test
test:
	pwsh ./scripts/test.ps1 -GoExecutable $(GO)
