GO ?= go

.PHONY: test
test:
	$(GO) test ./v2/config ./v2/hcore ./v2/hutils ./ray2sing/ray2sing
	cd engine/sing-box && $(GO) test -count=1 ./common/tls
	cd engine/sing-box && $(GO) test -count=1 -tags with_utls ./common/tls
