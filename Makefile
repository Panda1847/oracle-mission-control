PYTHON ?= python3
GO ?= go

.PHONY: test test-unit test-go verify run-demo ci package-deb

test:
	$(PYTHON) -m pytest -q

test-unit:
	$(PYTHON) -m pytest -q tests/unit

test-go:
	cd runtime-go && $(GO) test ./...

verify:
	bash scripts/verify_env.sh

run-demo:
	$(PYTHON) -m oracle --demo --web --web-port 5000

ci: test-go test

package-deb:
	bash scripts/build_deb.sh
