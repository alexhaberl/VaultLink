.PHONY: dev-setup sample-data test login-timing-check security-test secret-check web-assets-check architecture-check performance-evidence-check refactoring-contracts-check fuzz-policy-check fuzz fuzz-parallel fuzz-sequential lint build run policy-check package-manifest-bootstrap package-manifest-check native-package verify-native-package docker-smoke-build docker-test docker-smoke docker-setup-smoke docker-api-smoke docker-load-fixture-smoke docker-soak-evidence-smoke docker-soak-remote-smoke docker-upgrade-safety-test docker-update-safety-test docker-real-package-update-smoke

CONFIG ?= config/development.toml
DOCKER_SMOKE_IMAGE ?= vaultlink:smoke
FUZZ_MAX_TOTAL_TIME ?= 600
FUZZ_JOBS ?= 4
FUZZ_LOG_DIR ?= /tmp/vaultlink-fuzz-logs
PYTHON ?= python3
PACKAGE_TARGET ?= debian13-amd64
PACKAGE_VERSION ?= $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
PACKAGE_BINARY ?= target/release/vaultlink
PACKAGE_SBOM ?= target/vaultlink.cdx.json
PACKAGE_OUTPUT ?= dist
REAL_PACKAGE_TARGET ?= $(PACKAGE_TARGET)
REAL_PACKAGE_OLD_VERSION ?= $(PACKAGE_VERSION)
REAL_PACKAGE_NEW_VERSION ?= 0.7.1
REAL_PACKAGE_BUILDER_IMAGE ?= $(shell $(PYTHON) tools/package-targets.py get "$(REAL_PACKAGE_TARGET)" builder_image 2>/dev/null)
REAL_PACKAGE_OLD_PACKAGE ?= $(PACKAGE_OUTPUT)/$(shell $(PYTHON) tools/package-targets.py asset "$(REAL_PACKAGE_TARGET)" "$(REAL_PACKAGE_OLD_VERSION)" --allow-unprovisioned 2>/dev/null)
REAL_PACKAGE_NEW_PACKAGE ?= $(PACKAGE_OUTPUT)/$(shell $(PYTHON) tools/package-targets.py asset "$(REAL_PACKAGE_TARGET)" "$(REAL_PACKAGE_NEW_VERSION)" --allow-unprovisioned 2>/dev/null)
FUZZ_TARGETS = $(shell $(PYTHON) tools/fuzz-corpus.py targets)

dev-setup: sample-data
	@command -v cargo >/dev/null || (echo "Rust is missing; install it from https://rustup.rs" && exit 1)
	cargo fetch

sample-data:
	mkdir -p dev/mount/Dokumente dev/mount/Uploads dev/data
	printf '%s\n' 'VaultLink test file' > dev/mount/Dokumente/beispiel.txt

test:
	cargo test --all-targets

login-timing-check:
	cargo test --release --locked services::auth::tests::known_and_unknown_admin_login_timing_is_reported -- --ignored --nocapture

security-test:
	cargo test path_security
	cargo test secure_fs
	cargo test range
	@set -eu; \
		fresh_schema_test='db::tests::fresh_database_is_exactly_schema_eight_without_plaintext_secret_columns'; \
		listed_tests=$$(mktemp); \
		trap 'rm -f "$$listed_tests"' EXIT HUP INT TERM; \
		cargo test -- --list >"$$listed_tests"; \
		match_count=$$(grep -F -x -c "$$fresh_schema_test: test" "$$listed_tests" || true); \
		test "$$match_count" -eq 1 || { \
			echo "security-test requires exactly one $$fresh_schema_test test, found $$match_count" >&2; \
			exit 1; \
		}; \
		cargo test "$$fresh_schema_test" -- --exact
	cargo test proxy
	cargo test auth
	@if command -v shellcheck >/dev/null; then shellcheck deploy/*.sh deploy/docker/*.sh packaging/*.sh tools/*.sh; else echo "shellcheck is not installed; skipping script checks"; fi
	sh tools/check-supply-chain-policy.sh

secret-check:
	sh tools/check-secrets.sh

web-assets-check:
	sh tools/check-web-assets.sh

architecture-check:
	$(PYTHON) tools/test-architecture.py
	$(PYTHON) tools/check-architecture.py --root .

performance-evidence-check:
	$(PYTHON) tools/test-performance-evidence.py

refactoring-contracts-check:
	$(PYTHON) tools/test-refactoring-contracts.py
	$(PYTHON) tools/check-refactoring-contracts.py --root .

fuzz: fuzz-parallel

fuzz-policy-check:
	$(PYTHON) tools/test-fuzz-corpus.py
	$(PYTHON) tools/test-fuzz-policy.py
	$(PYTHON) tools/generate-fuzz-seeds.py --check
	$(PYTHON) tools/check-fuzz-policy.py

fuzz-parallel:
	@PYTHON="$(PYTHON)" FUZZ_JOBS="$(FUZZ_JOBS)" FUZZ_MAX_TOTAL_TIME="$(FUZZ_MAX_TOTAL_TIME)" FUZZ_LOG_DIR="$(FUZZ_LOG_DIR)" \
		sh tools/run-fuzz-targets.sh $(FUZZ_TARGETS)

fuzz-sequential:
	@$(MAKE) fuzz-parallel FUZZ_JOBS=1

lint:
	sh tools/check-web-assets.sh
	$(MAKE) architecture-check performance-evidence-check refactoring-contracts-check fuzz-policy-check
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

build:
	cargo build --release --locked

run: sample-data
	cargo run -- --config $(CONFIG)

policy-check:
	sh tools/check-supply-chain-policy.sh

# Bootstrap validation intentionally accepts image/snapshot placeholders so the
# protected refresh workflows can be merged. Release work always uses the
# strict target, which rejects every unprovisioned manifest or QEMU-runner
# input and validates the complete image-lock set.
package-manifest-bootstrap:
	$(PYTHON) tools/package-targets.py validate --allow-unprovisioned

package-manifest-check:
	$(PYTHON) tools/package-targets.py validate

native-package:
	sh tools/build-native-package.sh "$(PACKAGE_TARGET)" "$(PACKAGE_VERSION)" \
		"$(PACKAGE_BINARY)" "$(PACKAGE_SBOM)" "$(PACKAGE_OUTPUT)"

verify-native-package:
	sh tools/verify-native-package.sh "$(PACKAGE_TARGET)" "$(PACKAGE_VERSION)" \
		"$(PACKAGE_OUTPUT)/$$($(PYTHON) tools/package-targets.py asset "$(PACKAGE_TARGET)" "$(PACKAGE_VERSION)")" \
		"$(PACKAGE_BINARY)" "$(PACKAGE_SBOM)"

docker-smoke-build:
	@docker version >/dev/null 2>&1 || (echo "Docker is missing or WSL integration is not active" && exit 1)
	docker build -f deploy/docker/Dockerfile.setup-smoke -t $(DOCKER_SMOKE_IMAGE) .

docker-test: docker-smoke-build
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) cargo test --locked --all-targets

docker-smoke: docker-smoke-build
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) cargo test --locked --all-targets
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE)
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) bash deploy/docker/api-smoke.sh
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) sh deploy/docker/load-fixture-smoke.sh
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-evidence-smoke.sh
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-remote-smoke.sh
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) bash deploy/docker/upgrade-safety-test.sh
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) sh deploy/docker/update-safety-test.sh

docker-setup-smoke: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE)

docker-api-smoke: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) bash deploy/docker/api-smoke.sh

docker-load-fixture-smoke: docker-smoke-build
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) sh deploy/docker/load-fixture-smoke.sh

docker-soak-evidence-smoke: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-evidence-smoke.sh

docker-soak-remote-smoke: docker-smoke-build
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) sh deploy/docker/soak-remote-smoke.sh

docker-upgrade-safety-test: docker-smoke-build
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) bash deploy/docker/upgrade-safety-test.sh

docker-update-safety-test: docker-smoke-build
	docker run --rm --network none --user root $(DOCKER_SMOKE_IMAGE) sh deploy/docker/update-safety-test.sh

# This intentionally consumes two already-built, native packages. CI builds
# both versions from the same commit on the target's matching architecture;
# local callers may point these variables at equivalent disposable fixtures.
docker-real-package-update-smoke:
	@docker version >/dev/null 2>&1 || (echo "Docker is missing or WSL integration is not active" && exit 1)
	@test -n "$(REAL_PACKAGE_BUILDER_IMAGE)" && test "$(REAL_PACKAGE_BUILDER_IMAGE)" != UNPROVISIONED \
		|| (echo "REAL_PACKAGE_BUILDER_IMAGE must be a provisioned digest-pinned image" >&2; exit 1)
	@test -s "$(REAL_PACKAGE_OLD_PACKAGE)" \
		|| (echo "REAL_PACKAGE_OLD_PACKAGE is missing" >&2; exit 1)
	@test -s "$(REAL_PACKAGE_NEW_PACKAGE)" \
		|| (echo "REAL_PACKAGE_NEW_PACKAGE is missing" >&2; exit 1)
	@docker run --rm --network none --user root \
		--volume "$(CURDIR):/work:ro" --workdir /work \
		"$(REAL_PACKAGE_BUILDER_IMAGE)" \
		sh tools/real-package-update-smoke.sh \
			"$(REAL_PACKAGE_TARGET)" "$(REAL_PACKAGE_OLD_VERSION)" \
			"/work/$(REAL_PACKAGE_OLD_PACKAGE)" "$(REAL_PACKAGE_NEW_VERSION)" \
			"/work/$(REAL_PACKAGE_NEW_PACKAGE)"
