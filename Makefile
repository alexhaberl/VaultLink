.PHONY: dev-setup sample-data test security-test fuzz fuzz-parallel fuzz-sequential lint build run policy-check docker-smoke-build docker-smoke docker-setup-smoke docker-api-smoke docker-upgrade-safety-test

CONFIG ?= config/development.toml
DOCKER_SMOKE_IMAGE ?= vaultlink:smoke
FUZZ_MAX_TOTAL_TIME ?= 600
FUZZ_JOBS ?= 4
FUZZ_LOG_DIR ?= /tmp/vaultlink-fuzz-logs
FUZZ_TARGETS := path_normalization byte_range filename zip_search_preview_paths upload_overwrite_policy upload_validation_policy api_request_policy file_mutation_policy multipart_guard

dev-setup: sample-data
	@command -v cargo >/dev/null || (echo "Rust fehlt: https://rustup.rs installieren" && exit 1)
	cargo fetch

sample-data:
	mkdir -p dev/mount/Dokumente dev/mount/Uploads dev/data
	printf '%s\n' 'VaultLink Testdatei' > dev/mount/Dokumente/beispiel.txt

test:
	cargo test --all-targets

security-test:
	cargo test path_security
	cargo test secure_fs
	cargo test range
	cargo test db::tests::migrates_unversioned_installation_without_losing_data
	cargo test proxy
	cargo test auth
	@if command -v shellcheck >/dev/null; then shellcheck deploy/*.sh deploy/docker/*.sh tools/*.sh; else echo "shellcheck nicht installiert; Script-Prüfung übersprungen"; fi
	sh tools/check-supply-chain-policy.sh

fuzz: fuzz-parallel

fuzz-parallel:
	@FUZZ_JOBS="$(FUZZ_JOBS)" FUZZ_MAX_TOTAL_TIME="$(FUZZ_MAX_TOTAL_TIME)" FUZZ_LOG_DIR="$(FUZZ_LOG_DIR)" \
		sh tools/run-fuzz-targets.sh $(FUZZ_TARGETS)

fuzz-sequential:
	@$(MAKE) fuzz-parallel FUZZ_JOBS=1

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

build:
	cargo build --release --locked

run: sample-data
	cargo run -- --config $(CONFIG)

policy-check:
	sh tools/check-supply-chain-policy.sh

docker-smoke-build:
	@docker version >/dev/null 2>&1 || (echo "Docker fehlt oder WSL-Integration ist nicht aktiv" && exit 1)
	docker build -f deploy/docker/Dockerfile.setup-smoke -t $(DOCKER_SMOKE_IMAGE) .

docker-smoke: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE)
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) bash deploy/docker/api-smoke.sh
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) bash deploy/docker/upgrade-safety-test.sh

docker-setup-smoke: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE)

docker-api-smoke: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) bash deploy/docker/api-smoke.sh

docker-upgrade-safety-test: docker-smoke-build
	docker run --rm --network none $(DOCKER_SMOKE_IMAGE) bash deploy/docker/upgrade-safety-test.sh
