.PHONY: dev-setup sample-data test security-test fuzz lint build run docker-setup-smoke

CONFIG ?= config/development.toml

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
	@if command -v shellcheck >/dev/null; then shellcheck deploy/*.sh tools/*.sh; else echo "shellcheck nicht installiert; Script-Prüfung übersprungen"; fi

fuzz:
	cargo +nightly-2026-07-01 fuzz run path_normalization -- -max_total_time=600
	cargo +nightly-2026-07-01 fuzz run byte_range -- -max_total_time=600
	cargo +nightly-2026-07-01 fuzz run filename -- -max_total_time=600

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

build:
	cargo build --release --locked

run: sample-data
	cargo run -- --config $(CONFIG)

docker-setup-smoke:
	@docker version >/dev/null 2>&1 || (echo "Docker fehlt oder WSL-Integration ist nicht aktiv" && exit 1)
	docker build -f deploy/docker/Dockerfile.setup-smoke -t vaultlink:setup-smoke .
	docker run --rm vaultlink:setup-smoke
