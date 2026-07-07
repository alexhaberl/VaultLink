.PHONY: dev-setup sample-data test security-test fuzz lint build run

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
	@if command -v shellcheck >/dev/null; then shellcheck deploy/*.sh; else echo "shellcheck nicht installiert; Script-Prüfung übersprungen"; fi

fuzz:
	cargo fuzz run path_normalization -- -max_total_time=600
	cargo fuzz run byte_range -- -max_total_time=600
	cargo fuzz run filename -- -max_total_time=600

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

build:
	cargo build --release --locked

run: sample-data
	cargo run -- --config $(CONFIG)
