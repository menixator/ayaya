# ayaya

## ayaya-collector:
1. create a postgres db
1. Set up a AYAYA_COLLECTOR and DATABASE_URL as seen in the .envrc.sample file

```shell
cargo run -p ayaya-collector
```

## ayaya agent:

1. run the collector as described above
1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)


```shell
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- <PATH TO MONITOR>
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.



## ayaya-backend
1. Run the collector at least once to run migrations.
1. `cargo-leptos`  install with:  `cargo install -f cargo-leptos --version 0.2.26`
1. `rustup target add wasm32-unknown-unknown` for wasm target
1. `cargo-leptos serve --project ayaya_backend`
1. The backend will be running at 0.0.0.0:3000
