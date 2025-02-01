{
  description = "";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixpkgs-stable.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      pre-commit-hooks,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # stable
        toolchainFromFile = (pkgs.rust-bin.fromRustupToolchainFile "${self}/rust-toolchain.toml");
        # nightly 
        nightlyToolchain = pkgs.rust-bin.selectLatestNightlyWith (
          toolchain: toolchain.default.override { extensions = [ "rust-src" ]; }
        );

        toolchain = toolchainFromFile.override {
          extensions = [
            "rust-src"
            "rustc"
            "cargo"
            "clippy"
            "rustfmt"
            "rust-analyzer"
          ];
          targets = [ "x86_64-unknown-linux-gnu" "wasm32-unknown-unknown" ];
        };
      in
      with pkgs;
      {
        checks.pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            convco.enable = true;
            rustfmt.enable = true;
            rustfmt.package = toolchain;
            rustfmt.packageOverrides.cargo = toolchain;
            rustfmt.packageOverrides.rustfmt = toolchain;
          };
        };

        devShells.default = mkShell {
          name = "ayaya";
          buildInputs = [
            # aya's ebpf component requires nightly to compile. but since rust
            # does not have a stable ABI, having both nightly and stable is not
            # a proper usecase for cargo itself - rustup is the one that sort
            # of caters to this with +nightly. 

            # The aya-based program that loads the ebpf program will call cargo +nightly and 
            # embed the program within the binary itself.

            # This script will cater to that with some path precedence abuse
            # and finally ditch rustup.
            (pkgs.writeShellScriptBin "cargo" ''
              CURRENT_PATH=$(dirname "$0")

              if [ "$1" == "+nightly" ]; then
                shift
                PATH=${nightlyToolchain}/bin:$PATH
                ${nightlyToolchain}/bin/cargo "$@"
              else
                PATH=$CURRENT_PATH:${toolchain}/bin:$PATH
                ${toolchain}/bin/cargo "$@"
              fi
            '')

            pkg-config
            openssl
            gcc
            cmake
            #toolchain
            bpf-linker
            bpftools
            cargo-generate
            libclang
            # aya-tool missing
            sqlx-cli
            (pkgs.callPackage ./nix/cargo-leptos.nix { })
            protobuf
            tailwindcss
            rustup
          ];
          LIBCLANG_PATH = "${pkgs.llvmPackages_16.libclang.lib}/lib";
          #shellHook= self.checks.${system}.pre-commit-check.shellHook;

        };
      }
    );
}
