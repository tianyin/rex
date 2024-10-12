{
  description = "Rust development shell using Nix Flakes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs"; # Use the NixOS package set
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShell = pkgs.mkShell {
          name = "rust-dev-shell";
          buildInputs = with pkgs ; [
            rustup # Rust version manager
            cargo # Cargo for Rust package management
            rust-analyzer # LSP for Rust development
            clippy # Linting tool for Rust
            rustfmt # Code formatting tool for Rust
            pkg-config # For linking C libraries with Rust
            openssl # Useful if you are working on a Rust project that links with OpenSSL
          ];

          shellHook = ''
            echo "Welcome to the Rust development shell!"
            rustup default stable  # Optionally set the default toolchain
          '';

          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.openssl ];
        };
      });
}
