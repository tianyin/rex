{
  description = "A flake for the REX project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      # overlays = [
      #   (self: super: {
      #     bindgen = super.bindgen.overrideAttrs (oldAttrs: {
      #       src = super.fetchCrate {
      #         pname = "bindgen-cli";
      #         version = "0.68.1";
      #         sha256 = "sha256-5fwJq1WsL3IEcVUjsyqKdQU8VufbbPk6TglwJg3C1Gw=";
      #       };
      #     });
      #   })
      # ];

      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # overlays = overlays;
      };
    in
    {
      devShells."${system}".default =

        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        pkgs.mkShell {

          packages = with pkgs; [
            gcc
            diffutils
            xz.dev
            llvm
            clang
            zlib.dev
            openssl.dev
            flex
            bison
            busybox
            qemu
            mold
            pkg-config
            elfutils.dev
            libelf
            ncurses.dev
            rust-bindgen

            python3

          ];

          shellHook = ''
            export PS1="\u@\h \W\$ "
            alias ll='ls -la'
            source ./env.sh
          '';
        };
    };
}

