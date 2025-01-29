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

      # Use unwrapped clang & lld to avoid warnings about multi-target usage
      rexPackages = with pkgs; [
        # Kernel builds
        autoconf
        bc
        binutils
        bison
        elfutils
        fakeroot
        flex
        gcc
        getopt
        gnumake
        libelf
        ncurses
        openssl
        pahole
        pkg-config
        xz
        zlib

        ninja
        rust-bindgen
        pahole
        strace
        zstd
        eza
        zlib

        # Clang kernel builds
        llvmPackages.clang
        llvmPackages.bintools

        # for llvm/Demangle/Demangle.h
        libllvm


        bear # generate compile commands
        rsync # for make headers_install
        gdb

        # bmc deps
        iproute2
        memcached

        # python3 scripts
        (pkgs.python3.withPackages
          (python-pkgs: (with python-pkgs;  [
            # select Python packages here
            tqdm
          ])))

        zoxide # in case host is using zoxide
        openssh # q-script ssh support
      ];

      fhs = pkgs.buildFHSEnv {
        name = "rex-env";
        targetPkgs = pkgs: rexPackages;
        runScript = "./scripts/start.sh";
        profile = ''
          export NIX_ENFORCE_NO_NATIVE=0
        '';
      };
    in
    {
      devShells."${system}" = {
        default = fhs.env;

        rex = pkgs.mkShell {
          packages = rexPackages;
          # Disable default hardening flags. These are very confusing when doing
          # development and they break builds of packages/systems that don't
          # expect these flags to be on. Automatically enables stuff like
          # FORTIFY_SOURCE, -Werror=format-security, -fPIE, etc. See:
          # - https://nixos.org/manual/nixpkgs/stable/#sec-hardening-in-nixpkgs
          # - https://nixos.wiki/wiki/C#Hardening_flags
          hardeningDisable = [ "all" ];


            # export LIBCLANG_PATH="${pkgs.llvmPackages_19.libclang.lib}/lib/libclang.so"
          shellHook = ''
            echo "loading rex env"
            source ./scripts/env.sh
            export NIX_ENFORCE_NO_NATIVE=0
          '';
        };
      };
    };

}
