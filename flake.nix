{
  description = "A flake for the REX project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # overlays = overlays;
      };

      wrapCC = cc: pkgs.wrapCCWith {
        inherit cc;
        extraBuildCommands = ''
          # Remove the line that contains "-nostdlibinc"
          sed -i 's|-nostdlibinc||g' "$out/nix-support/cc-cflags"
          echo " -resource-dir=${pkgs.llvmPackages.clang}/resource-root" >> "$out/nix-support/cc-cflags"
        '';
      };

      wrappedClang = wrapCC pkgs.llvmPackages.clang.cc;
      lib = nixpkgs.lib;

      # Use unwrapped clang & lld to avoid warnings about multi-target usage
      rexPackages = with pkgs; [
        # Kernel builds
        autoconf
        bc
        binutils
        bison
        cmake
        diffutils
        elfutils.dev
        fakeroot
        flex
        gcc
        glibc.dev
        getopt
        gnumake
        libelf
        ncurses
        openssl.dev
        pahole
        pkg-config
        xz.dev
        zlib
        zlib.dev

        ninja
        rust-bindgen
        pahole
        strace
        zstd
        eza
        linuxKernel.packages.linux_latest_libre.perf

        # Clang kernel builds
        # llvmPackages.clang
        # llvmPackages.clang
        wrappedClang
        # llvmPackages.libcxxStdenv
        lld
        mold
        # llvmPackages.bintools

        qemu
        busybox
        perf-tools

        # for llvm/Demangle/Demangle.h
        libllvm
        libllvm.dev
        libgcc
        libclang.lib
        libclang.dev


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

      # (pkgs.buildFHSEnv.override { stdenv = pkgs.llvmPackages.stdenv; })
      fhs = (pkgs.buildFHSEnv.override { stdenv = pkgs.llvmPackages.stdenv; })
        {
          name = "rex-env";
          targetPkgs = pkgs: rexPackages;
          runScript = "./scripts/start.sh";

          # NIX_CFLAGS_COMPILE = lib.strings.makeLibraryPath [ ] + " -isystem ${pkgs.libclang.lib}/lib/clang/19/include";
          # If you want clang in /usr/bin/clang etc. inside the chroot:
          # export LD_LIBRARY_PATH=${pkgs.libgcc.lib}/lib:$LD_LIBRARY_PATH
          # export LIBCLANG_PATH="${pkgs.libclang.lib}/lib/libclang.so"
          extraShellInit = ''
            # Symlink the wrapped clang binaries into /usr/bin
          '';

            # export PATH=${wrappedClang}/bin:"$PATH"
          profile = ''
            export LD_LIBRARY_PATH="${pkgs.libclang.lib}/lib/clang/19/include:$LD_LIBRARY_PATH"
            export LIBCLANG_PATH="${pkgs.libclang.lib}/lib/libclang.so"
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
