{
  description = "Rust project";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "nixpkgs/nixos-unstable";
    nitro-util = {
      url = "github:monzo/aws-nitro-util/7d755578b0b0b9850c0d7c4738a6c8daf3ff55c0";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, nitro-util }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        nitro = nitro-util.lib.${system};

        # Development environment setup
        commonInputs = [
          rust
          pkgs.rust-analyzer
          pkgs.pkg-config
          pkgs.openssl
          pkgs.zlib
          pkgs.gcc
          pkgs.clang
          pkgs.jq
          pkgs.just
          pkgs.python3
          (pkgs.python3.withPackages (ps: with ps; [
            cryptography
          ]))
        ];
        linuxOnlyInputs = [
          pkgs.podman
          pkgs.conmon
          pkgs.slirp4netns
          pkgs.fuse-overlayfs
        ];
        darwinOnlyInputs = [
          pkgs.libiconv
          pkgs.darwin.apple_sdk.frameworks.Security
          pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
        ];
        inputs = commonInputs
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux linuxOnlyInputs
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin darwinOnlyInputs;

        setupEnvScript = pkgs.writeShellScript "setup-env" ''
          if [ ! -f .env ]; then
            cp .env.sample .env

            # Get a new ENCLAVE_SECRET_MOCK value using openssl
            export enclaveSecret=$(openssl rand -hex 32)
            sed -i "s|ENCLAVE_SECRET_MOCK=|ENCLAVE_SECRET_MOCK=$enclaveSecret|g" .env

            # Get a new JWT_SECRET value using openssl
            export jwtSecret=$(openssl rand -base64 32)
            sed -i "s|JWT_SECRET=|JWT_SECRET=$jwtSecret|g" .env
          fi
        '';

        # Function to create rootfs with specific APP_MODE
        mkRootfs = appMode: pkgs.buildEnv {
          name = "opensecret-rootfs-${appMode}";
          paths = [
            opensecret
            (pkgs.writeScriptBin "entrypoint" ''
              #!${pkgs.bash}/bin/bash

              # Set up busybox commands and other tools
              export PATH="/bin:${pkgs.busybox}/bin:${pkgs.python3}/bin:${pkgs.jq}/bin:${pkgs.socat}/bin:${nitro-bins}/bin:$PATH"

              # Create symlinks for busybox commands
              mkdir -p /bin
              ln -sf ${pkgs.busybox}/bin/busybox /bin/date
              ln -sf ${pkgs.busybox}/bin/busybox /bin/ip
              ln -sf ${pkgs.python3}/bin/python3 /bin/python3
              ln -sf ${pkgs.jq}/bin/jq /bin/jq
              ln -sf ${pkgs.socat}/bin/socat /bin/socat
              ln -sf ${pkgs.curl}/bin/curl /bin/curl
              
              # Set up CA certificates
              mkdir -p /etc/ssl/certs
              ln -sf ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt /etc/ssl/certs/ca-bundle.crt
              export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
              export AWS_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt
              
              # Copy required libraries and tools
              mkdir -p /lib
              export LD_LIBRARY_PATH="/lib:$LD_LIBRARY_PATH"
              install -m 755 ${nitro-bins}/lib/libnsm.so /lib/

              install -m 755 ${nitro-bins}/bin/kmstool_enclave_cli /bin/

              # Copy required C libraries
              cp -P ${pkgs.glibc}/lib/ld-linux*.so* /lib/
              cp -P ${pkgs.glibc}/lib/libc.so* /lib/
              cp -P ${pkgs.glibc}/lib/libdl.so* /lib/
              cp -P ${pkgs.glibc}/lib/libpthread.so* /lib/
              cp -P ${pkgs.glibc}/lib/librt.so* /lib/
              cp -P ${pkgs.glibc}/lib/libm.so* /lib/
              
              # Set up Python environment
              export PYTHONPATH="$(find ${pkgs.python3}/lib -name site-packages):$PYTHONPATH"

              # Copy opensecret to its location
              mkdir -p /app
              install -m 755 ${opensecret}/bin/opensecret /app/

              ${builtins.readFile ./entrypoint.sh}
            '')
            (pkgs.writeTextFile {
              name = "app-mode";
              text = builtins.trace "Creating APP_MODE file with value: ${appMode}" appMode;
              destination = "/app/APP_MODE";
            })
            (pkgs.writeTextFile {
              name = "traffic_forwarder";
              text = builtins.readFile ./nitro-toolkit/traffic_forwarder.py;
              destination = "/app/traffic_forwarder.py";
            })
            (pkgs.writeTextFile {
              name = "vsock_helper";
              text = builtins.readFile ./nitro-toolkit/vsock_helper.py;
              destination = "/app/vsock_helper.py";
            })
            pkgs.bash
            pkgs.busybox
            pkgs.openssl
            pkgs.socat
            pkgs.python3
            pkgs.jq
            pkgs.iproute2
            pkgs.coreutils
            pkgs.cacert
            pkgs.curl
            nitro-bins
          ];
          pathsToLink = [ "/bin" "/lib" "/app" "/usr/bin" "/usr/sbin" "/sbin" ];
        };

        # Function to create EIF with specific APP_MODE
        mkEif = appMode: nitro.buildEif {
          name = "opensecret-eif-${appMode}";
          kernel = nitro.blobs.${arch}.kernel;
          kernelConfig = nitro.blobs.${arch}.kernelConfig;
          nsmKo = nitro.blobs.${arch}.nsmKo;
          copyToRoot = mkRootfs appMode;
          entrypoint = "/bin/entrypoint";
        };

        # Build the main Rust package
        opensecret = pkgs.rustPlatform.buildRustPackage {
          pname = "opensecret";
          version = "0.1.0";
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let 
                baseName = baseNameOf path;
                parts = pkgs.lib.splitString "/" path;
              in 
                # Explicitly exclude .env files
                (baseName != ".env" && baseName != ".env.sample") &&
                (
                  (builtins.elem "src" parts) ||
                  (type == "regular" && (
                    baseName == "Cargo.toml" ||
                    baseName == "Cargo.lock" ||
                    baseName == "rust-toolchain.toml"
                  ))
                );
          };
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.rust-analyzer
            pkgs.gcc
            pkgs.clang
          ];
          buildInputs = [
            pkgs.openssl
            pkgs.zlib
          ];
        };

        # Use pre-built NSM library and KMS tools from nitro-bins directory
        nitro-bins = pkgs.stdenv.mkDerivation {
          name = "nitro-bins";
          version = "1.0";
          src = ./nitro-bins;
          dontUnpack = true;
          installPhase = ''
            mkdir -p $out/{lib,bin}
            # Use install to copy files and set permissions
            install -m 755 $src/libnsm.so $out/lib/
            install -m 755 $src/kmstool_enclave_cli $out/bin/
          '';
        };

        arch = pkgs.stdenv.hostPlatform.uname.processor;
      in
      {
        packages = {
          default = opensecret;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          eif-dev = mkEif "dev";
          eif-prod = mkEif "prod";
          eif-preview = mkEif "preview";
        };

        devShell = pkgs.mkShell {
          packages = inputs;
          shellHook = ''
            export LIBCLANG_PATH=${pkgs.libclang.lib}/lib/
            export LD_LIBRARY_PATH=${pkgs.openssl}/lib:$LD_LIBRARY_PATH
            export CC_wasm32_unknown_unknown=${pkgs.llvmPackages_14.clang-unwrapped}/bin/clang-14
            export CFLAGS_wasm32_unknown_unknown="-I ${pkgs.llvmPackages_14.libclang.lib}/lib/clang/14.0.6/include/"
            export PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig

            ${pkgs.lib.optionalString pkgs.stdenv.isLinux ''
              alias docker='podman'
              echo "Using 'podman' as an alias for 'docker'"
              echo "You can now use 'docker' commands, which will be executed by podman"

              # Podman configuration
              export CONTAINERS_CONF=$HOME/.config/containers/containers.conf
              export CONTAINERS_POLICY=$HOME/.config/containers/policy.json
              mkdir -p $HOME/.config/containers
              echo '{"default":[{"type":"insecureAcceptAnything"}]}' > $CONTAINERS_POLICY

              # Create a basic containers.conf if it doesn't exist
              if [ ! -f $CONTAINERS_CONF ]; then
                echo "[engine]
              cgroup_manager = \"cgroupfs\"
              events_logger = \"file\"
              runtime = \"crun\"

              [storage]
              driver = \"vfs\"" > $CONTAINERS_CONF
              fi

              # Ensure correct permissions
              chmod 600 $CONTAINERS_POLICY $CONTAINERS_CONF
            ''}

            ${setupEnvScript}
          '';
        };
      }
    );
}
