{
  description = "Server Buddy: ESP32-P4 Ethernet ESP-NOW hub for Home Assistant";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # ESP-IDF toolchains; keeps its own nixpkgs pin for the IDF Python env.
    esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";
  };

  outputs =
    {
      self,
      nixpkgs,
      esp-dev,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      # Waveshare-recommended IDF for ESP32-P4-WIFI6-POE-ETH. P4 and C6 are RISC-V.
      idfRev = "v5.5.4";
      idfHash = "sha256-rItbBrwItkfJf8tKImAQsiXDR95sr0LqaM51gDZG/nI=";

      perSystem =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          lib = pkgs.lib;

          esp-idf = esp-dev.packages.${system}.esp-idf-riscv.override {
            rev = idfRev;
            sha256 = idfHash;
          };

          # Home Assistant test env uses HA's own pinned Python package set.
          haPy = pkgs.home-assistant.python3Packages;
          haPython = haPy.python.buildEnv.override {
            extraLibs = [
              haPy.pytest-homeassistant-custom-component
              haPy.pytest
              haPy.pytest-asyncio
              haPy.mypy
            ];
            ignoreCollisions = true;
          };
          # Namespaced wrappers so the HA interpreter never shadows IDF's python.
          haTools = pkgs.symlinkJoin {
            name = "ha-tools";
            paths =
              map
                (
                  tool:
                  pkgs.writeShellScriptBin "ha-${tool}" ''
                    exec ${haPython}/bin/python -m ${tool} "$@"
                  ''
                )
                [
                  "pytest"
                  "mypy"
                ]
              ++ [
                (pkgs.writeShellScriptBin "ha-python" ''exec ${haPython}/bin/python "$@"'')
              ];
          };

          # Builds an ESP-IDF project offline inside the Nix sandbox.
          buildIdfProject =
            {
              name,
              src,
              target,
            }:
            pkgs.stdenvNoCC.mkDerivation {
              inherit name src;
              nativeBuildInputs = [ esp-idf ];
              dontConfigure = true;
              dontFixup = true;
              buildPhase = ''
                runHook preBuild
                export HOME=$TMPDIR/home
                mkdir -p $HOME
                export IDF_COMPONENT_MANAGER=0
                idf.py -B build set-target ${target}
                idf.py -B build build
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p $out
                cp build/*.bin build/flasher_args.json build/flash_args $out/
                cp -r build/bootloader build/partition_table $out/ 2>/dev/null || true
                find $out -type f ! -name '*.bin' ! -name '*flash*' -delete
              '';
            };

          p4-firmware = buildIdfProject {
            name = "server-buddy-p4";
            src = lib.fileset.toSource {
              root = ./firmware/p4;
              fileset = lib.fileset.gitTracked ./firmware/p4;
            };
            target = "esp32p4";
          };
        in
        {
          packages = {
            inherit esp-idf p4-firmware;
            default = p4-firmware;
          };

          devShells.default = pkgs.mkShell {
            name = "server-buddy";
            packages = [
              esp-idf
              pkgs.esphome
              haTools
              pkgs.ruff
              pkgs.ccache
              pkgs.git
              pkgs.picocom
              pkgs.nixfmt
            ];
            shellHook = ''
              export IDF_CCACHE_ENABLE=1
              export CCACHE_DIR="''${XDG_CACHE_HOME:-$HOME/.cache}/server-buddy-ccache"
            '';
          };

          formatter = pkgs.nixfmt-tree;

          checks = {
            inherit p4-firmware;

            nix-format = pkgs.runCommand "nix-format" { nativeBuildInputs = [ pkgs.nixfmt ]; } ''
              nixfmt --check ${./flake.nix}
              touch $out
            '';

            tooling =
              pkgs.runCommand "tooling-smoke"
                {
                  nativeBuildInputs = [
                    esp-idf
                    pkgs.esphome
                    haTools
                    pkgs.ruff
                  ];
                }
                ''
                  export HOME=$TMPDIR
                  idf.py --version
                  esptool.py version
                  esphome version
                  ha-python -c "import pytest_homeassistant_custom_component, homeassistant"
                  ha-pytest --version
                  ha-mypy --version
                  ruff --version
                  touch $out
                '';
          };
        };
    in
    {
      packages = forAllSystems (s: (perSystem s).packages);
      devShells = forAllSystems (s: (perSystem s).devShells);
      formatter = forAllSystems (s: (perSystem s).formatter);
      checks = forAllSystems (s: (perSystem s).checks);
    };
}
