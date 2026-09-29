{
  description = "Server Buddy: ESP32-P4 Ethernet ESP-NOW hub for Home Assistant";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # ESP-IDF toolchains; keeps its own nixpkgs pin for the IDF Python env.
    esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";
    # P4<->C6 SDIO transport (host on P4, co-processor firmware on C6).
    esp-hosted = {
      url = "git+https://github.com/espressif/esp-hosted-mcu?ref=refs/tags/v3.0.9&submodules=1";
      flake = false;
    };
    # Legacy host, used only by the one-shot C6 updater: it still speaks the
    # pre-1.0 RPC of the C6's factory firmware, which the v3 host does not.
    esp-hosted-v2 = {
      url = "git+https://github.com/espressif/esp-hosted-mcu?ref=refs/tags/v2.12.13&submodules=1";
      flake = false;
    };
    esp-wifi-remote = {
      url = "github:espressif/esp-wifi-remote/wifi_remote-v1.6.5";
      flake = false;
    };
    # Must match nixpkgs' home-assistant; provides hassfest for the integration check.
    ha-core = {
      url = "github:home-assistant/core/2026.5.4";
      flake = false;
    };
    esp-mdns = {
      url = "github:espressif/esp-protocols/mdns-v1.13.1";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      esp-dev,
      esp-hosted,
      esp-hosted-v2,
      esp-wifi-remote,
      esp-mdns,
      ha-core,
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
              haPy.tqdm # hassfest
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
                    exec env -u PYTHONPATH -u PYTHONHOME ${haPython}/bin/python -m ${tool} "$@"
                  ''
                )
                [
                  "pytest"
                  "mypy"
                ]
              ++ [
                # IDF's shell exports a Python 3.13 PYTHONPATH; keep HA isolated.
                (pkgs.writeShellScriptBin "ha-python" ''
                  exec env -u PYTHONPATH -u PYTHONHOME ${haPython}/bin/python "$@"
                '')
              ];
          };

          # Builds an ESP-IDF project (subdir of ./firmware) offline in the sandbox.
          firmwareSrc = lib.fileset.toSource {
            root = ./firmware;
            fileset = lib.fileset.gitTracked ./firmware;
          };
          # Pinned third-party IDF components; IDF names components by directory.
          mkComponents =
            links:
            pkgs.runCommand "sb-idf-components" { } (
              "mkdir $out\n" + lib.concatLines (lib.mapAttrsToList (n: src: "ln -s ${src} $out/${n}") links)
            );
          extraComponents = mkComponents {
            esp_hosted = esp-hosted;
            mdns = "${esp-mdns}/components/mdns";
          };

          buildIdfProject =
            {
              name,
              project,
              target,
              components ? extraComponents,
              preBuild ? "",
              # Extra sdkconfig fragment layered over sdkconfig.defaults.
              sdkconfigVariant ? null,
            }:
            let
              idfDefs = lib.optionalString (
                sdkconfigVariant != null
              ) "-D SDKCONFIG_DEFAULTS='sdkconfig.defaults;${sdkconfigVariant}'";
            in
            pkgs.stdenvNoCC.mkDerivation {
              inherit name;
              src = firmwareSrc;
              sourceRoot = "source/${project}";
              nativeBuildInputs = [ esp-idf ];
              dontConfigure = true;
              dontFixup = true;
              inherit preBuild;
              buildPhase = ''
                runHook preBuild
                export HOME=$TMPDIR/home
                mkdir -p $HOME
                rm -rf build
                export IDF_COMPONENT_MANAGER=0
                export SB_EXTRA_COMPONENTS=${components}
                export ESP_IDF_VERSION=${lib.removePrefix "v" (lib.versions.majorMinor (lib.removePrefix "v" idfRev))}
                idf.py -B build ${idfDefs} set-target ${target}
                idf.py -B build ${idfDefs} build
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
            project = "p4";
            target = "esp32p4";
          };

          c6-firmware = buildIdfProject {
            name = "server-buddy-c6";
            project = "c6";
            target = "esp32c6";
          };

          # One-shot tools: push the embedded C6 image over SDIO.
          # -legacy: 2.x host, for C6s still on factory (pre-1.0) firmware.
          # default: 3.x host, for C6s already on ESP-Hosted 3.x.
          c6ImageHook = "cp ${c6-firmware}/server_buddy_c6.bin main/c6_image.bin";
          p4-c6-updater-legacy = buildIdfProject {
            name = "server-buddy-p4-c6-updater-legacy";
            project = "p4_c6_updater";
            target = "esp32p4";
            sdkconfigVariant = "sdkconfig.hosted_v2";
            components = mkComponents {
              esp_hosted = esp-hosted-v2;
              esp_wifi_remote = "${esp-wifi-remote}/components/esp_wifi_remote";
            };
            preBuild = c6ImageHook;
          };
          p4-c6-updater = buildIdfProject {
            name = "server-buddy-p4-c6-updater";
            project = "p4_c6_updater";
            target = "esp32p4";
            sdkconfigVariant = "sdkconfig.hosted_v3";
            preBuild = c6ImageHook;
          };

          # ---- hub core host tests (fake platform + simulated node)
          hubSrc = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./protocol
              ./firmware/components/sb_protocol
              ./firmware/components/sb_hub
              ./tests/protocol_c
              ./tests/hub_c
            ];
          };

          hub-c =
            pkgs.runCommand "hub-c-asan"
              {
                nativeBuildInputs = [ pkgs.gcc ];
              }
              ''
                cd ${hubSrc}
                gcc ${cFlags} -Wno-unused-parameter -fsanitize=address,undefined -fno-sanitize-recover=all \
                  firmware/components/sb_protocol/*.c firmware/components/sb_hub/*.c tests/hub_c/test_hub.c \
                  -L${pkgs.mbedtls}/lib -Wl,-rpath,${pkgs.mbedtls}/lib -lmbedcrypto -lm \
                  -o $TMPDIR/hubtest
                $TMPDIR/hubtest
                touch $out
              '';

          apiSrc = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./firmware/p4/main/sb_api_logic.c
              ./firmware/p4/main/sb_api_logic.h
              ./tests/api_c
            ];
          };

          api-c = pkgs.runCommand "api-c-asan" { nativeBuildInputs = [ pkgs.gcc ]; } ''
            cd ${apiSrc}
            gcc -std=c11 -D_GNU_SOURCE -O1 -g -Wall -Wextra -Wpedantic -Werror \
              -fsanitize=address,undefined -fno-sanitize-recover=all \
              -Ifirmware/p4/main -I${lib.getDev pkgs.mbedtls}/include \
              -I${lib.getDev pkgs.cjson}/include/cjson \
              firmware/p4/main/sb_api_logic.c tests/api_c/test_api_logic.c \
              -L${pkgs.mbedtls}/lib -Wl,-rpath,${pkgs.mbedtls}/lib -lmbedcrypto \
              -L${pkgs.cjson}/lib -Wl,-rpath,${pkgs.cjson}/lib -lcjson \
              -o $TMPDIR/test_api
            $TMPDIR/test_api
            touch $out
          '';

          # ---- Home Assistant integration: lint, strict types, tests against a TLS fake hub
          haSrc = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./custom_components
              ./tests/ha
              ./hacs.json
              ./ruff.toml
            ];
          };
          haRuff = "--no-cache";
          ha-integration =
            pkgs.runCommand "ha-integration"
              {
                nativeBuildInputs = [
                  haPython
                  pkgs.ruff
                ];
              }
              ''
                export HOME=$TMPDIR
                cp -r ${haSrc} src && chmod -R +w src && cd src
                ruff check ${haRuff} custom_components tests/ha
                ruff format ${haRuff} --check custom_components tests/ha
                python -m mypy --strict --python-version 3.14 --explicit-package-bases \
                  --cache-dir $TMPDIR/mypy custom_components
                (cd tests/ha && python -m pytest -q -p no:cacheprovider)
                # hassfest from the pinned HA core (manifest, translations, config flow, ...)
                integration=$PWD/custom_components/server_buddy
                cp -r ${ha-core} $TMPDIR/core && chmod -R +w $TMPDIR/core
                (cd $TMPDIR/core && python -m script.hassfest --integration-path "$integration")
                touch $out
              '';

          # ---- protocol v1 host tests
          protocolSrc = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./protocol
              ./firmware/components/sb_protocol
              ./tests/protocol_c
            ];
          };
          protocolPython = pkgs.python3.withPackages (ps: [ ps.pytest ]);
          sbSources = "firmware/components/sb_protocol";
          cFlags = "-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror -I${sbSources}/include -Ifirmware/components/sb_hub/include -I${lib.getDev pkgs.mbedtls}/include";

          protocol-python =
            pkgs.runCommand "protocol-python"
              {
                nativeBuildInputs = [
                  protocolPython
                  pkgs.ruff
                ];
              }
              ''
                cp -r ${protocolSrc} src && chmod -R +w src && cd src/protocol/python
                ruff check --no-cache .
                python -m pytest -q -p no:cacheprovider
                touch $out
              '';

          protocol-c =
            pkgs.runCommand "protocol-c-asan"
              {
                nativeBuildInputs = [
                  pkgs.gcc
                  protocolPython
                ];
              }
              ''
                cd ${protocolSrc}
                gcc ${cFlags} -fsanitize=address,undefined -fno-sanitize-recover=all \
                  ${sbSources}/*.c tests/protocol_c/test_vectors.c \
                  -L${pkgs.mbedtls}/lib -Wl,-rpath,${pkgs.mbedtls}/lib -lmbedcrypto -lm \
                  -o $TMPDIR/test_vectors
                # Differential: C must agree with Python on 30k mutated frames.
                PYTHONPATH=protocol/python python -m sb_protocol.vectors --mutations 30000 $TMPDIR/mutations.txt
                $TMPDIR/test_vectors protocol/test-vectors $TMPDIR
                g++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -fsyntax-only \
                  -I${sbSources}/include tests/protocol_c/cxx_header.cpp
                touch $out
              '';

          protocol-fuzz =
            pkgs.runCommand "protocol-libfuzzer"
              {
                nativeBuildInputs = [
                  pkgs.clang
                  protocolPython
                ];
              }
              ''
                cd ${protocolSrc}
                clang ${cFlags} -fsanitize=fuzzer,address,undefined \
                  ${sbSources}/sb_protocol.c ${sbSources}/sb_describe.c tests/protocol_c/fuzz_decode.c \
                  -o $TMPDIR/fuzz
                mkdir $TMPDIR/corpus
                python ${./tests/protocol_c/make_corpus.py} protocol/test-vectors $TMPDIR/corpus
                $TMPDIR/fuzz -runs=2000000 -seed=1 $TMPDIR/corpus
                touch $out
              '';
        in
        {
          packages = {
            inherit
              esp-idf
              p4-firmware
              c6-firmware
              p4-c6-updater
              p4-c6-updater-legacy
              ;
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
              export IDF_COMPONENT_MANAGER=0
              export SB_EXTRA_COMPONENTS=${extraComponents}
              export CCACHE_DIR="''${XDG_CACHE_HOME:-$HOME/.cache}/server-buddy-ccache"
            '';
          };

          formatter = pkgs.nixfmt-tree;

          checks = {
            inherit
              p4-firmware
              c6-firmware
              protocol-python
              p4-c6-updater
              p4-c6-updater-legacy
              protocol-c
              protocol-fuzz
              hub-c
              api-c
              ha-integration
              ;

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
                  ruff check ${./scripts/hw-api-smoke.py}
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
