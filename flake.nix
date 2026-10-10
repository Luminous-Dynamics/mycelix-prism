{
  description = "Prism standalone Rust, WebAssembly, and Tauri development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          rustToolchain = version:
            pkgs.rust-bin.stable.${version}.default.override {
              extensions = [
                "clippy"
                "rust-analyzer"
                "rust-src"
                "rustfmt"
              ];
              targets = [ "wasm32-unknown-unknown" ];
            };

          commonPackages = with pkgs; [
            cargo-nextest
            cargo-audit
            cargo-deny
            trunk
            pkg-config
            clang
            cmake
            gnumake
            nodejs
            openssl
          ];

          # Fast formatting lane: intentionally omits the GTK/WebKit/Tauri
          # build inputs and Cargo tooling unrelated to rustfmt.
          mkFmtShell = version: pkgs.mkShell {
            packages = [
              (pkgs.rust-bin.stable.${version}.minimal.override {
                extensions = [ "rustfmt" ];
              })
            ];

            shellHook = ''
              echo "Prism format shell: Rust ${version} with rustfmt only."
            '';
          };

          mkPrismShell = version: pkgs.mkShell {
            packages = commonPackages ++ [ (rustToolchain version) ];

            nativeBuildInputs = with pkgs; [
              gobject-introspection
              wrapGAppsHook4
            ];

            buildInputs = with pkgs; [
              cairo
              glib
              gtk3
              libsoup_3
              librsvg
              pango
              webkitgtk_4_1
              dbus
            ];

            shellHook = ''
              export RUST_BACKTRACE=1
              echo "Prism dev shell: Rust ${version}, wasm32-unknown-unknown, Cargo Nextest, and Tauri/WebKitGTK dependencies."
              echo "After the standalone Cargo workspace is installed, validate with:"
              echo "  cargo metadata --locked --format-version 1"
              echo "  cargo nextest run --workspace --locked"
              echo "Generate and commit flake.lock before treating the shell as reproducible."
            '';
          };
        in
        {
          # Current stable for normal development and release qualification.
          default = mkPrismShell "1.99.0";

          # Compatibility lane if Prism commits to Rust 1.96.1 as its MSRV.
          msrv = mkPrismShell "1.96.1";

          # Keep formatting check lightweight and independent from system UI deps.
          fmt = mkFmtShell "1.99.0";
        });
    };
}
