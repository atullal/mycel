# Mycel's patch to swift-rs 1.0.8

Tauri builds its iOS Swift code (and each plugin's) with swift-rs. Xcode 27's
SwiftPM gives internal `@_cdecl` functions hidden visibility and prelinks
static products, which turns them into local symbols, so linking the iOS app
failed with "Undefined symbols: _retain_object, _release_object,
_string_from_bytes".

swift-rs 1.0.8 already repairs this with `globalize_cdecl_symbols` (it needs
rustup's `llvm-tools` component for `llvm-objcopy`), but only for the
package's own module (`Tauri.o`), not for swift-rs's runtime, which lands in
the same archive as `SwiftRs.o`.

Change (in `src-rs/build.rs`, marked `MYCEL PATCH`): `globalize_cdecl_symbols`
also treats the `SwiftRs.o` member as its own.

Drop this copy once a swift-rs release handles the SwiftRs member itself.
