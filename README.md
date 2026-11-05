# Python Android

Pinned Android native builds for CPython 3.10, Chaquopy 17.2.0 and third-party wheels. Supports API 23, arm64-v8a and armeabi-v7a.

## Build and release

Source revisions and hashes are pinned in `native/sources.json` and `native/runtime-sources.json`. Build tools and commands are defined in `.github/workflows/build.yml`.

Push a `v*` tag to build both ABIs and publish a GitHub Release. Manual workflow runs produce Actions artifacts only.

The wheels job links against the API 23 target ZIP produced by the runtime job, so third-party wheels are checked against the same CPython that ships.

Bionic only exposes `if_nameindex`, `lockf`, `preadv`, `pwritev` and `prlimit` from API 24, so CPython is configured without them and `os.if_nameindex`, `os.lockf`, `os.preadv`, `os.pwritev` and `resource.prlimit` are absent. `native/verify.py` rejects any shipped library that still references a symbol newer than API 23.

On armeabi-v7a CPython is also configured with `--disable-largefile`, because `_FILE_OFFSET_BITS=64` renames `fseeko` and friends onto the LFS64 symbols, which are API 24 additions too. 32-bit file offsets there therefore stop at 2 GB; arm64-v8a always uses 64-bit `off_t` and is unaffected.

Each release contains 12 wheels, 2 native ZIPs and 2 provenance manifests. Binary artifacts stay outside Git.

## TV integration

TV pins the release and manifest hashes in `chaquo/runtime/native.lock.json`. From the TV repository, run `python scripts/sync_python_runtime.py` before building the Python AAR and module APK.

TV owns Java SDK integration, helpers, canonical C++ runtime selection and final packaging. Native release versions are independent of TV module versions.

## Verification

Builds check SHA-256, ABI, dependencies and 16 KB ELF LOAD/RELRO alignment. Consumers report device loading, physical ARM and native 16 KB tests separately.
