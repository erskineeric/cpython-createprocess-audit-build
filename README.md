# CPython 3.14.7 Windows audit correction — diagnostic build

A public, manual-only build recipe for one correction in `Modules/_winapi.c`:

```diff
-    if (PySys_Audit("_winapi.CreateProcess", "uuu", application_name,
+    if (PySys_Audit("_winapi.CreateProcess", "uOu", application_name,
```

The middle argument is already a Python object. The recipe requires the exact original file, changes exactly one runtime-source byte, and verifies the exact corrected hash. It rejects a missing, changed, or already-corrected base. Two separately recorded **build-only invocation flag amendments** and a third **packaging-helper-only deferred import amendment** are described below; none adds a C/runtime implementation correction.

**This is a remote diagnostic artifact, not an approved live interpreter replacement or dependency downgrade.** It is not an official CPython distribution. No deployment, installation, release publication, or local launch-guard acceptance is included.

## Run

From this repository's Actions page, manually dispatch **CPython 3.14.7 audit correction - diagnostic build**. There are no inputs and no push or pull-request triggers. The sole runner is standard `windows-2022`, with a 90-minute job timeout. Independent run/attempt concurrency keys do not cancel or replace other runs. Permissions are read-only; checkout does not persist credentials. Both Actions are immutable SHA-pinned.

The job requires the runner's preinstalled x64 CPython 3.11, Visual Studio 2022 v143, and a Windows SDK at least 10.0.19041.0. It fails if compatible installed tools or their app-local redistributables are missing. It does not install a toolchain or discover/download a fallback interpreter. The moving hosted image is recorded by image version, selected tool versions, executable hashes, and CRT inventories; this is **not a bit-reproducible toolchain lock**.

Only successful source verification, build, A1–A8 runtime gate, and package-manifest read-back enables the runtime-package upload. A separate **records-only directory is exposed before checkout or bootstrap selection** and uploaded with `always()`, the same immutable action, and three-day retention. Both artifacts have unique run/attempt names. Ordinary failures retain status, completed/failed command receipts, prior logs, and available inventories; failure handling re-raises rather than changing failure to success. It exports no interpreter, work tree, verifier payload, environment dump, or credentials. Child processes receive an explicit noncredential environment allowlist. Hard runner loss, disk failure, cancellation or timeout can prevent finalization/upload; an initialized/running record is not success. Actual Actions upload and working-binary evidence remain hosted-only and pending.

## Source identity and signature verification

- CPython: `3.14.7`, source commit `823f0323ee6ec1402088b73bce1a38473cac36dc`.
- Official archive: `https://www.python.org/ftp/python/3.14.7/Python-3.14.7.tar.xz`.
- Archive SHA256: `3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81`.
- Sigstore bundle SHA256: `6f41efc358b146b5548dbfc0414e9247441f8524fb6ef59f1c4ca946ffc70701`.
- Original `_winapi.c`: `b5370463a3994370f02dcd60bf467e46d2674b44e6303b824fd4831e6bf3ecde`.
- Corrected `_winapi.c`: `e0df69dbaf096fee7f21932f7b282437a6e5d630345b5e8a3e29ace5e41a59e5`.
- Genuine `Include/patchlevel.h`: `16a8955952cbaefd16f85909b73a0a6c182ec813f9544a12c28897c95b8d3f22`.

Hashes and commit metadata alone are **not signature proof**. Before extracting/executing source, the hosted job performs real Sigstore certificate/signature/transparency verification for `hugo@python.org`, issuer `https://github.com/login/oauth`. Verification failure stops the job. Sigstore 4.5.0 plus all transitive dependencies are locked to 32 exact Windows-CPython-3.11-compatible wheel URLs and SHA256 values in `sigstore-wheels.lock.json`.

The small stdlib bootstrap downloads and hashes each wheel, validates archive paths, rejects installation hooks (`.pth` and `.data` layouts), and extracts each into a private directory. It never invokes pip, setup code, an installer, or site initialization. Only on the hosted runner does it import these pinned libraries, check their actual dependency metadata/constraints/extras, and invoke Sigstore's verification CLI with online TUF trust-root updates. The verifier supply-chain trust boundary is PyPI/TLS plus reviewed lock hashes and the hosted image; wheel hashes are not independent publisher signatures. TUF/Sigstore service availability and current trust metadata are required. No offline/unsigned fallback is provided.

## Diagnostic dependency composition

The official release's PCbuild defaults are intentionally used for this diagnostic only:

| Dependency | Version | Upstream repository |
|---|---|---|
| bzip2 | 1.0.8 | python/cpython-source-deps |
| xz/liblzma | 5.2.5 | python/cpython-source-deps |
| zlib-ng | 2.2.4 | python/cpython-source-deps |
| zstd | 1.5.7 | python/cpython-source-deps |
| mpdecimal | 4.0.0 | python/cpython-source-deps |
| SQLite | 3.50.4.0 | python/cpython-source-deps |
| OpenSSL, official prebuilt dependency | 3.5.7 | python/cpython-bin-deps |

Every upstream reference was resolved to a real immutable commit and its actual archive downloaded/hash-checked. `pins.json` records commits, origins, archive roots, and hashes. Mutable tags are provenance labels only, never build download selectors. Two unused zstd CLI-test symlinks (`tests/cli-tests/bin/unzstd` and `zstdcat`) are omitted only after exact path, link-type, and target-content-hash validation; no link is created or followed. The OpenSSL dependency is not rebuilt here. These versions have not been approved as replacements for any existing environment.

## Build and package boundaries

Dependencies are safely prestaged before direct `MSBuild.exe PCbuild/pcbuild.proj /t:Build /m:1 /nr:false /noAutoResponse`. There is no batch-wrapper/discovery fallback, automatic response-file input, user property-sheet import, process-kill command, clean/rebuild target, PGO, JIT, or free-threaded build. The upstream compiler tasks can create their normal internal command files; no user-supplied response files are passed. All recipe writes, intermediates, generated build helpers, and temporary data are private to the current runner job. PATH is not changed.

Explicit properties include Release/x64/v143; extensions, externals and SSL enabled; ctypes, tkinter, both `IncludeTest` and `IncludeTests`, `DisableGil` and `KillPython` disabled. **`UseTIER2=0`**, not `false`, is required: upstream `pythoncore.vcxproj:109` defines `_Py_TIER2` for every nonempty value other than `0`. `UseJIT=false` remains explicit. Native compiler-command tlogs are retained and rejected if `_Py_TIER2` or `_Py_JIT` occurs; the hosted gate also requires `sys._jit.is_available()` to be false. An empty private `UserRootDir` and disabled directory-build imports prevent local property injection. Original source members must match the prepared-source inventory after compilation; unexpected regeneration stops runtime export. New generated files are inventoried, not hidden.

### Build-helper startup amendments (accepted scope retained)

Deleting the old path override alone would allow site startup. There is no supported environment variable that disables system `site` initialization. The pinned upstream call graph therefore requires the following small, visible build-only amendment:

| Upstream route | Isolation and change |
|---|---|
| `PCbuild/_freeze_module.vcxproj:441,453` → `Programs/_freeze_module.c:46–69` | Already `PyConfig_InitIsolatedConfig`, `site_import=0`, `_install_importlib=0`, `_init_main=0`; reads source and marshals C headers, not import caches. No change. |
| `PCbuild/regen.targets` → explicit `PythonForBuild` | Absolute preinstalled 3.11 with **`-S -B -s`**. Do not use `-I`: upstream pegen explicitly needs `PYTHONPATH=Tools\peg_generator`, and generator scripts need sibling imports. Inherited Python variables are removed; only upstream's known private path assignments remain. |
| `PCbuild/python.vcxproj:134–136` → built interpreter / `PC/validate_ucrtbase.py` | Insert only ` -S -B -s` after the quoted built executable. Preserve upstream's private Lib path and `ContinueOnError=true`. This optional validator imports ctypes, intentionally unavailable in this configuration; its warning is **not** claimed as UCRT validation. |
| `PCbuild/regen.targets:167–172` → built interpreter / `Programs/freeze_test_frozenmain.py` | Insert only ` -S -B -s` after the quoted executable; preserve the explicit private Lib path and original target conditions. |
| Built interpreter → `PC/layout/main.py` | Explicit `-S -B -s`, `--source`, `--build`, `--copy`, `--temp`, `--arch amd64`, `--include-stable`. `PYTHONHOME` is the private source tree and `PYTHONPATH` the private build output for this invocation only. |
| Packaged interpreter → hosted gate | `-I -S -B`, with normal app-local Lib/DLLs discovery and no path override file. |

`amend_build_helpers` requires exact original hashes (`python.vcxproj`: `af1af9d053e147b8d319c9886af6bec34935f76a906bf39a266e256b5ca2f81f`; `regen.targets`: `7c8924059672e889cfefb7151ed2d3f1e240decce53686b20bab0d7b2bac4f30`), prevalidates both files, changes precisely those two command substrings, and records before/after hashes and literal commands. These are **not a second runtime correction**. Original, one-byte-post-patch, build-prepared and final source maps remain separate. The generated convenience `python.bat` is inventoried but never executed. No helper, fetched verifier, compiler or new runtime is executed in local review.

### Packaging-helper deferred import (approved scope; successor review pending)

The unchanged `PC/layout/main.py` imports `support.appxmanifest` unconditionally. Its original module-level `import ctypes` reaches the intentionally disabled native `_ctypes` before option parsing, even though APPX is not selected. The separately approved third build/layout amendment changes only `PC/layout/support/appxmanifest.py`: remove its sole `import ctypes\n` line and insert `    import ctypes\n\n` immediately after `def get_packagefamilyname(name, publisher_id):\n`. All ctypes references occur inside that function; the unselected APPX path does not call it. `IncludeCTypes=false` remains unchanged; APPX support is not enabled or validated by this recipe.

`amend_packaging_helper` requires original SHA256 `2ebfde12fd1c8a12b3c48ac3081ab018e68c633cb64d59b1ad0bceec5ad8af21`, exactly one import and function signature, and amended SHA256 `b80520a2a5098aa1e154216cbcb02bb77ff7f7e6ca3299929b3718d175e18e26` before writing. Missing, changed, or already-amended input fails closed. `packaging-helper-amendment.json` records exact removed/inserted bytes and before/after hashes separately alongside the existing two-file `build-helper-amendments.json`. The build-prepared inventory includes all three amendments; the preceding one-byte C-patch inventory remains separate.

The package uses the upstream **normal `PC/layout/main.py` route under the built 3.14.7 interpreter**, with only the separately disclosed support-module import relocation, not a custom Lib copier or the 3.11 bootstrap. It contains `python.exe`, `pythonw.exe`, `python314.dll`, stable-ABI `python3.dll`, source-form `Lib`, `DLLs`, selected app-local VC/UCRT DLLs and CRT/native dependency license notices. No APPX, preset, embedded/flat/zip-library layout, pip, tests, venv, precompilation or `--include-underpth` is selected. The recipe rejects **any `._pth` file anywhere in build output or package**, excluded trees, bytecode, missing native members or changed CRT copies. `site.py` may exist as standard-library source but site initialization is disabled by invocation flags, not by a hidden runtime correction. ctypes Python wrappers may exist but its native extension and tkinter are intentionally unavailable. No live installation is copied. Windows system DLLs remain an OS dependency, not a bundled operating system.

### Exact stock-placeholder cleanup (package-only; successor review pending)

The unchanged normal layout also copies the official source's 119-byte `Lib/site-packages/README.txt`, SHA256 `cba8fece8f62c36306ba27a128f124a257710e41fc619301ee97be93586917cb`. After layout, the owned recipe preflights both source and private package: ordinary roots, `Lib` and `site-packages` directories, exactly one regular single-link `README.txt`, and exact pinned bytes in both copies. Source/package roots must not overlap. Missing, empty, changed, additional, subdirectory, symlink, hardlink or Windows reparse-point state fails before deletion; reparse detection uses `lstat` attributes compatible with Python 3.11. Only the package README is explicitly unlinked, followed by an empty-directory `rmdir`. There is no recursive deletion or upstream-source change, and the strict no-`site-packages` validator remains unchanged. This is package filtering, **not a fourth source/helper amendment or another runtime correction**.

Separate `package-placeholder-cleanup.json` records the expected member, verified source/package hashes, confirmed removed relative file/hash and directory, phase, and success/failure. An unlink or rmdir failure propagates; partial successful removal is retained in the receipt. A running/interrupted phase is not completion, and its confirmed-removal list is not an exhaustive claim after disk failure or hard interruption. Existing records sealing/export automatically includes this receipt. Source-bound AST tests establish selection without importing/executing upstream layout, and an owned realistic layout mock deposits the actual placeholder before exercising cleanup and the unchanged validator. Fixtures also cover rejected content/links/reparse attributes and truthful failure records; they are not hosted-layout execution evidence.

Artifact `manifest.json` binds every exported file with a single explicit self-exclusion. `recipe/` contains the complete exact ten-file publication set, including tests, `.gitattributes` and `.github/workflows/build.yml`; success upload includes these hidden paths. Records include:

- full original, one-byte-post-patch, build-prepared and final source maps, plus all generated intermediate/output file hashes;
- every materialized native dependency and all 32 verifier-wheel inventories, each bound to its actual archive hash and pin; final native dependency path-set checks;
- selected MSVC headers/libraries/binaries, SDK headers/x64 link libraries/tools/imports, MSBuild imported props/targets/task trees, .NET host, bootstrap Python inputs, CRT/UCRT and Git trees; actual native read-input hashes and compiler command tlogs;
- image/tool versions, exact argv, command return codes, logs, signature receipt/bundle and the hosted runtime gate report.

The selected toolchain trees form a conservative **available-input closure**, not a claim that every inventoried file was read. Native tlogs add observed compiler/linker reads; they are not an OS-wide execution trace. Windows system DLLs/kernel, runner services and online trust responses remain outside this file inventory. Bootstrap site-packages are excluded by `-S`; existing stdlib caches are inventoried because `-B` prevents writes, not reads. Input path sets/hashes are reread before runtime export. These records provide file provenance, **not bit reproducibility**, a signed attestation or a toolchain license grant. The Python-stage records manifest binds its completion snapshot; a separate final workflow manifest also binds early/failure workflow records. No giant generated provenance documents are committed to the recipe.

## Runtime gate, hosted built interpreter only

A1–A8 use an absent absolute executable sentinel and an audit hook that unconditionally denies every `_winapi.CreateProcess` event before OS process creation:

1. ASCII command.
2. Spaces.
3. Quote and trailing backslash encoded with `subprocess.list2cmdline`.
4. Fixed `é漢🙂` Unicode payload.
5. Fixed 4096-character ASCII payload.
6. `command_line=None`.
7. `cwd=None`.
8. `RuntimeError` denial instead of the custom `BaseException` denial.

Each requires exactly one three-argument event; exact values and `str`/`None` types; command object identity; the designated exception object; and no returned process handles. Unexpected return or exception aborts without retry. The gate verifies the built executable/DLL binding, app-local module paths, x64/version/GIL/JIT configuration, required native imports, and available library versions without opening a database. bzip2/liblzma source versions are labeled as pinned-source versions because their extension APIs do not expose runtime versions.

**This is an ABI regression gate, not local launch-guard acceptance, comprehensive CPython regression testing, a security certification, or permission to run the artifact on another machine. Do not run this gate under an installed interpreter.**

## Local static/unit checks only

Using an already available Python and the unmodified source tree read from the hash-verified official archive (the suite reads `_winapi.c` and the pinned build/layout/ctypes sources as bytes, without importing them):

```text
python -I -S -B tests/test_build.py --source <original-_winapi.c> --temp <owned-fixture-directory> -v
```

The tests use stdlib fixtures and AST/configuration inspection. They import only the owned build helpers, never build main, the audit gate, compiler, downloaded verifier, or new interpreter. One ordinary-failure fixture runs the already available interpreter with `-I -S -B` solely to print fixed fixture text and exit nonzero; it is not a runtime audit probe. Coverage includes exact one-byte patching and rejected bases, malformed/wrong hashes, archive traversal/drive/ADS/device/link/collision rejection, preflight before extraction, wheel hooks, size bounds, workflow exclusions, immutable pins, public file allowlist, and hosted-only entrypoints. A real four-failure patch RED was captured before the implementation; completed green receipts belong outside the publication file set.

Successor regression coverage also includes the actual upstream tier-2 condition, exact helper flag amendments, normal-layout command/exclusions, complete recipe export, missing/extra/tampered/renamed input paths, generated-source records, archive binding, CRT/license fixture copies, native command/input tlogs, and failure-record preservation without partial executable export. Local fixture success is not hosted compilation, signature, package or upload acceptance. Independent SPEC then QUALITY review must precede any remote run.

The deferred-import correction adds source-hash-bound AST/XML checks of the actual unconditional layout → appxmanifest → ctypes → disabled `_ctypes` chain, its absence after recipe-registered fixture preparation, function-local binding at every ctypes reference, exact amended bytes, unchanged two-file flag amendments, rejected changed/already-amended sources and wrong after-hash before writes, separate record wiring before the prepared inventory, and actual option definitions proving APPX is unselected. The original-chain regression was captured RED against unchanged predecessor helpers before implementing the correction; no upstream module or APPX function is executed locally. This static gate does not claim that a hosted layout/build/runtime has run.
