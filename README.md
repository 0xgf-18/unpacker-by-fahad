# UNPACKER BY FAHAD

**static restore . clean . rebuild** — an all-in-one APK unpacking suite.

A single tool that **detects** the protection stack of an Android APK, **extracts**
any embedded real APK (repack tricks), and **unpacks** the payload with the
right backend — DPT Shell, LSParanoid, 360 Jiagu / ArkShell or PairipProtect —
then rebuilds and (optionally) signs the result. Designed for Termux on Android
and works on desktop (Windows/Linux/macOS).

Maintained by [Fahad (0xgf-18)](https://github.com/0xgf-18).

---

## Table of contents

- [Key features](#key-features)
- [Supported protections](#supported-protections)
- [How detection works](#how-detection-works)
- [One-shot auto mode](#one-shot-auto-mode)
- [Requirements](#requirements)
- [Install on Termux](#install-on-termux)
- [Build & run from source](#build--run-from-source)
- [Command line reference](#command-line-reference)
- [Mode deep dives](#mode-deep-dives)
  - [DPT Shell pipeline](#dpt-shell-pipeline)
  - [LSParanoid pipeline](#lsparanoid-pipeline)
  - [360 Jiagu / ArkShell pipeline](#360-jiagu--arkshell-pipeline)
  - [B2Al proxy packer pipeline](#b2al-proxy-packer-pipeline)
  - [PairipProtect pipeline](#pairipprotect-pipeline)
- [Outputs, signing & keystore](#outputs-signing--keystore)
- [Environment variables](#environment-variables)
- [Project layout](#project-layout)
- [Examples](#examples)
- [FAQ & troubleshooting](#faq--troubleshooting)
- [Limitations](#limitations)
- [Disclaimer](#disclaimer)

---

## Key features

- **One-shot operation** — `bash run.sh app.apk` does everything: analyze →
  extract embedded `origin.apk` (SignatureKiller / fake-360 re-packs) → recurse
  into the real app → auto-pick the correct unpacker → rebuild. No prompts.
- **Static first, runtime only when needed** — DPT and LSParanoid are fully
  static (no device). Ark requires a device only because 360 encrypts the dex
  at runtime.
- **Broad static profiler** — fingerprints packers, protectors, obfuscators and
  runtimes across four scopes (dex strings, native libs, assets, manifest) with
  anchor gating and additive scoring.
- **Decoy handling** — detects fake-360 placeholder shells (`libjiagu_*.a`
  markers, Art-Jiagu NeoArk) and never abuses them; real re-packs are unwrapped
  automatically. The DPT rebuild additionally **strips decorative `libjiagu*`
  natives/assets** from the output when no real 360 wiring exists (no
  com.qihoo / com.stub / b2al manifest component and no jiagu reference in the
  payload dexes).
- **Rebuild + signing** — restores the real `Application` entry point, strips
  shell `appComponentFactory`, drops a decorative 360 layer (jiagu natives
  nothing wires — no com.qihoo / com.stub / b2al manifest component and no
  jiagu reference in the payload dexes), zipaligns and signs with a generated
  keystore when build-tools / apksigner are available.
- **Termux-ready** — ships with `run.sh` that auto-builds on first run and
  auto-locates `apktool.jar`.
- **Mobile-friendly UI** — fixed-width ANSI cards sized for Termux screens.

---

## Supported protections

### Built-in pipelines (fully automated)

| Strategy | Protection | Type | Device needed |
| --- | --- | --- | --- |
| `dpt` | DPT Shell | static payload restore + AES key recovery | no |
| `lsparanoid` | LSParanoid | static string deobfuscation (smali rewrite) | no |
| `ark` | 360 Jiagu / ArkShell | runtime dump + rebuild | yes (su / adb) |
| `b2al` | B2Al proxy packer | static record-chain recover + rebuild | no |
| `pairip` | PairipProtect (VM) | RePairip deprotection | no |
| `embedded` | SignatureKiller / fake-360 re-packs | extract embedded `origin.apk`, recurse | no |

### Detectable but external-tool routes

The profiler fingerprints these and prints the recommended vendor tool via
`--analyze` (they need a specialised backend, currently not wired in):

| Fingerprint | Tool |
| --- | --- |
| Bangcle / SecNeo 梆梆 | KeyDive |
| Tencent Legu 腾讯乐固 | KeyDive |
| Ijiami 爱加密 | KeyDive |
| Baidu Protect 百度加固 | KeyDive |
| APKProtect | KeyDive |
| DexProtector | KeyDive |
| AppKiller Protector | KeyDive |
| Unity IL2CPP | Auto-Il2cppDumper |
| Xamarin / .NET (Mono) | pyxamstore |
| React Native (Hermes bytecode) | hermes_rs |
| Flutter (Dart AOT) | blutter |
| Dex2C (native compile) | d2c |

---

## How detection works

`Profiler.analyze()` opens the zip once, then scans every fingerprint across
four independent scopes:

- **dex** — substring scan over every `classes*.dex` (Latin-1 view)
- **native** — basename match on `lib/**/*.so` entries
- **asset** — entry-name patterns over the zip listing
- **manifest** — substring match on the binary `AndroidManifest.xml`

Scoring is additive: every unique hit adds to `hits`, and likelihood is
`min(1.0, 0.42 + 0.16 * (hits-1))` — one weak hit lands near 0.42, several
cross-scope hits saturate at 1.0. **Anchor gating** prevents false positives: a layer is only reported when at
least one *discriminative* marker (e.g. `b2al`, `libjiagu`, `OoooooOooo`) is
physically present in a binary scope; generic strings like `com.qihoo` only add
confidence. A fingerprint may instead provide a **binary gate** (e.g. B2Al:
does a `classes*.dex` actually contain a decodable record chain?) which replaces
the text-anchor test; a passing B2Al gate also suppresses the overlapping
`ark360` text fingerprint.

**Decoy scan** — a separate pass looks for fake-360 placeholders (tiny text
`libjiagu*.a`, Art-Jiagu NeoArk markers) and SignatureKiller re-packs (real APK
embedded as `origin.apk`). When a *content proof* (placeholder native / decoy
marker) is found, the genuine ArkShell layer is suppressed and a `fake360`
DECOY layer (likelihood 1.0) is emitted instead.

`--analyze` additionally runs an optional **APKiD YARA** scan
(`tools/apkid`, contributed rules included) when Python + YARA are available.

---

## One-shot auto mode

`--mode auto-all` (the default when you run through `run.sh`):

1. **Profile** the APK.
2. **Embedded repack?** — if a real nested APK entry exists
   (`assets/SignatureKiller/origin.apk` or any `origin.apk` / `assets/*.apk`),
   extract it into `<out>/embedded/` and **recurse** (guarded to depth 4).
3. **Raw?** — prints `APK IS RAW - nothing to unpack`, exits 0.
4. **Route** — pick the first built-in pipeline for the detected stack
   (DPT / LSParanoid / Ark / B2Al / Pairip).
5. **Decoy-only?** — no embedded apk to extract → falls through to the classic
   quick detectors (`DptDetector`, `LsparanoidDetector`, `ArkDetector`,
   `B2AlDetector`) as a last-resort route.

Aliases: `auto-all`, `oneshot`, `full`, `single`, or menu choice `5`.

---

## Requirements

- JDK **17+** (Termux: `pkg install openjdk-17`)
- `apktool.jar` — needed only for LSParanoid / rebuild stages;
  `run.sh` auto-detects `./apktool.jar` or `$APKTOOL_HOME/apktool.jar`
  (or set `DPT_APKTOOL_JAR`)
- `tools/RePairip.jar` — bundled, required for PairipProtect
- Ark mode needs a device:
  - `--device local` — on-device Termux. Default `--root auto` uses **Shizuku's
    `rish`** (no root) when it is installed, otherwise falls back to `su -c`.
  - `--device adb` — host with `adb` binary + USB/network device
  - `--root bluestacks` — Bluestacks whitelist PATH-hijack (no root prompt)
- Gradle is optional — `run.sh` uses the bundled wrapper if `gradle` is absent

---
Youtube Video https://youtu.be/EQvlHzHL-t8?si=JLDmbGmbvRuJCA0A
## Install on Termux

```bash
pkg install openjdk-17 unzip
termux-setup-storage            # allow /sdcard access
git clone https://github.com/0xgf-18/unpacker-by-fahad DPT-UNPACKER
cd DPT-UNPACKER
ls -la

chmod +x run.sh && ./run.sh
```

First run builds the tool via Gradle (`installDist`) automatically; afterwards
it starts instantly. The bundle contains `run.sh`, `apktool.jar`, the shaded
runtime (`lib/*.jar`) and `tools/RePairip.jar`.

---

## Build & run from source

```bash
./gradlew --no-daemon installDist      # or: gradle --no-daemon installDist
java -Xmx1g -cp "build/install/fahad-unpacker/lib/*" com.dpt.unpack.MainKt app.apk
```

Requires a Kotlin/JVM toolchain; `build.gradle.kts` targets Kotlin 2.1.20,
JVM target 11.

---

## Command line reference

```
usage: dpt-unpacker <input.apk> [options]      (first positional = input)
```

| Option | Meaning |
| --- | --- |
| `-i, --input <apk>` | input APK |
| `-o, --output <dir>` | output directory (default `<name>-unpacked/` next to input) |
| `--mode <dpt\|lsparanoid\|ark\|b2al\|pairip\|auto\|auto-all>` | force a route |
| `--analyze` | profile only: protection stack + APKiD booster + recommendation |
| `--debug` | verbose output (stack traces on failure) |
| `--inspect` | DPT: layout info only, no dump |
| `--crack` | DPT: attempt payload AES key recovery (default) |
| `--dump-manifest` | DPT: stop after manifest handling |
| `--aes-key <hex>` | DPT: override recovered AES key |
| `--package <pkg>` | override target package (dpt + ark) |
| `--application <class>` | force the real Application class (dpt + ark) — use when auto-discovery picks a wrapper (e.g. SignatureKiller's `KillerApplication`) instead of the app's real `Application` |
| `--build-key <key>` | DPT: build key override |
| `--build-keys-file <f>` | DPT: load extra build keys from file |
| `-h, --help` | help |

### Ark / 360 options

| Option | Meaning |
| --- | --- |
| `--device <adb\|local>` | `adb` = host drives device (default); `local` = on-device Termux |
| `--root <auto\|su\|shizuku\|bluestacks>` | `auto` (default): local uses `rish` if installed, else `su`; `shizuku` forces `rish -c <cmd>` (adb-uid, **no root**, local only); `bluestacks` is adb-only |
| `--adb <path>` | path to adb binary (default PATH / `$ANDROID_HOME`) |
| `--timeout <sec>` | max seconds to wait for payload decrypt (default 120) |
| `--dump-dir <dir>` | offline: read already-dumped `ark_payload_*.dex` from dir |
| `--application <class>` | force the real Application class |
| `--no-install` | do not (re)install the APK on the device |
| `--no-launch` | do not start the app (use with `--dump-dir`) |

### Mode aliases

- DPT: `dpt`, `shell`, `1`
- LSParanoid: `lsp`, `lsparanoid`, `2`
- Ark: `ark`, `360`, `jiagu`, `3`
- Pairip: `pairip`, `repairip`, `4`
- B2Al: `b2al`, `b2`, `proxy`, `6`
- Auto-all: `auto-all`, `oneshot`, `full`, `single`, `5`

---

## Mode deep dives

### DPT Shell pipeline

Static, five stages:

1. **Detect payload** — `DptDetector` locates the shell dexes (`payloadDexes`)
   and the `OoooooOooo` code asset; layout parsed by `OoooooOoooParser` into
   candidate code-store sections.
2. **Recover key** — `KeyRecovery` derives the per-app AES key (build key +
   package heuristics); verifies plaintext prologue rate; honours
   `--aes-key`, `--build-key`, `--build-keys-file`.
3. **Restore dex bodies** — `DexRestorer` decrypts each `classes*.dex` section
   in place, neutralising runtime hooks and bridges as it goes.
4. **Rebuild** — `ApkRebuilder` merges the patched dexes with the original zip;
   the binary manifest is rewritten to point `<application android:name>` at the
   **real** Application (`ArkDexTools.discoverRealApplication`) and the shell's
   `appComponentFactory` attribute is removed (prevents
   `ClassNotFoundException > ProxyComponentFactory`). Decorative `libjiagu*`
   entries are detected (`Fake360Detector`: no manifest/dex 360 wiring) and
   stripped from the output; a real 360 layer keeps them untouched.
5. **Sign** — zipalign + apksigner with a generated keystore (see
   [Outputs, signing & keystore](#outputs-signing--keystore)).

### LSParanoid pipeline

Static, six stages, requires `apktool.jar`:

1. **Detect** — `LsparanoidDetector` (`org.lsposed.lsparanoid`,
   `DeobfuscatorHelper` markers).
2. **Locate apktool** — `ExternalTool` search: `DPT_APKTOOL_JAR`, `APKTOOL_HOME`,
   cwd / DIST `apktool.jar`.
3. **Decode** — `apktool d -f -o <out>`.
4. **Deobfuscate** — `SmaliDeobfuscator` resolves every `getString()` call
   against the embedded encrypted string tables; reports rounds, resolved /
   total / skipped / errors and recovered string arrays; `cleanup = true`
   strips the LSParanoid runtime glue.
5. **Rebuild** — `apktool b` → `<name>-rebuilt.apk`.
6. **Sign** — to `<out>/<name>-unpacked.apk`.

### 360 Jiagu / ArkShell pipeline

Runtime dump, requires a device (or an existing dump):

1. **Detect** — `ArkDetector` looks for the `b2al` class prefix, `StubApp`,
   native `libjiagu*` artifacts and the shell proxy `<application>`
   (e.g. `b2al.encryp.vip`).
2. **Collect payloads** —
   - *device:* install (`adb install -r -t` or `pm install` via `su`), launch
     (`am start -n` or `monkey`), then poll for `ark_payload_*.dex` under
     `/data/app/*/lib/*` (or the app base dir) until the
     `--timeout` expires.
   - *offline:* `--dump-dir` reads already-dumped containers, sorted by index.
3. **Extract + fix** — `ArkOatExtractor` extracts dex blobs from the OAT
   containers; `DexChecksum` repairs the deferred checksums; `DexValidator`
   verifies structural integrity.
4. **Application entry** — `ArkDexTools.discoverRealApplication` finds the real
   `Application` subclass across the payload dexes and rewrites the manifest.
5. **Rebuild + sign** — `ArkRebuilder` + signing to `<name>-unpacked.apk`.

### B2Al proxy packer pipeline

Fully static, no device. The shipped `classes.dex` is a small proxy stub whose
body is a chain of XOR-encrypted DEX records plus a trailer (never assumes a
fixed build offset — the chain end is auto-detected):

1. **Detect + recover** — `B2AlDetector` reads the record count from the last 4
   bytes, probes candidate block-ends before EOF (decrypt the first `0x2C` bytes,
   check dex magic + header `file_size` + endian tag), walks the whole chain
   backwards and validates every record (`plain[i] ^ key[i & 63]`).
2. **Trailer** — the real Application class name is recovered from the trailer
   (`n - 0x48`, 32 bytes XOR `key0`).
3. **Restore** — the records are written back as a dedicated multidex
   (`classes.dex … classesN.dex`).
4. **Manifest** — `<application android:name>` is repointed at the real
   Application via the in-place AXML string-pool patch (UTF-8 and UTF-16 pools).
5. **Rebuild + sign** — `ArkRebuilder` drops the proxy carrier + old signature,
   installs the recovered dexes, then zipalign + apksigner.

### PairipProtect pipeline

Delegates to `RePairip.jar` (discovery order: `DPT_REPAIRIP_JAR`, `tools/`,
cwd, repo-root walk, bare `RePairip.jar`):

1. **Load/merge** — `java -jar RePairip.jar -i <input.apk|input.apks>` (log/
   merge instrumentation for `.apks` bundles).
2. **Translation patch** — if a captured `pairip.json` is found
   (`<out>/pairip.json` or `<input>-pairip.json` next to the APK) the static
   translation patch is applied (`-t pairip.json`).
3. **Output** — written next to the input (RePairip writes the fixed APK).

---

## Outputs, signing & keystore

- **DPT / LSParanoid / Ark** → `<out>/<name>-unpacked.apk`
  (`<out>` defaults to `<name>-unpacked/` beside the input).
- **Pairip** → output appears next to the input file.
- Signing uses `zipalign` + `apksigner` from `DPT_BUILD_TOOLS` / `ANDROID_HOME`,
  or path binaries as a fallback. A throwaway keystore is generated per output
  dir (`Signer.ensureKeystore`). If no signer is found the result is left
  **unsigned** and a note is printed.
- Intermediate artifacts kept under the output dir: `unsigned.apk`,
  `aligned.apk`, `patched_dex/`, `embedded/origin.apk`.

---

## Environment variables

| Variable | Purpose |
| --- | --- |
| `DPT_APKTOOL_JAR` | path to `apktool.jar` (LSParanoid / rebuild) |
| `APKTOOL_HOME` | directory holding `apktool.jar` |
| `DPT_REPAIRIP_JAR` | path to `RePairip.jar` (pairip mode) |
| `DPT_BUILD_TOOLS` | Android build-tools dir (signing) |
| `ANDROID_HOME` | fallback for build-tools / adb |

`run.sh` auto-sets `DPT_APKTOOL_JAR` from `./apktool.jar` or
`$APKTOOL_HOME/apktool.jar` when unset.

---

## Project layout

```
fahad-unpacker/
├── run.sh                    # Termux launcher: builds + one-shot auto mode
├── build.gradle.kts          # Kotlin 2.1.20 / JVM 11
├── src/main/kotlin/com/dpt/unpack/
│   ├── Main.kt               # CLI, auto-all orchestration, UI
│   ├── detection/            # Profiler (static fingerprints), DptDetector, ApkIdRunner
│   ├── code/                 # OoooooOooo layout parser
│   ├── crack/                # DPT AES key recovery
│   ├── crypto/               # DPT/LSP crypto primitives
│   ├── dex/                  # dex parsers, DummyJniBridge
│   ├── restore/              # DexRestorer, DptHookStripper
│   ├── lsp/                  # LsparanoidDetector, SmaliDeobfuscator, ExternalTool
│   ├── ark/                  # ArkDetector, ArkDumper (adb/local/bluestacks),
│   │                         # ArkOatExtractor, ArkDexTools, ArkRebuilder
│   ├── b2al/                 # B2AlDetector (proxy carrier record-chain recover)
│   ├── axml/                 # binary AndroidManifest read + patch
│   ├── rebuild/              # ApkRebuilder, Signer
│   ├── tools/                # RePairipTool, DumpMethod
│   ├── checksum/             # DexChecksum
│   ├── validate/             # DexValidator
│   ├── elf/                  # ELF helpers
│   ├── extraction/           # PayloadExtractor
│   └── util/                 # Cursor
└── tools/
    ├── RePairip.jar          # PairipProtect deprotector (vendored)
    └── apkid/                # APKiD YARA rules (--analyze booster)
```

---

## Examples

```bash
# fully automatic (Termux)
bash run.sh com.example.app.apk

# analyse only: stack + recommendation
bash run.sh app.apk --analyze

# force a specific route
bash run.sh app.apk --mode dpt
bash run.sh app.apk --mode lsparanoid
bash run.sh app.apk --mode pairip

# B2Al proxy packer: static record-chain recover + rebuild
bash run.sh app.apk --mode b2al

# fake-360: SignatureKiller repack (has origin.apk) is unpacked statically
bash run.sh app.apk
# ... a marker-only fake shell (no origin.apk, no lib/libjiagu.so) is detected
# as FAKE SHELL ONLY and resolved statically with a clean readable copy.

# ark on a rooted phone via Termux su
bash run.sh app.apk --mode ark --device local

# ark driven by a host pc
bash run.sh app.apk --mode ark --device adb --adb /path/to/adb

# ark fully offline from a previous dump
bash run.sh app.apk --mode ark --dump-dir ./dumped --no-install --no-launch

# output to a custom directory
bash run.sh app.apk -o ./out
```

### Fully static unpacking (no device, no root)

Most routes run entirely on the machine/phone without touching a device:

| Protection | Static? | Notes |
| --- | --- | --- |
| DPT (dex-shell) | ✅ | payload restore + key recovery, offline |
| LSParanoid | ✅ | smali-level deobfuscation via local apktool |
| B2Al proxy packer | ✅ | static record-chain recover + multidex rebuild |
| Fake-360 decoy / marker-only shell | ✅ | embedded `origin.apk` is extracted, or the readable copy is delivered (`FAKE SHELL ONLY`) |
| SignatureKiller re-pack | ✅ | embedded `origin.apk` extracted + recursed |
| PairipProtect translation | ✅ | offline from a captured `pairip.json` |
| Real 360 / ArkShell (offline mode) | 🔜 | encrypted payload lives in `libjiagu.so` → static decryptor planned |
| Real 360 / ArkShell (OTA/online) | ❌ | payload only exists at runtime; requires device/root |

Run everything with one command:

```bash
bash run.sh app.apk           # auto-all: profile -> extract -> pick the best static route
bash run.sh app.apk --analyze # explain what it will do
```

### Unpack 360 / Ark on a non-rooted phone (Shizuku)

Shizuku runs the server as the **adb (shell)** user, which is enough for Ark
dumping — the decrypted `ark_payload_*.dex` payloads land in
`/data/data/<pkg>/code_cache/` after the app starts and are readable by that uid.
No root required.

1. Install **Shizuku** and start it (`adb` mode via USB/wireless, or root).
2. **Shizuku app → "Use Shizuku in terminal apps" → Export files** — this
   exports the `rish` script + `rish_shizuku.dex` to a folder.
3. In **Termux**: `termux-setup-storage`, then move the two files from the
   export folder into Termux's private directory (Android 14+ refuses writable
   dex, so `~/` or `$PREFIX/bin` works, not `/sdcard`) and fix permissions:

   ```bash
   mv ~/storage/shared/rish/rish* $PREFIX/bin/
   chmod +x $PREFIX/bin/rish
   chmod 400 $PREFIX/bin/rish_shizuku.dex   # required on Android 14+
   export RISH_APPLICATION_ID=com.termux
   rish -c 'id'                             # sanity check: runs as shell/uid
   ```

   No Shizuku-side grant is needed for Termux — `rish` runs the command as the
   server itself.
4. Run the unpacker:

   ```bash
   bash run.sh app.apk --mode ark --device local --root shizuku
   ```

   Or simply `--root auto` (default) — it picks `rish` automatically if it is
   installed, else falls back to `su`.

Notes:

- Shizuku must be **running** when the dump happens (restart it after a reboot).
- If the payload read is denied for a specific app, that app's files are not
  world-readable for that user; root is the only fallback there.
- `installApk` goes through `pm install`, which the adb user may use; if it
  fails, install the APK manually and run with `--no-install`.

---

## FAQ & troubleshooting

**It asks a menu instead of running automatically** — that only happens when you
run the raw JAR without `run.sh` on an interactive terminal. Via `run.sh` (or
with `--mode auto-all`) it never prompts.

**`apktool not found (set DPT_APKTOOL_JAR...)`** — LSParanoid mode needs
`apktool.jar`; drop it next to `run.sh` (bundle already has it) or
`export DPT_APKTOOL_JAR=/path/to/apktool.jar`.

**Ark says `adb not found - install platform-tools`** — no adb host set up.
Use `--device local` on a rooted Termux, pass `--adb <path>`, or set
`ANDROID_HOME`.

**Output is unsigned** — no `zipalign`/`apksigner` in `DPT_BUILD_TOOLS`/PATH.
Install Android build-tools or sign the APK yourself (e.g. with apksigner).

**`no packer/protector fingerprint found`** — the APK looks raw; verify with
`--analyze`.

**`protection stack: ... no built-in pipeline for 'x'`** — detected a backend
that ships as an external tool (KeyDive / blutter / ...). See the
[Supported protections](#supported-protections) table for the recommended tool.

---

## Limitations

- Ark/360 dex decryption happens **at runtime** on the real device — a rooted
  device (or a Bluestacks root-mode, or an already-captured dump) is mandatory.
- Nested embedded chains are recursed up to a depth of 4, then refused to avoid
  infinite unpacking loops.
- Static routes (DPT/LSP) can be defeated by newer packer versions; key-recovery
  heuristics cover the known layout families.
- No license keys / commercial signing; outputs rely on your own keystore or the
  generated throwaway one.

---

## License

Copyright © 2026 Fahad (0xgf-18). **All rights reserved.**

You may **use** this tool freely for personal, non-commercial purposes. All
other rights remain with the author: copying, modifying, redistributing or
commercial use requires the author's explicit written permission. See the
[LICENSE](LICENSE) file for full terms.

---

## Disclaimer

For **security research and educational purposes only**. Only unpack APKs you
own or are explicitly authorised to analyse. The author is not responsible for
misuse.
