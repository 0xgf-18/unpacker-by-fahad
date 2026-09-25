# Android Unpacking Research Sources

## Research Inventory

### A — Integrated and Validated

| ID | Repository | URL | Technique | License | Status |
|---|---|---|---|---|---|
| R01 | DPT-Shell (existing) | Built-in | Static DEX extraction | Internal | VALIDATED |
| R02 | B2Al (existing) | Built-in | B2Al detector | Internal | VALIDATED |
| R03 | LSParanoid (existing) | Built-in | Smali deobfuscation | Internal | VALIDATED |

### B — Integrated but Environment-Dependent

| ID | Repository | URL | Technique | License | Status |
|---|---|---|---|---|---|
| R04 | frida-packing-detector | github.com/poping520/frida-packing-detector | Generic runtime packing detection | MIT | Requires Frida |
| R05 | fridroid-unpacker | github.com/enovella/fridroid-unpacker | Frida-based DEX dump | Apache-2.0 | Requires Frida |

### C — Research Implemented Independently

| ID | Repository | URL | Technique | License | Status |
|---|---|---|---|---|---|
| R06 | Profiler (existing) | Built-in | Multi-signal static detection | Internal | VALIDATED |
| R07 | ArkDetector (existing) | Built-in | 360/Ark detection | Internal | VALIDATED |
| R08 | FridaDumper (existing) | Built-in | Frida-based dump | Internal | Requires Frida |

### D — Research Only (Not Integrated)

| ID | Repository | URL | Technique | License | Status |
|---|---|---|---|---|---|
| R09 | CheckPointSW/android_unpacker | github.com/checkpointsw/android_unpacker | AOSP-patched ART dump | Apache-2.0 | RESEARCH ONLY |
| R10 | strazzere/android-unpacker | github.com/strazzere/android-unpacker | GDB/native unpacker | Apache-2.0 | RESEARCH ONLY |
| R11 | rewhy/adaptiveunpacker | github.com/rewhy/adaptiveunpacker | Adaptive unpacking | Unknown | RESEARCH ONLY |
| R12 | TheQmaks/clsdumper | github.com/TheQmaks/clsdumper | Class dumper | Unknown | RESEARCH ONLY |
| R13 | NoahMauthe/decompilation_analysis | github.com/NoahMauthe/decompilation_analysis | Decompilation analysis | Unknown | RESEARCH ONLY |
| R14 | SafaSafari/jiagu_unpacker | github.com/SafaSafari/jiagu_unpacker | Jiagu DEX extraction | MIT | RESEARCH ONLY |
| R15 | VexoraWebServices/CyberArmor | github.com/VexoraWebServices/CyberArmor | CyberArmor analysis | Unknown | RESEARCH ONLY |
| R16 | serval-snt-uni-lu/RePack | github.com/serval-snt-uni-lu/RePack | Repacking research | Unknown | RESEARCH ONLY |
| R17 | DragonJAR/Android-Pentesting-Skill | github.com/DragonJAR/Android-Pentesting-Skill | Pentesting reference | Unknown | RESEARCH ONLY |
| R18 | harshdhamaniya/android-security-handbook | github.com/harshdhamaniya/android-security-handbook | Security handbook | Unknown | RESEARCH ONLY |

### E — External Tools (Not Integrated)

| ID | Repository | URL | Technique | License | Status |
|---|---|---|---|---|---|
| R19 | CodingGay/BlackDex | github.com/CodingGay/BlackDex | Runtime DEX dump (app) | Apache-2.0 | EXTERNAL TOOL |
| R20 | Krainium/DarkDex | github.com/Krainium/DarkDex | Memory-based DEX extraction | Unknown | EXTERNAL TOOL |
| R21 | zyq8709/DexHunter | github.com/zyq8709/DexHunter | ART/DVM modification | Apache-2.0 | RESEARCH ONLY |
| R22 | muhammadrizwan87/dexdumper | github.com/muhammadrizwan87/dexdumper | Memory-based DEX extraction | NOASSERTION | EXTERNAL TOOL |
| R23 | UltraSina/androidReverse | github.com/UltraSina/androidReverse | On-device reverse engineering | Unknown | EXTERNAL TOOL |
| R24 | jacobocasado/droidsaw | github.com/jacobocasado/droidsaw | Pure-Rust DEX decompiler | BSD-3-Clause | EXTERNAL TOOL |
| R25 | damarkuncoro/dex-parser-rust | github.com/damarkuncoro/dex-parser-rust | Rust DEX parser | Unknown | EXTERNAL TOOL |
| R26 | drneox/nutcracker | github.com/drneox/nutcracker | Automated analysis pipeline | Unknown | EXTERNAL TOOL |
| R27 | purifire (academic) | arxiv.org/html/2509.16340v1 | eBPF-based anti-analysis bypass | Academic | RESEARCH ONLY |

## Technique Coverage Matrix

### Detection
- Static fingerprint matching (Profiler) — VALIDATED
- Native library detection (ArkDetector) — VALIDATED
- AXML/Manifest analysis (AxmlManifest) — VALIDATED
- Runtime behavior detection (frida-packing-detector concept) — RESEARCH

### Static Unpacking
- DPT Shell extraction (DPT unpacker) — VALIDATED
- B2Al detection (B2AlDetector) — VALIDATED
- LSParanoid smali deobfuscation (SmaliDeobfuscator) — VALIDATED
- Jiagu AES/XOR decryption (jiagu_unpacker concept) — RESEARCH
- 360/Ark native loader analysis (ArkDumper) — VALIDATED

### Dynamic Extraction
- Frida-based DEX dump (FridaDumper) — VALIDATED
- Memory scanning for DEX headers — RESEARCH
- ClassLoader hooking (Frida scripts) — RESEARCH
- InMemoryDexClassLoader interception — RESEARCH

### DEX Extraction
- Static DEX extraction from ZIP — VALIDATED
- Payload DEX recovery (OoooooOooo parser) — VALIDATED
- Checksum repair (ChecksumRepair) — VALIDATED
- DEX validation (DexValidator) — VALIDATED

### ART Analysis
- ART runtime modification (DexHunter) — RESEARCH ONLY
- CompactDex handling (DarkDex) — RESEARCH ONLY
- ART heap object walking — RESEARCH ONLY

### Dalvik Analysis
- Dalvik DEX format parsing — VALIDATED
- Dalvik bytecode analysis — VALIDATED

### Native Analysis
- ELF parsing (ElfParser) — VALIDATED
- JNI bridge analysis (DummyJniBridge) — VALIDATED
- Native library detection — VALIDATED

### Obfuscation
- Smali obfuscation detection — VALIDATED
- String encryption detection — VALIDATED
- Code flow analysis — PARTIAL

### Rebuilding
- APK rebuild (ApkRebuilder) — VALIDATED
- Manifest patching — VALIDATED
- Resource handling — VALIDATED

### Validation
- DEX header validation — VALIDATED
- ZIP structure validation — VALIDATED
- Checksum verification — VALIDATED
- Signature validation — VALIDATED

### Runtime Analysis
- Root-based file access — VALIDATED
- ADB-based operations — VALIDATED
- Shizuku integration — VALIDATED
