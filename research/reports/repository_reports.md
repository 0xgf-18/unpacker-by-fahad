# Repository Research Reports

## R09: CheckPointSW/android_unpacker

**Repository:** https://github.com/checkpointsw/android_unpacker
**License:** Apache-2.0
**Copyright:** Check Point Software Technologies
**Stars:** 366
**Last Updated:** 2017 (DEF CON 25)

### Technique
AOSP-patched ART/DVM runtime that dumps DEX during class loading. Requires building a custom AOSP image from android-6.0.1_r65 with unpacker.patch applied to the ART directory.

### Architecture
- Shell script (unpacker.sh) launches AOSP emulator
- Installs target APK
- Modified ART runtime intercepts DEX loading
- Dumps unpacked DEX to filesystem

### Compatibility
- Android: 6.0.1 only (AOSP patch)
- ART: Yes (modified)
- Dalvik: No
- Root: N/A (emulator-based)
- ADB: Yes (for APK installation)
- Native: No (pure Java/ART modification)

### Reusable Code
None directly. The concept of intercepting DEX loading at the ART level is valuable for understanding dynamic unpacking approaches.

### Research Value
HIGH - Demonstrates that ART-level interception is the most effective approach for generic unpacking. The patch to class_linker.cc shows exactly where DEX files are loaded.

### Integration Possibility
NOT_INTEGRATABLE - Requires AOSP build environment and custom emulator image.

---

## R10: strazzere/android-unpacker

**Repository:** https://github.com/strazzere/android-unpacker
**License:** Apache-2.0
**Copyright:** Tim 'diff' Strazzere
**Stars:** 1.2k
**Last Updated:** Active (corellium fork added)

### Technique
Multiple approaches:
1. GDB-based unpacking (gdb-scripts/) - Attach GDB to process, set breakpoints on DEX loading
2. Native unpacker (native-unpacker/) - Runs natively without GDB dependency
3. Emulator hiding (hide-emu/) - Hides QEMU/debugger from packers
4. Corellium-based (corellium-android-unpacking/) - ARM-based realistic unpacking

### Architecture
- gdb-scripts/: Bash scripts for GDB-based unpacking
- native-unpacker/: C/C++ native code for APKProtect/Bangcle/LIAPP/Qihoo
- hide-emu/: Hacks for hiding QEMU/debuggers
- corellium-android-unpacking/: Automated dynamic unpacking

### Compatibility
- Android: 4.0-8.0 (varies by approach)
- ART: Yes
- Dalvik: Yes
- Root: Yes
- ADB: Yes
- Native: Yes (for native-unpacker)

### Reusable Code
- Emulator hiding concepts (anti-detection)
- GDB script patterns for DEX dumping
- Native unpacking approach for specific packers

### Research Value
HIGH - Demonstrates multiple unpacking approaches and anti-detection techniques. The native unpacker shows how to handle packers that hook libc functions.

### Integration Possibility
RESEARCH_ONLY - Concepts can inform detection strategies, but direct integration requires GDB/emulator infrastructure.

---

## R19: CodingGay/BlackDex

**Repository:** https://github.com/CodingGay/BlackDex
**License:** Apache-2.0
**Stars:** 6,402
**Language:** C++/C/Java

### Technique
Runtime DEX extraction using DexFile cookie-based approach. Supports Android 5.0-12 without requiring root or custom environment. Runs as an Android app.

### Architecture
- Android app that runs on device
- Uses DexFile cookie to extract DEX
- Supports both hook-based and cookie-based extraction
- Deep unpacking mode with method instruction repair

### Compatibility
- Android: 5.0-12
- ART: Yes
- Root: Not required (but works better with root)
- ADB: No (runs as app)
- Native: Yes (C++ core)

### Reusable Code
None directly (pre-built APK). The DexFile cookie technique is well-documented and can be independently implemented.

### Research Value
VERY HIGH - Most popular Android unpacker. Demonstrates that DexFile cookie-based extraction is the most effective modern approach.

### Integration Possibility
EXTERNAL_TOOL - Available as pre-built APK. Can be used alongside Unpacker by Fahad.

---

## R20: Krainium/DarkDex

**Repository:** https://github.com/Krainium/DarkDex
**License:** Unknown
**Stars:** Active development

### Technique
Memory-based DEX extraction using redroid (Android in Docker). Event-driven capture using bpftrace uprobes on ART's DexFileLoader::OpenCommon and ClassLinker::DefineClass.

### Architecture
- Host-side darkdex.sh script
- Uses redroid (Android in Docker)
- bpftrace for kernel-level probing
- artwalk for DexFile heap object recovery
- CompactDex to standard DEX conversion

### Compatibility
- Android: 5.0+ (via redroid)
- ART: Yes
- Root: Yes (host-level)
- ADB: Yes
- Native: Yes (bpftrace, C)

### Reusable Code
- CompactDex to DEX conversion concept
- artwalk DexFile heap walking concept
- dexval validation concept

### Research Value
VERY HIGH - Cutting-edge approach using eBPF for anti-analysis bypass. The CompactDex handling is particularly valuable for modern Android versions.

### Integration Possibility
EXTERNAL_TOOL - Requires redroid + bpftrace host environment.

---

## R21: zyq8709/DexHunter

**Repository:** https://github.com/zyq8709/DexHunter
**License:** Apache-2.0
**Stars:** 1,356
**Last Updated:** 2015

### Technique
Modified ART/DVM runtime that dumps DEX during class loading. Based on Android 4.4.3 source code. Feature string-based trigger for targeted unpacking.

### Architecture
- Modified art/runtime/class_linker.cc (ART)
- Modified dalvik/vm/native/dalvik_system_DexFile.cpp (DVM)
- Feature string file pushed to /data/ before app launch
- Dumps "whole.dex" to app data directory

### Compatibility
- Android: 4.4.3 (ART) / 4.4.3 (DVM)
- ART: Yes (modified)
- Dalvik: Yes (modified)
- Root: Yes
- ADB: Yes
- Native: Yes (C++)

### Reusable Code
- DEX loading interception points in ART
- Feature string matching concept
- DEX dump mechanism

### Research Value
HIGH - Foundational research for ART-based unpacking. Shows the exact interception points in ART runtime.

### Integration Possibility
NOT_INTEGRATABLE - Requires AOSP modification, Android 4.4 only.

---

## R22: muhammadrizwan87/dexdumper

**Repository:** https://github.com/muhammadrizwan87/dexdumper
**License:** NOASSERTION (contact author)
**Stars:** 86
**Language:** C

### Technique
Memory-based DEX extraction library that runs within the application process. Pure C implementation with no external dependencies.

### Architecture
- Native C library (libdexdumper.so)
- Smart memory scanning with region filtering
- DEX signature detection
- SHA1-based duplicate prevention
- Runtime configuration via .conf files

### Compatibility
- Android: 5.0+
- ART: Yes
- Root: Not required
- ADB: No (runs in-app)
- Native: Yes (pure C)

### Reusable Code
- Memory scanning algorithm
- DEX signature detection
- Duplicate prevention via SHA1

### Research Value
HIGH - Demonstrates that in-process DEX extraction is possible without root. The memory scanning approach is valuable.

### Integration Possibility
RESEARCH - Technique can be studied, but direct integration requires native library compilation.

---

## R14: SafaSafari/jiagu_unpacker

**Repository:** https://github.com/SafaSafari/jiagu_unpacker
**License:** MIT
**Stars:** 38
**Language:** Python

### Technique
Static DEX extraction from Jiagu-packed APKs. Handles AES-CBC and XOR encryption layers, fake ZIP encryption flags.

### Architecture
- Python script (jiagu_unpacker.py)
- ZIP decryption module (zip_decrypt.py)
- AES and XOR decryption
- Automatic detection of fake encryption flags

### Compatibility
- Android: 5.0+ (Jiagu packer)
- ART: Yes
- Dalvik: Yes
- Root: No
- ADB: No
- Native: No (pure Python)

### Reusable Code
- ZIP decryption concept
- AES/XOR decryption patterns
- Fake encryption flag detection

### Research Value
MEDIUM - Jiagu-specific but demonstrates the pattern of ZIP-based DEX encryption and decryption.

### Integration Possibility
RESEARCH - Python tool, but concepts can be independently implemented in Kotlin.

---

## R04: poping520/frida-packing-detector

**Repository:** https://github.com/poping520/frida-packing-detector
**License:** MIT
**Stars:** Active

### Technique
Generic runtime detection of Android app protection/packing. Non-signature-based, uses runtime behavior analysis.

### Architecture
- Frida library (JavaScript)
- Hooks Application lifecycle
- Checks Activity class loading during attachBaseContext
- Reports protection status and unpack completion

### Compatibility
- Android: 5.0+
- ART: Yes
- Root: Yes
- ADB: Yes
- Native: No (JavaScript)

### Reusable Code
- Application lifecycle hooking pattern
- Class loading detection concept
- Protection status callback pattern

### Research Value
HIGH - Demonstrates a generic, non-signature-based approach to packing detection.

### Integration Possibility
RESEARCH - Frida script, but concept can be documented and used with existing FridaDumper.

---

## R05: enovella/fridroid-unpacker

**Repository:** https://github.com/enovella/fridroid-unpacker
**License:** Unknown
**Stars:** Active

### Technique
Frida-based DEX dump using OpenMemory/OpenCommon in libart.so/libdexfile.so.

### Architecture
- Frida script (dexDump.js)
- Hooks libart.so OpenMemory or libdexfile.so OpenCommon
- Calculates DEX size from memory
- Dumps DEX from memory

### Compatibility
- Android: 4.4-11
- ART: Yes
- Root: Yes
- ADB: Yes
- Native: No (JavaScript)

### Reusable Code
- OpenMemory/OpenCommon hooking pattern
- DEX size calculation from memory

### Research Value
HIGH - Most reliable Frida-based unpacking approach. Well-tested against multiple packers.

### Integration Possibility
RESEARCH - Concept already partially implemented in FridaDumper.
