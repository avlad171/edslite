# EDS Lite modernization (2026)

Status of the fork's update from upstream sovworks/edslite v2.0.0.237 (2020).

## 1. Build / platform

| | Before | After |
|---|---|---|
| Gradle / AGP | 4.x / 3.3.2 | 9.9.1 / 9.5.1 |
| compileSdk / targetSdk | 28 / 28 | 37 (Android 17) / 37 |
| minSdk | 14 | 29 (Android 10) |
| NDK | r13b | 29.0.14206865 (16 KB page aligned) |
| Java | 8 | 17 |
| Support libs | com.android.support 26/28 | AndroidX |
| RxLifecycle | rxlifecycle2 | rxlifecycle3 (AndroidX, same RxJava 2 API) |
| ABIs | x86, x86_64, armv7, arm64 | x86_64, armv7, arm64 |

Toolchain on the dev Mac: Temurin 21 in `~/.local/jdk`, SDK in
`/usr/local/share/android-commandlinetools` (`local.properties`), `./gradlew assembleLiteDebug`.

Build status: `./gradlew assembleLiteDebug` succeeds; APK targets 37, all native libs are
16 KB page aligned (`zipalign -c -P 16` OK). Fixes needed for the new toolchain: 31
`switch (R.id.*)` blocks converted to if/else (R ids are no longer constants), and missing
`<string.h>`/`<unistd.h>` includes added to 11 legacy crypto/IO C files (implicit
declarations are errors in current clang). Not yet run on a device.

Behaviour changes required by targetSdk 31..37 and done:
- `android:exported` on every component with an intent filter.
- `FLAG_IMMUTABLE` on all PendingIntents; the auto-close alarm intent is now explicit (setPackage).
- `registerReceiver` -> `ContextCompat.registerReceiver(..., RECEIVER_NOT_EXPORTED)` (17 sites).
  **Security fix**: internal broadcasts such as `BROADCAST_CLOSE_ALL` / location-changed were
  previously receivable from *any* app on Android < 14.
- Foreground service type `specialUse` for LocationsService (keeps volumes mounted).
- `POST_NOTIFICATIONS`, scoped-storage permissions, `MANAGE_EXTERNAL_STORAGE` declared.
- Backups/device-transfer disabled (`allowBackup=false`, data_extraction_rules).
- `enableOnBackInvokedCallback=false` as a stop-gap.

Still TODO for targetSdk 37:
- Runtime request for POST_NOTIFICATIONS and the "All files access" settings intent.
- Migrate 17 `onBackPressed` overrides to `OnBackPressedCallback` (predictive back).
- Replace `AsyncTask` (3 uses) and `Environment.getExternalStorageDirectory` (8 uses).

## 2. ext2/3/4 support (READ-ONLY)

Native C: lwext4 (GPLv2, pinned commit eaea5a5) + `native/ext4/edsext4_core.c` + JNI shim;
Java: `com.sovworks.eds.fs.ext4.Ext4FS`. Detected automatically inside any container
(EDS / VeraCrypt / TrueCrypt / LUKS) by the ext superblock magic.

- Read-only twice over: lwext4 mounted `read_only`, and the block device write callback
  returns EROFS unconditionally.
- Patches to lwext4 (see `native/lwext4/EDS-PATCHES.txt`):
  1. `metadata_csum_seed` support (default in e2fsprogs >= 1.47, i.e. every new ext4).
  2. **Upstream bug**: sparse files returned the contents of physical block 0 instead of zeros
     for holes in multi-block reads. Fixed.
- I/O errors are handled at every point: `misc/ext4-test/run.sh` makes the N-th read fail for
  every N over a full walk (~1100 runs, ASan/UBSan). Found and fixed a double inode-ref release
  in lwext4 (EDS-PATCHES.txt #3) that crashed EDS when a USB drive was unplugged.
- Listings return each entry's type/size/mtime from its inode (no per-entry path lookups);
  Java caches them on the listed paths. /bin (1505 entries) on the phone: 7 s -> 1.3 s, together
  with caching the file manager's date/size formatters (80% of the remaining time was ICU
  formatter setup per row, an upstream EDS cost for every large folder).
- Symbolic links are followed with chroot semantics: absolute targets resolve from the volume
  root, `..` stops at it, 40-link limit (ELOOP); broken links and loops are hidden from listings.
- Not supported (mount fails cleanly with a message): `inline_data`, `casefold`, `encrypt`
  (fscrypt). These are common on Android-created ext4; desktop `mkfs.ext4` doesn't set them.
- Journal is not replayed: an uncleanly-unmounted volume shows its last checkpointed state.
- Tests: `misc/ext4-test/run.sh` builds the core with ASan+UBSan and compares every file of
  ext2, ext3, ext4 (4k, 1k blocks, no-csum, no-extents) images from `mke2fs -d` with the
  source tree; also asserts the image is byte-identical afterwards.

"Full disk encryption": on GrapheneOS the internal storage already uses file-based encryption
managed by the OS; an unprivileged app cannot replace it. What this app *can* do is open whole
encrypted block devices it is given access to (e.g. a LUKS/VeraCrypt-encrypted USB drive via
USB host / SAF). That is the planned scope; see open questions.

## 3. Upstream security review

### VeraCrypt (1.24 -> 1.26.31, Nov 2026) - items that matter for a third-party reader/writer

| Change | Relevance to EDS | Status |
|---|---|---|
| 1.24: passwords up to 128 bytes | EDS silently truncated VeraCrypt passwords to 64 bytes -> can't open volumes with longer passwords, and EDS-created volumes with long passwords don't open in VeraCrypt | **Fixed**: 128 bytes, with 64-byte legacy fallback |
| 1.26.7: XTS key1 must differ from key2 on creation; 1.26.14 warns on mount | EDS creates XTS volumes | TODO (creation check + mount warning) |
| 1.26.7: TrueCrypt mode, RIPEMD-160, GOST89 removed | EDS still mounts these; keep read-only for legacy data, disable *creation* | TODO |
| 1.26.7: BLAKE2s PRF | can't open such volumes | TODO (C) |
| 1.26.29: Argon2id KDF (416 MiB / 6 passes at default PIM, up to 1 GiB) | can't open such volumes | TODO (C, reference argon2) |
| CVE-2026-54073: hidden volume quick-format wrote plaintext zero sectors (1.26.6-1.26.28) | Check EDS hidden-volume creation for the same pattern | TODO audit |
| CVE-2026-53762: wolfCrypt builds used HKDF instead of PBKDF2 | not applicable (EDS uses its own PBKDF2) | n/a |
| 1.24-Update7: hidden volume may not reuse outer password/PIM/keyfiles | EDS hidden-volume creation | TODO |
| CVE-2024-54187, CVE-2025-23021, CVE-2026-77372/77572/108982, GHSA-w98h/-wf3r | OS driver/installer specific | n/a |

### LUKS2 + LVM2 (READ-ONLY, implemented)

Layering, each layer only reads inside the bounds of the one below; the same rule will carry
the future write path (writes only via the ext4 driver, never to raw partitions):

    USB / partition -> Luks2Header (Java, validated) -> Luks2Volume (C: Argon2, AES-XTS)
                    -> Lvm2 linear LV (Java metadata, bounds-checked) -> ext4 (C, lwext4)

- `luks2/Json.java`, `Luks2Header.java`: strict parser; both header copies + SHA-256 checksums,
  newest valid seqid wins, out-of-sync flagged. Refuses: re-encryption (keyslot, flags, extra
  segments, mandatory requirements), dm-integrity, unknown KDF/AF/area types, overlapping or
  out-of-bounds areas, truncated devices, duplicate keys, deep nesting.
- `native/luks/edsluks.c`: Argon2 (reference impl, vendored) in native memory (LUKS2 uses up to
  1 GiB); AES-XTS-plain64 decrypt; master key lives only as native key schedules, wiped on close.
- `luks2/Lvm2.java`: label/mda/text CRCs verified; linear LVs only.
- Tested against a real Ubuntu 26.10 LUKS2 (argon2id, 1 GiB) USB install
  (`misc/luks2-test/run.sh`): crypto KATs; 26 header-mutation tests; full stack mount; **all 154,185
  dpkg-tracked files (7.6 GB) verified against dpkg md5sums, 0 mismatches**.
- Not yet: ciphers other than aes-xts-plain64, ARMv8 AES instructions (Gladman AES is
  table-based), Argon2 multithreading/progress, choosing among several LUKS partitions / LVs.

### USB mass storage (READ-ONLY, implemented)

`com.sovworks.eds.usb`: Bulk-Only Transport + SCSI over Android's USB host API, exposed as a
`Luks2Header.Source` so the LUKS2 -> LVM2 -> ext4 stack runs on it unchanged.

- Read-only by construction: an opcode allowlist (TEST UNIT READY, REQUEST SENSE, INQUIRY,
  READ CAPACITY 10/16, READ 10/16) checked on every command; the only bulk-OUT transfers are
  31-byte command blocks; there is no data-out phase in the code.
- `AndroidBulkPipe`: finds class 8/6/0x50 interfaces, USB permission flow (mutable PendingIntent
  with explicit package), claims the interface with force (detaches the kernel driver) and selects
  the BOT alternate setting (the kernel may have used UAS).
- Errors per BOT 1.0: stall -> clear halt; bad/missing CSW, tag mismatch, phase error -> reset
  recovery and retry (reads are idempotent); UNIT ATTENTION retried; disconnect detected and
  reported. 120 KiB per READ (Linux default).
- `PartitionTable`: GPT with header + entry CRCs, falls back to the backup copy; MBR primaries;
  no table = whole device.
- Tests: `misc/usb-test/run.sh` (simulated device with fault injection, GPT/MBR corruption cases).
  On device (Pixel 10, Android 17, SanDisk 3.2Gen1 250 GB): GPT + LUKS2 header read correctly,
  170 MB/s sequential read, no retries. Unplug mid-read -> "USB device was disconnected" within
  10 ms, no hang; replug reopens fine. Full stack on device (USB -> GPT -> LUKS2 argon2id 1 GiB ->
  LVM2 -> ext4): wrong passphrase rejected in 8.7 s, correct one unlocks in 8.8 s, ext4 mount 3 ms,
  root listing 23 ms, 48 USB commands in total; no out-of-memory with the 1 GiB Argon2 allocation.
- Debug builds have `UsbProbeActivity` (src/debug) for on-device probing:
  `adb shell am start --user 10 -n com.sovworks.edslite/com.sovworks.eds.android.debug.UsbProbeActivity [--ei readMiB N]`

### USB drive in the file manager

- Drawer > Containers lists each attached mass-storage drive ("USB drive: <product>"). Tap: USB
  permission, find the LUKS2 partition, EDS's normal password dialog, file manager. Read-only;
  write actions are hidden on read-only locations.
- `UsbLuksLocation` (EDSLocation, id = LUKS UUID) on top of `UsbDriveLocation` (non-openable
  placeholder for the partition). Unplug force-closes the location (key wiped) and refreshes the UI.
- `Ext4FS` serializes all native calls and closes open file handles before unmounting, so a
  forced close (unplug) can't race a read into freed native memory.

Fixes found while testing on Android 17:
- Edge-to-edge: content was drawn under the status/action bar (hid the first drawer entries).
  `EdgeToEdgeInsets` pads every activity's content by the system bars / cutout / keyboard.
- Internal broadcasts were implicit while their receivers are `RECEIVER_NOT_EXPORTED`, so they
  were not delivered (drawer/file list didn't refresh on open/close/attach). Now package-explicit.
- `MediaMountedReceiver` slept 3 s on the main thread on every USB/media event (UI freeze).
- "Stop service and exit" killed the process 4 s later even if EDS had been reopened meanwhile.

### LUKS / cryptsetup

EDS supports LUKS1 only. LUKS2 (default since cryptsetup 2.1, Argon2id default) is not
supported. Plan: LUKS2 read-only in C (JSON header + Argon2id/PBKDF2 keyslots + AF merge +
aes-xts-plain64), reusing the Argon2 code above. CVE-2021-4122 (online re-encryption) only
affects writers; a read-only implementation must refuse volumes with an in-progress
re-encryption segment.

### Forks of edslite

78 forks; only a few with real changes:
- cobol56/nevercrypt (2022): passwords hidden from accessibility services; hide create
  menu items on read-only mounts. **Ported** (adapted, see below).
- bakad3v/0sakaCrypt (Jul 2026): incognito keyboard for passwords; hidden-volume protection.
  Keyboard flag **ported**; hidden-volume protection TODO (review license first).
- Dezirae-Stark/edslite-pq, uploadersoasis/EDS_lite_fork: no code changes beyond CI.

Password-field hardening now in `EditSB`: IME no-personalized-learning, excluded from
autofill, `accessibilityDataSensitive` on Android 14+ (keeps TalkBack working, unlike
nevercrypt's `importantForAccessibility="no"`), no long-press copy.
FLAG_SECURE is now on by default.

Dependency bump with security relevance: metadata-extractor 2.12.0 -> 2.22.0 (parses EXIF of
decrypted images; several malformed-input fixes since 2019).
