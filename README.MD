# EDS Lite

EDS (Encrypted Data Store) is a virtual disk encryption software for Android which allows you to store your files in an encrypted container. EDS Lite is an open source edition of EDS. Visit [EDS web site](https://sovworks.com/eds/) to learn about EDS features and capabilities.

You can download and install the latest version from [Google Play](https://play.google.com/store/apps/details?id=com.sovworks.edslite).

Please support the development of the open source version of EDS by making a donation: [![Donation](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://sovworks.com/eds/donations.php) or by purchasing [the full version](https://play.google.com/store/apps/details?id=com.sovworks.eds.android).

## This fork

An unofficial update of EDS Lite 2.0.0.237 (2020), not affiliated with sovworks. It brings the app to current Android and adds read-only access to Linux-encrypted USB drives. Details, test results and open items are in [docs/MODERNIZATION.md](docs/MODERNIZATION.md).

### What's new

- **Android 10 to 17.** Builds with current tooling (targetSdk 37) and handles the behaviour changes that came with it: exported components, immutable PendingIntents, private broadcast receivers, edge-to-edge layout, foreground service type, notification permission.
- **Encrypted USB drives (read-only).** Plug in a USB stick encrypted with LUKS2 (the Linux default since cryptsetup 2.1), choose *Containers → USB drive* in the drawer, and enter the passphrase. EDS talks to the drive directly over USB, without root and without Android mounting it:
  USB mass storage → GPT/MBR partition → LUKS2 (argon2id/argon2i/PBKDF2, aes-xts-plain64) → LVM2 (linear volumes) → ext2/ext3/ext4.
  Unplugging the drive closes the volume and wipes the key.
- **ext2/3/4 inside containers (read-only).** Detected automatically in EDS, VeraCrypt, TrueCrypt and LUKS containers. Symbolic links work and cannot point outside the volume.
- **Security fixes and hardening.** Internal broadcasts can no longer be received by other apps. Screenshots of the app are blocked by default, and password fields are hardened. VeraCrypt passwords of up to 128 bytes work. Two memory-handling bugs in the vendored Argon2 and lwext4 libraries are fixed.

### Requirements and limitations

- Android 10 or newer, and a phone with USB host (OTG) support for USB drives.
- LUKS2, LVM2 and ext4 are **read-only**: EDS never writes to the drive. The USB layer can only send read commands.
- Not supported yet: LUKS1 on USB drives, ciphers other than aes-xts-plain64, LVM volume types other than linear, and the ext4 features `inline_data`, `casefold` and `encrypt`. The ext4 journal is not replayed.
- The volume needs as much RAM as its Argon2 key slot asks for (cryptsetup's default is up to 1 GiB).
- The app ID is still `com.sovworks.edslite`, so this build replaces the Google Play version instead of installing next to it. Uninstall that one first, or install this one in a separate user profile.

## Building

Requirements: JDK 17 or newer (tested with 21), the Android SDK with platform 37, and NDK `29.0.14206865`. Gradle downloads the rest itself; the wrapper uses Gradle 9.9.1.

1. Clone the project and create `local.properties` in its root with `sdk.dir=/path/to/android/sdk`.
2. Build the debug APK:

   ```
   ./gradlew assembleLiteDebug
   ```

   The APK ends up in `app/build/outputs/apk/lite/debug/`.

Debug builds include a diagnostic screen, `UsbProbeActivity`, that reads a USB drive's partitions and LUKS2 header without asking for a passphrase.

## Tests

These desktop tests run on macOS or Linux and need no phone:

- `misc/ext4-test/run.sh`: the ext4 driver, built with AddressSanitizer and UndefinedBehaviorSanitizer, against ext2/3/4 images made by `mke2fs`. Covers sparse files, symlink edge cases, and a read failure injected at every point of a full walk. Needs `e2fsprogs`.
- `misc/usb-test/run.sh`: the USB transport against a simulated drive with injected faults, plus damaged GPT and MBR tables.
- `misc/luks2-test/run.sh`: crypto known-answer tests, header corruption tests, and a full unlock-and-verify run against a real LUKS2 disk.

## License

GPLv2+
