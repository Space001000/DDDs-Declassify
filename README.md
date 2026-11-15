# DDDs Declassify

*Declassify your CIAs.*

An Android app that decrypts 3DS games on-device, for use with emulators such as Azahar.

- Decrypts `.cia` files (to decrypted CIA, or CCI for base games) and `.3ds`/`.cci` cartridge images
- Supports seeded titles and New 3DS crypto; a seed database is built in
- Batch mode, with output files named after the game's own title
- Updates and DLC get their own names, so they never overwrite the base game

## Keys are not included

This app ships **no** encryption keys. You must provide an `aes_keys.txt` dumped from
**your own** console (for example with GodMode9). It uses the same format as Citra/Azahar:

```
generator=...
slot0x2CKeyX=...
slot0x25KeyX=...
slot0x18KeyX=...
slot0x1BKeyX=...
slot0x3DKeyX=...
common0=...
common1=...
```

`generator` and `slot0x2CKeyX` are always required. `slot0x3DKeyX` + `commonN` are needed
for CIAs whose contents are encrypted with a title key.

## Usage

1. Load `aes_keys.txt`, in one of three ways:
   - **Find keys automatically**: allow file access once, and the app checks `Download/`,
     `Azahar/sysdata/`, `citra-emu/sysdata/`, `gm9/out/` and SD cards each time it opens.
   - **Search a folder instead**: pick a folder and the app searches it (no extra permission).
   - Tap **Crypto Keys** and pick the file directly.
2. Optionally load your own `seeddb.bin` if a newer seeded title is missing from the built-in one.
3. Pick one or more `.cia`, `.3ds` or `.cci` files and a destination.

Decrypting a CIA needs free internal storage of about twice the file size; a `.3ds` about once.

## Intended use

Use this only with titles you own and have dumped yourself. Do not open issues
asking for keys or game files.

## References

File formats and crypto are documented on [3dbrew](https://www.3dbrew.org/); Project_CTR's
ctrtool and makerom were used as format references.

## Building

Open in Android Studio, or run `./gradlew assembleDebug`. Unit tests: `./gradlew testDebugUnitTest`.
