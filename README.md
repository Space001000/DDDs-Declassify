# DDDs Declassify

*Declassify your CIAs.* (A CIA is a "CTR Importable Archive"; FBI installs them. This app declassifies them.)

An Android app that decrypts 3DS `.cia` files on-device and exports them as a decrypted
`.cia` or `.cci`, for use with emulators such as Azahar.

- Strips the CIA (AES-CBC) layer and the NCCH (AES-CTR) layer in place
- Supports seeded titles (via `seeddb.bin`) and New 3DS crypto methods
- Batch mode for multiple files
- Shows the game's icon and title before decrypting

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

1. Load `aes_keys.txt`: pick the file, or tap **Find it in a folder** and choose a folder
   (your Azahar/Citra user folder, SD card root, ...). The app searches it for
   `sysdata/aes_keys.txt`, `gm9/out/aes_keys.txt` and similar locations.
2. A seed database (1,861 titles) is built in. Load your own `seeddb.bin` only if a newer seeded title is missing.
3. Pick one or more `.cia` or `.3ds`/`.cci` files and a destination. CIAs can be saved as
   decrypted CIA or converted to CCI (base games only); `.3ds`/`.cci` files are saved as
   decrypted `.3ds`/`.cci`.

Decryption needs free internal storage of roughly twice the input file size.

## Intended use

Use this only with titles you own and have dumped yourself. Do not open issues
asking for keys or game files.

## Building

Open in Android Studio, or run `./gradlew assembleDebug`.
