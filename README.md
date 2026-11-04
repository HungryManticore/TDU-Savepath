# TDU save/config folder redirector (ASI)

Runs TDU's user data (`config` + `savegame`) from the game's own installation folder
instead of `%USERPROFILE%\Documents\Test Drive Unlimited`.

Target build analysed: `TestDriveUnlimited.exe`
SHA-256 `1408778de813902587ad83438bce52a606f8895c5d74478762ad1c9cf92d5a96`, x86 PE, image base 0x400000.

## What the exe does (static evidence)

| VA | Evidence |
|----|----------|
| `0x9A4840` | The only save-root initialiser. Calls `SHGetFolderPathA(NULL, 0x8005 /*CSIDL_PERSONAL|CSIDL_FLAG_CREATE*/, token, 0, buf)` at `0x9A4881`, then copies the 23-byte literal `"\Test Drive Unlimited\"` (`0xF06F4C`) onto the end. |
| `0x608DE0` | `void __cdecl SetBaseDir(const char* p)`: `strncpy(g_base, p, 0x1FF)` into global `0xFE8E78`, then forces a trailing `\`. Single caller: `0x9A48AC`. |
| `0x60A1E0` | Save-path builder: `_snprintf(dst, n, "%s%s\%s", g_base /*0xFE8E78*/, "savegame" /*0xEEDE88*/, <profile/slot>)` -> `mov byte [dst+n-1], 0`. |
| `0x607680` | Sibling-folder selector: `strncat(base, {"savegame","marketplace","publisher"}[i])`. |
| `0x607DC0` | Recursive `mkdir -p` helper (`CreateDirectoryA` + `ERROR_ALREADY_EXISTS` check) - it creates the whole redirected tree itself. |

Only two of the nine `SHGetFolderPathA` call sites use `CSIDL_PERSONAL` (`0x9A4881` = save root,
`0x97DA9A` = crash-dump path). The other seven use `0x8023` (`CSIDL_COMMON_APPDATA`) and are untouched.

The exe has **no relocation directory**, so it always loads at 0x400000 and RVAs are stable.

## Two redirect layers

1. `RedirectDocuments=1` - IAT hook on `SHELL32!SHGetFolderPathA` in the exe's import table
   (found by walking the import descriptors, no hardcoded offsets). For `csidl & 0xFF == 5`
   it returns `SaveRoot`.
2. `FlatLayout=1` - 6-byte detour at `RVA 0x208DE0` (`SetBaseDir`) that supplies
   `<SaveRoot>\` instead of the Documents path. Prologue bytes are verified
   (`8B 44 24 04 85 C0`); on any other exe build the detour is skipped.

## Resulting layout

* `FlatLayout=1` (default): `<SaveRoot>\savegame\<profile>\...`, `<SaveRoot>\ProfileList.dat`
* `FlatLayout=0`: `<SaveRoot>\Test Drive Unlimited\savegame\<profile>\...`

## Build

32-bit MSVC (the game is x86). From an *x86 Native Tools Command Prompt*:

```
build.bat
```

## Install

Copy `tdu_savepath.asi` and `tdu_savepath.ini` into the game's `scripts` folder.
`dinput8.dll` in the game root is Ultimate ASI Loader; it loads `scripts\*.asi` from its
DllMain/TLS callback, i.e. before the game's entry point, so the hooks are live before
any path is computed.

## Verify

1. Start the game; on first save the game creates `<SaveRoot>\savegame\...`.
2. `%USERPROFILE%\Documents\Test Drive Unlimited` must not be recreated.
3. If it is, `FlatLayout=0` + `RedirectDocuments=1` still moves the tree
   (that layer needs no exe address at all).

## Caveats

* The game folder must be writable (it is here: `D:\Test Drive Unlimited`).
* `SHGetFolderPathA` also serves the crash-dump path, which then lands in the same tree.
* CD-key / GameSpy reads stay registry-based and are unaffected.
