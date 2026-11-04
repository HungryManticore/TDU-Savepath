// tdu_savepath.cpp
// Test Drive Unlimited (1.66A / TestDriveUnlimited.exe, sha256 1408778de813902587ad83438bce52a606f8895c5d74478762ad1c9cf92d5a96)
// ASI plugin: relocate the "%USERPROFILE%\Documents\Test Drive Unlimited" data root
// (config + savegame) into the game's own installation folder.
//
// Build (32-bit!): see build.bat
// Install: put tdu_savepath.asi + tdu_savepath.ini into the game's "scripts" folder.
// (Ultimate ASI Loader is already present as dinput8.dll in this installation.)
//
// How the game resolves the folder (static analysis of the shipped exe):
//   TestDriveUnlimited.exe!0x9A4840  -> SHGetFolderPathA(NULL, 0x8005 /*CSIDL_PERSONAL*/) 
//                                      + "\Test Drive Unlimited\"   (literal @ 0xF06F4C)
//                                      -> setter @ 0x608DE0 stores it in global 0xFE8E78
//   TestDriveUnlimited.exe!0x60A1E0  -> _snprintf(buf, n, "%s%s\%s", g_baseDir /*0xFE8E78*/,
//                                      "savegame" /*0xEEDE88*/, <profile/slot>)
// So the whole user-data tree hangs off one global string, and that string is fed by
// exactly one SHGetFolderPathA(CSIDL_PERSONAL) call site.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef CSIDL_PERSONAL
#define CSIDL_PERSONAL 0x0005
#endif

typedef HRESULT(WINAPI* tSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
typedef void(__cdecl* tSetBaseDir)(const char*);

static HMODULE           g_self = NULL;
static tSHGetFolderPathA g_realSHGetFolderPathA = NULL;
static tSetBaseDir       g_realSetBaseDir = NULL;

static char g_gameDir[MAX_PATH] = { 0 };   // "D:\Test Drive Unlimited"
static char g_root[MAX_PATH] = { 0 };      // redirect target, no trailing backslash
static char g_rootSlash[MAX_PATH] = { 0 }; // redirect target, trailing backslash

static int g_flat = 1;          // 1 = base dir becomes <root>\      -> <root>\savegame\...
                                // 0 = base dir stays <root>\Test Drive Unlimited\ -> <root>\Test Drive Unlimited\savegame\...
static int g_hookDocuments = 1; // 1 = also redirect every SHGetFolderPathA(CSIDL_PERSONAL) caller

// RVA of the base-directory setter inside TestDriveUnlimited.exe for the build above.
// It is the only writer of global 0xFE8E78 and is called from exactly one place (0x9A48AC).
#define RVA_SET_BASE_DIR 0x208DE0u

static unsigned char g_trampoline[32] = { 0 };
static char          g_iniPath[MAX_PATH] = { 0 };

// ---------------------------------------------------------------- utilities
static void TrimTrailingSlashes(char* s)
{
    int n = lstrlenA(s);
    while (n > 3 && (s[n - 1] == '\\' || s[n - 1] == '/')) s[--n] = 0;
}

static void AddTrailingSlash(char* s)
{
    int n = lstrlenA(s);
    if (n > 0 && n < MAX_PATH - 2 && s[n - 1] != '\\' && s[n - 1] != '/') { s[n] = '\\'; s[n + 1] = 0; }
}

static void ResolveGameDir(void)
{
    GetModuleFileNameA(GetModuleHandleA(NULL), g_gameDir, MAX_PATH);
    char* last = NULL;
    for (char* p = g_gameDir; *p; ++p) if (*p == '\\' || *p == '/') last = p;
    if (last) *last = 0;
}

static void LoadConfig(void)
{
    GetModuleFileNameA(g_self, g_iniPath, MAX_PATH);
    char* dot = NULL;
    for (char* p = g_iniPath; *p; ++p) if (*p == '.') dot = p;
    if (dot) lstrcpyA(dot, ".ini");

    char buf[MAX_PATH] = { 0 };
    GetPrivateProfileStringA("TDU", "SaveRoot", "", buf, MAX_PATH, g_iniPath);

    if (buf[0])
    {
        lstrcpynA(g_root, buf, MAX_PATH);
        // allow "%GAME%" / "%GAMEDIR%" placeholders
        char expanded[MAX_PATH] = { 0 };
        if (lstrcmpiA(buf, "%GAME%") == 0 || lstrcmpiA(buf, "%GAMEDIR%") == 0)
        {
            lstrcpynA(expanded, g_gameDir, MAX_PATH);
            lstrcpynA(g_root, expanded, MAX_PATH);
        }
    }
    else
    {
        lstrcpynA(g_root, g_gameDir, MAX_PATH);
    }

    TrimTrailingSlashes(g_root);
    lstrcpynA(g_rootSlash, g_root, MAX_PATH);
    AddTrailingSlash(g_rootSlash);

    g_flat = GetPrivateProfileIntA("TDU", "FlatLayout", 1, g_iniPath) ? 1 : 0;
    g_hookDocuments = GetPrivateProfileIntA("TDU", "RedirectDocuments", 1, g_iniPath) ? 1 : 0;
}

// ------------------------------------------------- SHGetFolderPathA IAT hook
static HRESULT WINAPI HookSHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath)
{
    if (pszPath && ((csidl & 0xFF) == CSIDL_PERSONAL))
    {
        lstrcpynA(pszPath, g_root, MAX_PATH);
        return S_OK;
    }
    if (g_realSHGetFolderPathA) return g_realSHGetFolderPathA(hwnd, csidl, hToken, dwFlags, pszPath);
    return E_FAIL;
}

static void InstallDocumentsHook(void)
{
    BYTE* base = (BYTE*)GetModuleHandleA(NULL);
    if (!base) return;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return;

    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + impRva);
    for (; desc->Name; ++desc)
    {
        const char* dll = (const char*)(base + desc->Name);
        if (lstrcmpiA(dll, "SHELL32.dll") != 0) continue;

        IMAGE_THUNK_DATA* oft = (IMAGE_THUNK_DATA*)(base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        IMAGE_THUNK_DATA* ft = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
        for (; oft->u1.AddressOfData; ++oft, ++ft)
        {
            if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + oft->u1.AddressOfData);
            if (lstrcmpA((const char*)ibn->Name, "SHGetFolderPathA") != 0) continue;
            if (g_realSHGetFolderPathA) continue;

            g_realSHGetFolderPathA = (tSHGetFolderPathA)(uintptr_t)ft->u1.Function;
            DWORD oldProt = 0;
            if (VirtualProtect(&ft->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt))
            {
                ft->u1.Function = (uintptr_t)&HookSHGetFolderPathA;
                VirtualProtect(&ft->u1.Function, sizeof(void*), oldProt, &oldProt);
            }
        }
    }
}

// ---------------------------------------------------- base directory detour
// Original prologue (6 bytes, instruction aligned): mov eax,[esp+4]; test eax,eax
static void __cdecl HookSetBaseDir(const char* gamePath)
{
    (void)gamePath;                          // ignore the Documents-based path
    if (g_realSetBaseDir) g_realSetBaseDir(g_rootSlash);
}

static void InstallBaseDirHook(void)
{
    BYTE* target = (BYTE*)GetModuleHandleA(NULL) + RVA_SET_BASE_DIR;
    static const BYTE expect[6] = { 0x8B, 0x44, 0x24, 0x04, 0x85, 0xC0 };
    if (memcmp(target, expect, 6) != 0) return;   // different exe build: leave it alone

    // --- trampoline: original bytes, then jmp back to target+6
    memcpy(g_trampoline, expect, 6);
    BYTE* t = g_trampoline + 6;
    t[0] = 0xE9;
    *(int*)(t + 1) = (int)((target + 6) - (t + 5));

    DWORD oldProt = 0;
    VirtualProtect(g_trampoline, sizeof(g_trampoline), PAGE_EXECUTE_READWRITE, &oldProt);
    g_realSetBaseDir = (tSetBaseDir)(void*)g_trampoline;

    // --- patch entry: jmp HookSetBaseDir; nop
    if (!VirtualProtect(target, 6, PAGE_EXECUTE_READWRITE, &oldProt)) return;
    target[0] = 0xE9;
    *(int*)(target + 1) = (int)((BYTE*)&HookSetBaseDir - (target + 5));
    target[5] = 0x90;
    VirtualProtect(target, 6, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), target, 6);
}

// -------------------------------------------------------------- entry point
BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(hModule);
    g_self = hModule;

    ResolveGameDir();
    LoadConfig();

    if (g_hookDocuments) InstallDocumentsHook(); // everything that asks for "My Documents"
    if (g_flat)          InstallBaseDirHook();   // exact <root>\ base directory

    CreateDirectoryA(g_root, NULL);
    return TRUE;
}
