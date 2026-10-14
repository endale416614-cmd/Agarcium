#pragma once
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <MinHook.h>
#include <iostream>
#include "config.h"
#include "win_hook.h"
#include "winsock_hook.h"
#include "hook.h"
#include "xml_hook.h"
#include "mod_loader.h"
#include "offline_guard.h"

constexpr char CLIENT_LOCALE[] = "en-US";
FILE* fpstdout = stdout;
FILE* fpstderr = stderr;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    auto& loader = ModLoader::Instance();
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        setlocale(LC_ALL, CLIENT_LOCALE);

        config::ParseConfig();

        if (MH_Initialize() != MH_OK)
            return false;

        // Only create the (hidden) console when asked: otherwise every log line costs a write to conhost.
        if (config::EnableConsole && AllocConsole()) {
            AttachConsole(GetCurrentProcessId());
            ShowWindow(GetConsoleWindow(), SW_HIDE);

            // Disable QUICK_EDIT_MODE (this can cause the window to freeze)
            DWORD prev_mode;
            HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
            GetConsoleMode(hConsole, &prev_mode);
            SetConsoleMode(hConsole, prev_mode & ~ENABLE_QUICK_EDIT_MODE);

            // Redirect output streams
            freopen_s(&fpstdout, "CONOUT$", "w", stdout);
            freopen_s(&fpstderr, "CONOUT$", "w", stderr);
        }

        if (config::EnableConsole) {
            SetConsoleTitleA(config::WindowName.c_str());
            ShowWindow(GetConsoleWindow(), SW_RESTORE);
        }

        loader.LoadMods(config::ModsPath);

        // On failure: remove every hook already installed (returning FALSE unloads this DLL, so live hooks would
        // jump into freed memory), then close the game - it must not run without the redirect and offline guard.
        // winsock::Hook succeeds only if at least one complete TCP enforcement layer is active, and
        // offline::Hook only if every DNS/UDP/ConnectEx guard is in place.
        const char* failed = nullptr;
        if (!win::Hook()) failed = "window";
        else if (!winsock::Hook()) failed = "winsock (no TCP enforcement layer could be installed)";
        else if (!offline::Hook()) failed = "internet guard";

        if (failed) {
            std::cerr << "[DllMain] Hook installation failed: " << failed << std::endl;
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            if (!offline::TestNoUI()) {
                MessageBoxA(NULL, "Failed to install the offline client patch (window, winsock or internet guard hooks).", "Error", MB_ICONERROR | MB_OK);
            }
            TerminateProcess(GetCurrentProcess(), 1);
            return FALSE;
        }

        break;
    }

    case DLL_PROCESS_DETACH:
        FreeConsole();
        break;
    }
    return TRUE;
}