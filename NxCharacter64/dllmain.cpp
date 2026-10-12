#include "nxcharacter64.h"
#include <iostream> // For simple logging
#include <string>
#include <shlobj.h> // For PathCombine (optional)

// Define the global function pointers
OriginalNxControllerManagerConstructor0_t OriginalNxControllerManagerConstructor0 = NULL;
OriginalNxControllerManagerConstructor1_t OriginalNxControllerManagerConstructor1 = NULL;
OriginalNxControllerManagerDestructor_t OriginalNxControllerManagerDestructor = NULL;
OriginalNxControllerManagerAssignmentOperator_t OriginalNxControllerManagerAssignmentOperator = NULL;
OriginalNxControllerManagerVTable_t OriginalNxControllerManagerVTable = NULL;

void* (__cdecl *OriginalNxCreateControllerManager)(void* param_1) = NULL;
void (__cdecl *OriginalNxReleaseControllerManager)(void* param_1) = NULL;


// Handle to the original DLL
HMODULE hOriginalDLL = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Load the original DLL
            hOriginalDLL = LoadLibraryA("NxCharacter64.dll.bak");

            if (hOriginalDLL == NULL) {
                std::cerr << "Error: Failed to load original NxCharacter64.dll " << std::endl;
                // Depending on criticality, you might want to exit the process
                // ExitProcess(1);
                return FALSE;
            }

            // Load our custom DLL. It carries the offline guard, so the game must not run without it:
            // it returns FALSE from DllMain (and LoadLibrary fails) if it cannot be set up, and it can be missing.
            if (LoadLibraryA("AgarciumClient.dll") == NULL) {
                MessageBoxA(NULL, "AgarciumClient.dll could not be loaded; the offline client patch is not active.", "Error", MB_ICONERROR | MB_OK);
                TerminateProcess(GetCurrentProcess(), 1);
                return FALSE;
            }

            // Get addresses of the original functions using their mangled names
            OriginalNxControllerManagerConstructor0 = (OriginalNxControllerManagerConstructor0_t)GetProcAddress(hOriginalDLL, "??0NxControllerManager@@IEAA@XZ");
            OriginalNxControllerManagerConstructor1 = (OriginalNxControllerManagerConstructor1_t)GetProcAddress(hOriginalDLL, "??0NxControllerManager@@QEAA@AEBV0@@Z");
            OriginalNxControllerManagerDestructor = (OriginalNxControllerManagerDestructor_t)GetProcAddress(hOriginalDLL, "??1NxControllerManager@@MEAA@XZ");
            OriginalNxControllerManagerAssignmentOperator = (OriginalNxControllerManagerAssignmentOperator_t)GetProcAddress(hOriginalDLL, "??4NxControllerManager@@QEAAAEAV0@AEBV0@@Z");

            // For the vftable, you usually don't get it with GetProcAddress directly.
            // The vftable is part of the class's data layout. You might need to find
            // an instance of the class or analyze its structure to access the vftable pointer.
            // For now, we'll assume we can't directly get the vftable address this way.
            // OriginalNxControllerManagerVTable = (OriginalNxControllerManagerVTable_t)GetProcAddress(hOriginalDLL, "??_7NxControllerManager@@6B@");

            // Get addresses of the original non-mangled functions
            OriginalNxCreateControllerManager = (void* (__cdecl *)(void*))GetProcAddress(hOriginalDLL, "NxCreateControllerManager");
            OriginalNxReleaseControllerManager = (void (__cdecl *)(void*))GetProcAddress(hOriginalDLL, "NxReleaseControllerManager");


            // Check if all required functions were found
            if (!OriginalNxControllerManagerConstructor0 ||
                !OriginalNxControllerManagerConstructor1 ||
                !OriginalNxControllerManagerDestructor ||
                !OriginalNxControllerManagerAssignmentOperator ||
                !OriginalNxCreateControllerManager ||
                !OriginalNxReleaseControllerManager)
            {
                std::cerr << "Error: Failed to find all required functions in original NxCharacter64.dll" << std::endl;
                // You might want to free the library and return FALSE
                FreeLibrary(hOriginalDLL);
                hOriginalDLL = NULL;
                return FALSE;
            }

            std::cout << "Proxy NxCharacter64.dll loaded successfully!" << std::endl;

            break;
        case DLL_PROCESS_DETACH:
            if (hOriginalDLL) {
                FreeLibrary(hOriginalDLL);
                hOriginalDLL = NULL;
                std::cout << "Proxy NxCharacter64.dll unloaded." << std::endl;
            }
            break;
    }
    return TRUE;
}

// --- Proxy Wrapper Implementations ---
void* ProxyNxControllerManagerConstructor0(void* This) {
    std::cout << "Intercepted NxControllerManager Constructor (void)" << std::endl;
    return OriginalNxControllerManagerConstructor0(This);
}

void* ProxyNxControllerManagerConstructor1(void* This, const void* other) {
    std::cout << "Intercepted NxControllerManager Constructor (copy)" << std::endl;
    return OriginalNxControllerManagerConstructor1(This, other);
}

void ProxyNxControllerManagerDestructor(void* This) {
    std::cout << "Intercepted NxControllerManager Destructor" << std::endl;
    OriginalNxControllerManagerDestructor(This);
}

void* ProxyNxControllerManagerAssignmentOperator(void* This, const void* other) {
    std::cout << "Intercepted NxControllerManager Assignment Operator" << std::endl;
    return OriginalNxControllerManagerAssignmentOperator(This, other);
}

// Non-mangled function proxies (these were already correct)
void* __cdecl ProxyNxCreateControllerManager(void* param_1) {
    std::cout << "Intercepted NxCreateControllerManager" << std::endl;
    return OriginalNxCreateControllerManager(param_1);
}

void __cdecl ProxyNxReleaseControllerManager(void* param_1) {
    std::cout << "Intercepted NxReleaseControllerManager" << std::endl;
    OriginalNxReleaseControllerManager(param_1);
}