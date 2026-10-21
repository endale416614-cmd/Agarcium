#include <iostream>
#include <string.h>
#include "config.h"
#include "win_hook.h"
#include "hook.h"
#include "hook_guard.h"

namespace win {
	BOOL Hook_CreateWindowExA(BOOL bEnable) {
		static decltype(&CreateWindowExA) _CreateWindowExA = &CreateWindowExA;

		decltype(&CreateWindowExA) Hook = [](DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam) -> HWND {
			// A class name may be an ATOM (or NULL), not a string.
			if (!config::WindowName.empty() && lpClassName && !IS_INTRESOURCE(lpClassName) && strcmp(lpClassName, CLIENT_CLASS)) {
				lpWindowName = config::WindowName.c_str();
			}

			return _CreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
			};

		return hook_guard::Install("window/CreateWindowExA", &CreateWindowExA, Hook,
			reinterpret_cast<LPVOID*>(&_CreateWindowExA));
	}

	BOOL Hook_CreateMutexA(BOOL bEnable) {
		static decltype(&CreateMutexA) _CreateMutexA = &CreateMutexA;

		decltype(&CreateMutexA) Hook = [](LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) -> HANDLE {
			if (lpName && !strcmp(lpName, MUTLI_MUTEX)) {
				hook::PatchClient();

				if (config::EnableMultiClient) {
					HANDLE hProcHandle = GetCurrentProcess();
					HANDLE hHandle = _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
					if (hProcHandle && hHandle) {
						HANDLE hMaple;
						DuplicateHandle(hProcHandle, hHandle, {}, &hMaple, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);
						CloseHandle(hMaple);
					}

					return hHandle;
				}
			}

			return _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
			};

		return hook_guard::Install("window/CreateMutexA", &CreateMutexA, Hook,
			reinterpret_cast<LPVOID*>(&_CreateMutexA));
	}

	BOOL Hook() {
		BOOL bResult = TRUE;
		bResult &= Hook_CreateWindowExA(TRUE);
		bResult &= Hook_CreateMutexA(TRUE);

		return bResult;
	}
}
