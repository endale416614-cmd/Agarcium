#include <iostream>
#include "hook.h"
#include "config.h"
#include "cstring_lite.h"
#include <thread>
#include <condition_variable>
#include "xml_hook.h"
#include <MinHook.h>

namespace hook {
	bool WriteBytes(DWORD_PTR dwAddr, const std::vector<BYTE>& bytes) {
		if (dwAddr < PE_START || dwAddr + bytes.size() >= PE_END) {
			return false;
		}

		for (size_t i = 0; i < bytes.size(); i++) {
			*(BYTE*)(dwAddr + i) = bytes[i];
		}
		return true;
	}

	FARPROC GetFuncAddress(LPCSTR lpLibFileName, LPCSTR lpProcName) {
		HMODULE hModule = LoadLibraryA(lpLibFileName);
		if (!hModule) {
			printf("GetFuncAddress, LoadLibraryA error: %lu", GetLastError());
			return FALSE;
		}

		FARPROC funcAddress = GetProcAddress(hModule, lpProcName);
		if (!funcAddress) {
			printf("GetFuncAddress, GetProcAddress error: %lu", GetLastError());
			return FALSE;
		}

		return funcAddress;
	}

	const std::vector<BYTE> intToByteArray(uint32_t num) {
		return {
			static_cast<BYTE>(num & 0xFF),
			static_cast<BYTE>((num >> 8) & 0xFF),
			static_cast<BYTE>((num >> 16) & 0xFF),
			static_cast<BYTE>((num >> 24) & 0xFF)
		};
	}

	bool SetClientPort() {
		if (config::Port < 1024) {
			std::cout << "Unsupported port: " << config::Port << std::endl;
			return false;
		}

		// gConnectPort
		DWORD_PTR dwGlobalConnectPort = 0x1421227d4;
		const std::vector<BYTE> portBytes = intToByteArray(config::Port);
		WriteBytes(dwGlobalConnectPort, portBytes);
		std::cout << "gConnectPort: " << (void*)dwGlobalConnectPort << std::endl;

		return true;
	}

	bool SetLoginUsername() {
		std::cout << "gLoginUsername: " << config::Username << std::endl;

		if (config::Username.empty()) {
			return false;
		}
		// gLoginUsername
		uintptr_t dwGlobalLoginUsername = 0x14210e398;
		auto* username = reinterpret_cast<cstring_lite::CStringA*>(dwGlobalLoginUsername);
		username->SetString(config::Username);

		return true;
	}

	bool SetLoginPassword() {
		if (config::Password.empty()) {
			return false;
		}

		// gLoginPassword
		uintptr_t dwGlobalLoginPassword = 0x14210e3a0;
		auto* password = reinterpret_cast<cstring_lite::CStringA*>(dwGlobalLoginPassword);
		password->SetString(config::Password);

		return true;
	}

	// Define the function type for a void function with no parameters
	typedef void (*InitLoginUI_t)();

	// Original function pointer that will store the trampoline
	static InitLoginUI_t OriginalInitLoginUI = nullptr;

	// The address of the function to hook
	static DWORD_PTR dwInitLoginUI = 0x140e3e630;

	bool AttemptedLogin = false;

	void HookedInitLoginUI() {
		// Call the original function
		OriginalInitLoginUI();

		// Set our username/password
		SetLoginUsername();
		SetLoginPassword();

		if (AttemptedLogin) {
			// Already tried to login, stop us from getting into a loop.
			return;
		}
		AttemptedLogin = true;

		DWORD_PTR dwNetworkServicePtr = 0x14210d360;
		DWORD_PTR dwNetworkServiceLogin = 0x140b5d6e0;

		void* pNetworkService = *reinterpret_cast<void**>(dwNetworkServicePtr);
		typedef void(__thiscall* NetworkServiceLogin_t)(void* thisPtr);

		NetworkServiceLogin_t NetworkServiceLogin = reinterpret_cast<NetworkServiceLogin_t>(dwNetworkServiceLogin);
		NetworkServiceLogin(pNetworkService);
	}

	void LoginHook() {
		MH_STATUS status = MH_CreateHook(
			reinterpret_cast<LPVOID>(dwInitLoginUI),
			reinterpret_cast<LPVOID>(&HookedInitLoginUI),
			reinterpret_cast<LPVOID*>(&OriginalInitLoginUI)
		);

		if (status != MH_OK) {
			std::cerr << "Failed to create InitLoginUI hook. Error code: " << status << std::endl;
			return;
		}

		status = MH_EnableHook(reinterpret_cast<LPVOID>(dwInitLoginUI));

		if (status != MH_OK) {
			std::cerr << "Failed to enable InitLoginUI hook. Error code: " << status << std::endl;
			return;
		}

		std::cout << "UIService::InitLoginUI(): " << (void*)dwInitLoginUI << std::endl;
	}

	bool PatchClient() {
		// CAntiHackManager::InitInstance()
		DWORD_PTR dwBypassNGS = 0x140516b00;
		// CGameApp::IsNXLEnabled()
		DWORD_PTR dwDisableNXL = 0x1403f9650;
		// CCommonString::CheckLocale()
		DWORD_PTR dwLocaleLanguage = 0x140216a20;

		WriteBytes(dwBypassNGS, { 0x33, 0xC0, 0xC3 }); // return 0
		std::cout << "CAntiHackManager::InitInstance(): " << (void*)dwBypassNGS << std::endl;

		WriteBytes(dwDisableNXL, { 0xB8, 0x00, 0x00, 0x00, 0x00 }); // return 0
		std::cout << "CGameApp::IsNXLEnabled(): " << (void*)dwDisableNXL << std::endl;

		WriteBytes(dwLocaleLanguage, { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }); // return 0
		std::cout << "CCommonString::CheckLocale(): " << (void*)dwLocaleLanguage << std::endl;

		SetClientPort();

		if (config::EnableAutoLogin) {
			// note: stops manual input of login fields!
			DWORD_PTR dwUseLoginFields = 0x14210e20b;
			WriteBytes(dwUseLoginFields, { 0x01 });

			LoginHook();
		}

		xml_hook::init();

		return true;
	}
}