#pragma once
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <cstdint>
#include <string>

// Refuses game hooks on a client they were not written for, and logs every hook to offline_guard.log (next to
// AgarciumClient.dll; Export Diagnostics includes it), one line each:
//   hook <layer>/<name> INSTALLED
//   hook <layer>/<name> REFUSED: <reason>
namespace hook_guard {
	// PE header of the Global Steam x64 MapleStory2.exe that every game address in this patch belongs to.
	constexpr DWORD GameTimeDateStamp = 0x5e6f5807;
	constexpr DWORD GameSizeOfImage = 0x2d84000;
	// Bytes hashed (32-bit FNV-1a) at a game-code address before it is patched. The exe on disk is packed, so the
	// expected hashes are read from the unpacked code in memory, just before the patch runs (Frida, read only).
	constexpr size_t GuardBytes = 16;

	// Appends one time-stamped line to offline_guard.log.
	void Log(const std::string& line);

	// Logs INSTALLED if ok, else REFUSED with the reason. Returns ok.
	bool Report(const char* name, bool ok, const std::string& reason = "");

	// True if the running exe is the client above; logs REFUSED for name otherwise. For game data.
	bool CheckGameExe(const char* name);

	// CheckGameExe, and the GuardBytes bytes at address must hash to fnv; logs REFUSED for name otherwise.
	// For game code.
	bool CheckGameCode(const char* name, uintptr_t address, uint32_t fnv);

	// MH_CreateHook + MH_EnableHook; logs the result for name.
	bool Install(const char* name, LPVOID target, LPVOID detour, LPVOID* original);
}
