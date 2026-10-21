#include "hook_guard.h"
#include <MinHook.h>
#include <cstdio>
#include <iostream>
#include <mutex>

namespace hook_guard {
	namespace {
		std::string Hex(uint64_t value) {
			char text[24];
			snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
			return text;
		}

		uint32_t Fnv1a(const BYTE* bytes, size_t length) {
			uint32_t hash = 0x811c9dc5;
			for (size_t i = 0; i < length; i++) {
				hash = (hash ^ bytes[i]) * 0x01000193;
			}
			return hash;
		}

		// Empty if the running exe is the expected client, else why not. Read once: the header does not change.
		const std::string& ExeMismatch() {
			static const std::string reason = [] {
				auto base = reinterpret_cast<const BYTE*>(GetModuleHandleA(nullptr));
				auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
				if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) {
					return std::string("exe has no PE header");
				}
				auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
				if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
					return std::string("exe has no PE32+ header");
				}
				DWORD stamp = nt->FileHeader.TimeDateStamp, size = nt->OptionalHeader.SizeOfImage;
				if (stamp == GameTimeDateStamp && size == GameSizeOfImage) {
					return std::string();
				}
				return "exe TimeDateStamp " + Hex(stamp) + " SizeOfImage " + Hex(size) + ", expected " +
					Hex(GameTimeDateStamp) + " " + Hex(GameSizeOfImage);
			}();
			return reason;
		}
	}

	void Log(const std::string& line) {
		static std::mutex mutex;
		std::lock_guard<std::mutex> lock(mutex);

		char path[MAX_PATH] = { 0 };
		HMODULE self = GetModuleHandleA("AgarciumClient.dll");
		if (!self || !GetModuleFileNameA(self, path, MAX_PATH)) {
			return;
		}
		std::string logPath(path);
		logPath = logPath.substr(0, logPath.find_last_of("\\/") + 1) + "offline_guard.log";

		FILE* file = nullptr;
		if (fopen_s(&file, logPath.c_str(), "a") == 0 && file) {
			SYSTEMTIME now;
			GetLocalTime(&now);
			fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d %s\n",
				now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, line.c_str());
			fclose(file);
		}
	}

	bool Report(const char* name, bool ok, const std::string& reason) {
		std::string line = std::string("hook ") + name + (ok ? " INSTALLED" : " REFUSED: " + reason);
		(ok ? std::cout : std::cerr) << "[Hook] " << line << std::endl;
		Log(line);
		return ok;
	}

	bool CheckGameExe(const char* name) {
		return ExeMismatch().empty() || Report(name, false, ExeMismatch());
	}

	bool CheckGameCode(const char* name, uintptr_t address, uint32_t fnv) {
		if (!CheckGameExe(name)) {
			return false;
		}
		// Safe to read: the exe is the expected one, so the address lies inside its image.
		uint32_t actual = Fnv1a(reinterpret_cast<const BYTE*>(address), GuardBytes);
		return actual == fnv || Report(name, false, "code at " + Hex(address) +
			" has fnv1a " + Hex(actual) + ", expected " + Hex(fnv));
	}

	bool Install(const char* name, LPVOID target, LPVOID detour, LPVOID* original) {
		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status == MH_OK) {
			status = MH_EnableHook(target);
		}
		return Report(name, status == MH_OK, std::string("MinHook ") + MH_StatusToString(status));
	}
}
