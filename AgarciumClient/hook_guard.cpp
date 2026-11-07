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

	namespace {
		// The crash line is written inside a crashing process, whose heap and CRT locks may be held: only a stack buffer and
		// wsprintfA, then CreateFileW/WriteFile/CloseHandle on the path found at install. The log is not held open between
		// crashes: a held FILE_APPEND_DATA handle makes hook_guard::Log's fopen fail with a sharing violation (its blocked
		// and REFUSED lines would stop), so the file is opened only here, once.
		wchar_t g_CrashLogPath[MAX_PATH] = { 0 };
		LONG g_CrashLogged = 0;
		LPTOP_LEVEL_EXCEPTION_FILTER g_NextFilter = nullptr;

		void WriteCrashLine(const EXCEPTION_RECORD& record) {
			char line[256];
			SYSTEMTIME now;
			GetLocalTime(&now);
			int length = wsprintfA(line, "%04u-%02u-%02u %02u:%02u:%02u crash: exception 0x%08lX", now.wYear, now.wMonth, now.wDay,
				now.wHour, now.wMinute, now.wSecond, record.ExceptionCode);
			if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && record.NumberParameters >= 2) {
				ULONG_PTR kind = record.ExceptionInformation[0], address = record.ExceptionInformation[1];
				length += wsprintfA(line + length, " (%s of 0x%08lX%08lX)", kind == 8 ? "execute" : kind == 1 ? "write" : "read",
					static_cast<DWORD>(address >> 32), static_cast<DWORD>(address));
			}
			auto at = reinterpret_cast<ULONG_PTR>(record.ExceptionAddress);
			HMODULE module = nullptr;
			wchar_t path[MAX_PATH];
			DWORD pathLength = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCWSTR>(record.ExceptionAddress), &module) ? GetModuleFileNameW(module, path, MAX_PATH) : 0;
			if (pathLength > 0 && pathLength < MAX_PATH) {
				DWORD start = 0;
				for (DWORD i = 0; i < pathLength; i++) {
					if (path[i] == L'\\' || path[i] == L'/') {
						start = i + 1;
					}
				}
				char name[64];
				int n = 0;
				for (DWORD i = start; i < pathLength && n < 63; i++) {
					name[n++] = path[i] < 0x80 ? static_cast<char>(path[i]) : '?';
				}
				name[n] = '\0';
				length += wsprintfA(line + length, " at %s+0x%lx", name, static_cast<DWORD>(at - reinterpret_cast<ULONG_PTR>(module)));
			} else {
				length += wsprintfA(line + length, " at 0x%08lX%08lX", static_cast<DWORD>(at >> 32), static_cast<DWORD>(at));
			}
			// CRLF, as the CRT's text mode writes the log's other lines.
			length += wsprintfA(line + length, ", thread %lu\r\n", GetCurrentThreadId());
			HANDLE file = CreateFileW(g_CrashLogPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (file != INVALID_HANDLE_VALUE) {
				DWORD written = 0;
				WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr);
				CloseHandle(file);
			}
		}

		// TODO(BT-217): no line when something ends the process before the top-level filter runs (a vectored handler, which
		// the game's crash reporter can add, or a fail-fast); add a vectored handler of our own if reports come without a line.
		LONG WINAPI CrashFilter(EXCEPTION_POINTERS* pointers) {
			// Once per process. A stack overflow has no stack left for the line, and its exit code already names it.
			if (g_CrashLogPath[0] && pointers && pointers->ExceptionRecord &&
					pointers->ExceptionRecord->ExceptionCode != EXCEPTION_STACK_OVERFLOW && InterlockedExchange(&g_CrashLogged, 1) == 0) {
				WriteCrashLine(*pointers->ExceptionRecord);
			}
			LPTOP_LEVEL_EXCEPTION_FILTER next = g_NextFilter;
			return next ? next(pointers) : EXCEPTION_CONTINUE_SEARCH;
		}

		// A filter set after ours is called next, and its caller gets the one before it back: ours stays in front.
		LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter_Hook(LPTOP_LEVEL_EXCEPTION_FILTER filter) {
			return reinterpret_cast<LPTOP_LEVEL_EXCEPTION_FILTER>(InterlockedExchangePointer(
				reinterpret_cast<PVOID volatile*>(&g_NextFilter), reinterpret_cast<PVOID>(filter)));
		}
	}

	void InstallCrashLog() {
		wchar_t path[MAX_PATH] = { 0 };
		HMODULE self = GetModuleHandleW(L"AgarciumClient.dll");
		DWORD length = self ? GetModuleFileNameW(self, path, MAX_PATH) : 0;
		if (length > 0 && length < MAX_PATH) {
			std::wstring logPath(path, length);
			logPath = logPath.substr(0, logPath.find_last_of(L"\\/") + 1) + L"offline_guard.log";
			if (logPath.size() < MAX_PATH) {
				wcscpy_s(g_CrashLogPath, logPath.c_str());
			}
		}
		// Ours first, keeping the filter set before it; then the hook on KernelBase's, which kernel32's jumps to.
		g_NextFilter = SetUnhandledExceptionFilter(&CrashFilter);
		HMODULE kernelBase = GetModuleHandleW(L"KernelBase.dll");
		FARPROC target = kernelBase ? GetProcAddress(kernelBase, "SetUnhandledExceptionFilter") : nullptr;
		if (!target) {
			target = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetUnhandledExceptionFilter");
		}
		Install("crash/SetUnhandledExceptionFilter", reinterpret_cast<LPVOID>(target),
			reinterpret_cast<LPVOID>(&SetUnhandledExceptionFilter_Hook), nullptr);
	}
}
