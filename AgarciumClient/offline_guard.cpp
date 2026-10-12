#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <WinDNS.h>
#include <MinHook.h>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include "offline_guard.h"

#pragma comment(lib, "Ws2_32.lib")

namespace offline {
	namespace {
		std::mutex g_LogMutex;
		std::set<std::string> g_Logged;

		void Log(const std::string& what) {
			std::lock_guard<std::mutex> lock(g_LogMutex);
			if (!g_Logged.insert(what).second) {
				return; // each blocked destination is logged once
			}
			std::cout << "[Offline] Blocked " << what << std::endl;

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
				fprintf(file, "%04d-%02d-%02d %02d:%02d:%02d blocked %s\n",
					now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, what.c_str());
				fclose(file);
			}
		}

		std::string Describe(const sockaddr* addr, int addrlen) {
			char text[INET6_ADDRSTRLEN + 16] = { 0 };
			DWORD length = sizeof(text);
			if (WSAAddressToStringA(const_cast<sockaddr*>(addr), addrlen, nullptr, text, &length) == 0) {
				return text;
			}
			return "address family " + std::to_string(addr->sa_family);
		}

		bool IsLocalAddress(const sockaddr* addr, int addrlen) {
			switch (addr->sa_family) {
			case AF_UNSPEC: // UDP "disconnect"
			case AF_UNIX:
				return true;
			case AF_INET:
				return addrlen >= (int)sizeof(sockaddr_in) &&
					reinterpret_cast<const sockaddr_in*>(addr)->sin_addr.S_un.S_un_b.s_b1 == 127;
			case AF_INET6: {
				if (addrlen < (int)sizeof(sockaddr_in6)) {
					return false;
				}
				const in6_addr& ip = reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr;
				if (IN6_IS_ADDR_LOOPBACK(&ip)) {
					return true;
				}
				return IN6_IS_ADDR_V4MAPPED(&ip) && ip.u.Byte[12] == 127;
			}
			default:
				return false;
			}
		}

		// Names that never need a DNS server: localhost and literal IP addresses.
		bool IsLocalName(const std::string& name) {
			if (name.empty()) {
				return true;
			}
			std::string lower;
			for (char c : name) {
				lower += (char)tolower((unsigned char)c);
			}
			if (lower == "localhost" || (lower.size() > 10 && lower.compare(lower.size() - 10, 10, ".localhost") == 0)) {
				return true;
			}
			in_addr v4;
			in6_addr v6;
			return inet_pton(AF_INET, name.c_str(), &v4) == 1 || inet_pton(AF_INET6, name.c_str(), &v6) == 1;
		}

		std::string Narrow(const wchar_t* text) {
			if (!text) {
				return std::string();
			}
			int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
			std::string result(size > 0 ? size - 1 : 0, '\0');
			if (size > 1) {
				WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), size, nullptr, nullptr);
			}
			return result;
		}

		bool AllowName(const std::string& name, const char* via) {
			if (IsLocalName(name)) {
				return true;
			}
			Log(std::string("DNS lookup ") + name + " (" + via + ")");
			return false;
		}

		// ---- DNS ----
		decltype(&getaddrinfo) Original_getaddrinfo = nullptr;
		decltype(&GetAddrInfoW) Original_GetAddrInfoW = nullptr;
		decltype(&GetAddrInfoExW) Original_GetAddrInfoExW = nullptr;
		decltype(&gethostbyname) Original_gethostbyname = nullptr;
		decltype(&DnsQuery_A) Original_DnsQuery_A = nullptr;
		decltype(&DnsQuery_W) Original_DnsQuery_W = nullptr;
		decltype(&DnsQuery_UTF8) Original_DnsQuery_UTF8 = nullptr;
		decltype(&DnsQueryEx) Original_DnsQueryEx = nullptr;

		INT WSAAPI getaddrinfo_Hook(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result) {
			if (node && !AllowName(node, "getaddrinfo")) {
				return WSAHOST_NOT_FOUND;
			}
			return Original_getaddrinfo(node, service, hints, result);
		}

		INT WSAAPI GetAddrInfoW_Hook(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result) {
			if (node && !AllowName(Narrow(node), "GetAddrInfoW")) {
				return WSAHOST_NOT_FOUND;
			}
			return Original_GetAddrInfoW(node, service, hints, result);
		}

		INT WSAAPI GetAddrInfoExW_Hook(PCWSTR name, PCWSTR service, DWORD nameSpace, LPGUID nspId,
				const ADDRINFOEXW* hints, PADDRINFOEXW* result, timeval* timeout, LPOVERLAPPED overlapped,
				LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE handle) {
			if (name && !AllowName(Narrow(name), "GetAddrInfoExW")) {
				return WSAHOST_NOT_FOUND;
			}
			return Original_GetAddrInfoExW(name, service, nameSpace, nspId, hints, result, timeout, overlapped, completion, handle);
		}

		hostent* WSAAPI gethostbyname_Hook(const char* name) {
			if (name && !AllowName(name, "gethostbyname")) {
				WSASetLastError(WSAHOST_NOT_FOUND);
				return nullptr;
			}
			return Original_gethostbyname(name);
		}

		DNS_STATUS WINAPI DnsQuery_A_Hook(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD* results, PVOID* reserved) {
			if (name && !AllowName(name, "DnsQuery_A")) {
				return DNS_ERROR_RCODE_NAME_ERROR;
			}
			return Original_DnsQuery_A(name, type, options, extra, results, reserved);
		}

		DNS_STATUS WINAPI DnsQuery_W_Hook(PCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD* results, PVOID* reserved) {
			if (name && !AllowName(Narrow(name), "DnsQuery_W")) {
				return DNS_ERROR_RCODE_NAME_ERROR;
			}
			return Original_DnsQuery_W(name, type, options, extra, results, reserved);
		}

		DNS_STATUS WINAPI DnsQuery_UTF8_Hook(PCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORD* results, PVOID* reserved) {
			if (name && !AllowName(name, "DnsQuery_UTF8")) {
				return DNS_ERROR_RCODE_NAME_ERROR;
			}
			return Original_DnsQuery_UTF8(name, type, options, extra, results, reserved);
		}

		DNS_STATUS WINAPI DnsQueryEx_Hook(PDNS_QUERY_REQUEST request, PDNS_QUERY_RESULT result, PDNS_QUERY_CANCEL cancel) {
			if (request && request->QueryName && !AllowName(Narrow(request->QueryName), "DnsQueryEx")) {
				return DNS_ERROR_RCODE_NAME_ERROR;
			}
			return Original_DnsQueryEx(request, result, cancel);
		}

		// ---- UDP ----
		decltype(&sendto) Original_sendto = nullptr;
		decltype(&WSASendTo) Original_WSASendTo = nullptr;

		int WSAAPI sendto_Hook(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
			if (to && !AllowAddress(to, tolen, "sendto")) {
				WSASetLastError(WSAENETUNREACH);
				return SOCKET_ERROR;
			}
			return Original_sendto(s, buf, len, flags, to, tolen);
		}

		int WSAAPI WSASendTo_Hook(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags,
				const sockaddr* to, int tolen, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
			if (to && !AllowAddress(to, tolen, "WSASendTo")) {
				WSASetLastError(WSAENETUNREACH);
				return SOCKET_ERROR;
			}
			return Original_WSASendTo(s, buffers, count, sent, flags, to, tolen, overlapped, completion);
		}

		// ---- ConnectEx (async connects used by WinHTTP / Chromium) ----
		decltype(&WSAIoctl) Original_WSAIoctl = nullptr;
		LPFN_CONNECTEX Original_ConnectEx = nullptr;

		BOOL PASCAL ConnectEx_Hook(SOCKET s, const sockaddr* name, int namelen, PVOID sendBuffer, DWORD sendLength,
				LPDWORD sent, LPOVERLAPPED overlapped) {
			if (name && !AllowAddress(name, namelen, "ConnectEx")) {
				WSASetLastError(WSAENETUNREACH);
				return FALSE;
			}
			return Original_ConnectEx(s, name, namelen, sendBuffer, sendLength, sent, overlapped);
		}

		int WSAAPI WSAIoctl_Hook(SOCKET s, DWORD code, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize,
				LPDWORD returned, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
			int result = Original_WSAIoctl(s, code, inBuffer, inSize, outBuffer, outSize, returned, overlapped, completion);
			GUID connectEx = WSAID_CONNECTEX;
			if (result == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && inBuffer && inSize >= sizeof(GUID) &&
					outBuffer && outSize >= sizeof(LPFN_CONNECTEX) && memcmp(inBuffer, &connectEx, sizeof(GUID)) == 0) {
				auto* function = static_cast<LPFN_CONNECTEX*>(outBuffer);
				if (*function != ConnectEx_Hook) {
					// Every provider in practice hands out the same mswsock ConnectEx.
					Original_ConnectEx = *function;
					*function = ConnectEx_Hook;
				}
			}
			return result;
		}

		// ---- Discord Rich Presence (local pipe, but it publishes what you play) ----
		decltype(&CreateFileA) Original_CreateFileA = nullptr;
		decltype(&CreateFileW) Original_CreateFileW = nullptr;

		bool IsDiscordPipe(const std::string& path) {
			std::string lower;
			for (char c : path) {
				lower += (char)tolower((unsigned char)c);
			}
			return lower.find("\\pipe\\discord-ipc-") != std::string::npos;
		}

		HANDLE WINAPI CreateFileA_Hook(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
				DWORD disposition, DWORD flags, HANDLE templateFile) {
			if (name && IsDiscordPipe(name)) {
				Log(std::string("Discord pipe ") + name);
				SetLastError(ERROR_FILE_NOT_FOUND);
				return INVALID_HANDLE_VALUE;
			}
			return Original_CreateFileA(name, access, share, security, disposition, flags, templateFile);
		}

		HANDLE WINAPI CreateFileW_Hook(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
				DWORD disposition, DWORD flags, HANDLE templateFile) {
			if (name && wcsstr(name, L"discord-ipc-") && IsDiscordPipe(Narrow(name))) {
				Log("Discord pipe " + Narrow(name));
				SetLastError(ERROR_FILE_NOT_FOUND);
				return INVALID_HANDLE_VALUE;
			}
			return Original_CreateFileW(name, access, share, security, disposition, flags, templateFile);
		}

		template <typename T>
		bool Install(HMODULE module, const char* function, T hook, T* original) {
			FARPROC target = module ? GetProcAddress(module, function) : nullptr;
			if (!target) {
				std::cerr << "[Offline] " << function << " not found" << std::endl;
				return false;
			}
			if (MH_CreateHook(target, reinterpret_cast<LPVOID>(hook), reinterpret_cast<LPVOID*>(original)) != MH_OK ||
					MH_EnableHook(target) != MH_OK) {
				std::cerr << "[Offline] Failed to hook " << function << std::endl;
				return false;
			}
			return true;
		}
	}

	bool AllowAddress(const sockaddr* addr, int addrlen, const char* via) {
		if (!addr || IsLocalAddress(addr, addrlen)) {
			return true;
		}
		Log(Describe(addr, addrlen) + " (" + via + ")");
		return false;
	}

	bool Hook() {
		HMODULE ws2 = LoadLibraryA("WS2_32.dll");
		HMODULE dns = LoadLibraryA("DNSAPI.dll");
		HMODULE kernel = GetModuleHandleA("KERNELBASE.dll");
		if (!kernel) {
			kernel = GetModuleHandleA("KERNEL32.dll");
		}

		bool ok = true;
		ok &= Install(ws2, "getaddrinfo", &getaddrinfo_Hook, &Original_getaddrinfo);
		ok &= Install(ws2, "GetAddrInfoW", &GetAddrInfoW_Hook, &Original_GetAddrInfoW);
		ok &= Install(ws2, "GetAddrInfoExW", &GetAddrInfoExW_Hook, &Original_GetAddrInfoExW);
		ok &= Install(ws2, "gethostbyname", &gethostbyname_Hook, &Original_gethostbyname);
		ok &= Install(ws2, "sendto", &sendto_Hook, &Original_sendto);
		ok &= Install(ws2, "WSASendTo", &WSASendTo_Hook, &Original_WSASendTo);
		ok &= Install(ws2, "WSAIoctl", &WSAIoctl_Hook, &Original_WSAIoctl);
		ok &= Install(dns, "DnsQuery_A", &DnsQuery_A_Hook, &Original_DnsQuery_A);
		ok &= Install(dns, "DnsQuery_W", &DnsQuery_W_Hook, &Original_DnsQuery_W);
		ok &= Install(dns, "DnsQuery_UTF8", &DnsQuery_UTF8_Hook, &Original_DnsQuery_UTF8);
		Install(dns, "DnsQueryEx", &DnsQueryEx_Hook, &Original_DnsQueryEx); // absent on very old Windows
		ok &= Install(kernel, "CreateFileA", &CreateFileA_Hook, &Original_CreateFileA);
		ok &= Install(kernel, "CreateFileW", &CreateFileW_Hook, &Original_CreateFileW);

		std::cout << "[Offline] Internet guard " << (ok ? "active" : "partially active") << std::endl;
		return ok;
	}
}
