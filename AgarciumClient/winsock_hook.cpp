#define GLOG_NO_ABBREVIATED_SEVERITIES
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2spi.h>
#include <MSWSock.h>
#include <iostream>
#include <mutex>
#include <atomic>
#include <string>
#include "config.h"
#include "hook.h"
#include "winsock_hook.h"
#include "offline_guard.h"

#pragma comment(lib, "Ws2_32.lib")

#define NEXON_IP_NA		L"23.98.21"  /* Nexon's North America IP pattern to search for upon hook */
#define NEXON_IP_SA		L"52.171.48" /* Nexon's South America IP pattern to search for upon hook */
#define NEXON_IP_EU		L"13.65.17"  /* Nexon's Europe IP pattern to search for upon hook */
#define NULL_IP         L"0.0.0.0"   /* An uninitialized IP argument presents a "null" IP of zero */

namespace winsock {
    namespace {
        // State tracking
        WSPPROC_TABLE g_ProcTable;
        ULONG g_HostAddress;
        ULONG g_RouteAddress;
        std::atomic<bool> g_HookInitialized{ false };
        std::atomic<bool> g_WSPStartupCalled{ false };
        std::atomic<bool> g_WS2HooksInstalled{ false };
        std::mutex g_HookMutex;

        // Define the WSPStartup signature
        using WSPStartup_t = int (WINAPI*)(WORD, LPWSPDATA, LPWSAPROTOCOL_INFOW, WSPUPCALLTABLE, LPWSPPROC_TABLE);
        static WSPStartup_t WSPStartupAddr = nullptr;

        // WS2_32 function pointers for direct API hooking (fallback layer)
        using connect_t = int (WINAPI*)(SOCKET, const sockaddr*, int);
        using WSAConnect_t = int (WINAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
        using getpeername_t = int (WINAPI*)(SOCKET, sockaddr*, int*);

        static connect_t Original_connect = nullptr;
        static WSAConnect_t Original_WSAConnect = nullptr;
        static getpeername_t Original_getpeername = nullptr;

        // Helper: Check if address matches Nexon patterns and should be redirected
        bool ShouldRedirectAddress(const sockaddr* addr, int addrlen, WCHAR* outAddr, DWORD outAddrLen) {
            if (!addr || addrlen < sizeof(sockaddr_in)) return false;

            const sockaddr_in* service = (const sockaddr_in*)addr;
            if (service->sin_family != AF_INET) {
                std::cout << "[Winsock] Non-IPv4 connection (AF=" << service->sin_family << "), skipping redirect" << std::endl;
                return false;
            }

            // Get string representation
            DWORD dwLen = outAddrLen;
            if (WSAAddressToStringW((sockaddr*)addr, addrlen, NULL, outAddr, &dwLen) != 0) {
                // Fallback: build string manually
                swprintf_s(outAddr, outAddrLen, L"%d.%d.%d.%d:%d",
                    service->sin_addr.S_un.S_un_b.s_b1,
                    service->sin_addr.S_un.S_un_b.s_b2,
                    service->sin_addr.S_un.S_un_b.s_b3,
                    service->sin_addr.S_un.S_un_b.s_b4,
                    htons(service->sin_port));
            }

            return (wcsstr(outAddr, NEXON_IP_NA) || wcsstr(outAddr, NEXON_IP_SA) ||
                    wcsstr(outAddr, NEXON_IP_EU) || wcsstr(outAddr, NULL_IP));
        }

        // Helper: Perform the actual redirect
        bool PerformRedirect(sockaddr_in* service, const char* caller) {
            std::cout << "[" << caller << "] Resolving hostname: " << config::HostName << std::endl;

            hostent* he = gethostbyname(config::HostName.c_str());
            if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
                int err = WSAGetLastError();
                std::cerr << "[" << caller << "] ERROR: DNS resolution failed for " << config::HostName << " (error: " << err << ")" << std::endl;
                return false;
            }

            auto routeAddr = (struct in_addr*)he->h_addr_list[0];
            std::cout << "[" << caller << "] " << config::HostName << " resolved to " << inet_ntoa(*routeAddr) << std::endl;

            g_RouteAddress = routeAddr->S_un.S_addr;
            g_HostAddress = service->sin_addr.S_un.S_addr;
            service->sin_addr.S_un.S_addr = g_RouteAddress;
            return true;
        }

        /* Hooks the Winsock Service Provider's Connect function to redirect the host to a new socket */
        int WINAPI WSPConnect_Hook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno) {
            std::cout << "[WSPConnect] Hook called - Socket: " << s << ", namelen: " << namelen << std::endl;

            if (!name) {
                std::cerr << "[WSPConnect] ERROR: sockaddr is NULL!" << std::endl;
                return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
            }

            if (namelen < sizeof(sockaddr_in)) {
                std::cerr << "[WSPConnect] ERROR: namelen too small (" << namelen << " < " << sizeof(sockaddr_in) << ")" << std::endl;
                return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
            }

            sockaddr_in* service = (sockaddr_in*)name;
            unsigned short pPort = htons(service->sin_port);

            std::cout << "[WSPConnect] Address family: " << service->sin_family << ", Port: " << pPort << std::endl;
            std::cout << "[WSPConnect] Raw IP bytes: "
                      << (int)service->sin_addr.S_un.S_un_b.s_b1 << "."
                      << (int)service->sin_addr.S_un.S_un_b.s_b2 << "."
                      << (int)service->sin_addr.S_un.S_un_b.s_b3 << "."
                      << (int)service->sin_addr.S_un.S_un_b.s_b4 << std::endl;

            // Retrieve a string buffer of the current socket address (IP)
            WCHAR szAddr[50] = { 0 };
            DWORD dwLen = 50;
            int nRet = WSAAddressToStringW((sockaddr*)name, namelen, NULL, szAddr, &dwLen);
            if (nRet) {
                int wsaError = WSAGetLastError();
                std::cerr << "[WSPConnect] WSAAddressToStringW failed with error: " << wsaError << std::endl;

                if (!pPort) {
                    std::cerr << "[WSPConnect] No port specified, returning error" << std::endl;
                    return nRet;
                }

                std::cout << "[WSPConnect] Socket redirection falling back to " << config::HostName << std::endl;
            } else {
                std::wcout << L"[WSPConnect] Parsed address: " << szAddr << std::endl;
            }

            bool matchNA = wcsstr(szAddr, NEXON_IP_NA) != nullptr;
            bool matchSA = wcsstr(szAddr, NEXON_IP_SA) != nullptr;
            bool matchEU = wcsstr(szAddr, NEXON_IP_EU) != nullptr;
            bool matchNull = wcsstr(szAddr, NULL_IP) != nullptr;

            std::cout << "[WSPConnect] Pattern match - NA: " << matchNA << ", SA: " << matchSA
                      << ", EU: " << matchEU << ", NULL: " << matchNull << std::endl;

            if (matchNA || matchSA || matchEU || matchNull) {
                std::wcout << L"[WSPConnect] Redirecting from: " << szAddr << std::endl;
                std::cout << "[WSPConnect] Resolving hostname: " << config::HostName << std::endl;

                hostent* he = gethostbyname(config::HostName.c_str()); // Resolve DNS
                if (!he) {
                    int nRet = WSAGetLastError();
                    std::cerr << "[WSPConnect] ERROR: Unable to resolve " << config::HostName << " with error: " << nRet << std::endl;
                    return nRet;
                }

                if (!he->h_addr_list || !he->h_addr_list[0]) {
                    std::cerr << "[WSPConnect] ERROR: DNS resolved but no addresses returned!" << std::endl;
                    return WSAHOST_NOT_FOUND;
                }

                auto routeAddr = (struct in_addr*)he->h_addr_list[0];
                std::cout << "[WSPConnect] " << config::HostName << " resolved to " << inet_ntoa(*routeAddr) << std::endl;
                g_RouteAddress = routeAddr->S_un.S_addr;
                g_HostAddress = service->sin_addr.S_un.S_addr;
                service->sin_addr.S_un.S_addr = g_RouteAddress;
            } else {
                std::wcout << L"[WSPConnect] No pattern match for address: " << szAddr << L" - passing through without redirect" << std::endl;
            }

            if (!offline::AllowAddress(name, namelen, "WSPConnect")) {
                if (lpErrno) *lpErrno = WSAENETUNREACH;
                return SOCKET_ERROR;
            }

            std::cout << "[WSPConnect] Connecting to " << inet_ntoa(service->sin_addr) << ":" << pPort << std::endl;

            int result = g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
            if (result == SOCKET_ERROR && lpErrno) {
                std::cerr << "[WSPConnect] Connection failed with error: " << *lpErrno << std::endl;
            } else {
                std::cout << "[WSPConnect] Connection initiated successfully" << std::endl;
            }

            return result;
        }

        /* Hooks the Winsock Service Provider's GetPeerName function to pretend to be connected to the host */
        int WINAPI WSPGetPeerName_Hook(SOCKET s, sockaddr* name, LPINT namelen, LPINT lpErrno) {
            std::cout << "[WSPGetPeerName] Hook called - Socket: " << s << std::endl;

            int nRet = g_ProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);
            if (nRet == SOCKET_ERROR) {
                std::cerr << "[WSPGetPeerName] Failed with error: " << (lpErrno ? *lpErrno : -1) << std::endl;
                return nRet;
            }

            sockaddr_in* service = reinterpret_cast<sockaddr_in*>(name);
            std::cout << "[WSPGetPeerName] Peer address: " << inet_ntoa(service->sin_addr) << std::endl;

            // Check if the returned address is the routed address
            if (service->sin_addr.S_un.S_addr == g_HostAddress) {
                std::cout << "[WSPGetPeerName] Swapping host address to route address" << std::endl;
                // Return the socket address back to the host address
                service->sin_addr.S_un.S_addr = g_RouteAddress;
            }

            return 0;
        }
    }

    // ============================================================================
    // WS2_32 Direct API Hooks (Fallback Layer)
    // These hooks catch connections that bypass the WSP layer
    // ============================================================================
    namespace ws2_fallback {

        int WINAPI connect_Hook(SOCKET s, const sockaddr* name, int namelen) {
            std::cout << "[WS2_connect] Hook called - Socket: " << s << std::endl;

            if (name && namelen >= sizeof(sockaddr_in)) {
                WCHAR szAddr[50] = { 0 };
                sockaddr_in* service = (sockaddr_in*)name;
                unsigned short port = htons(service->sin_port);

                std::cout << "[WS2_connect] Attempting connection to "
                          << inet_ntoa(service->sin_addr) << ":" << port << std::endl;

                if (ShouldRedirectAddress(name, namelen, szAddr, 50)) {
                    std::wcout << L"[WS2_connect] Redirecting from: " << szAddr << std::endl;
                    if (PerformRedirect(service, "WS2_connect")) {
                        std::cout << "[WS2_connect] Redirected to " << inet_ntoa(service->sin_addr) << ":" << port << std::endl;
                    }
                }
            }

            if (!offline::AllowAddress(name, namelen, "connect")) {
                WSASetLastError(WSAENETUNREACH);
                return SOCKET_ERROR;
            }

            return Original_connect(s, name, namelen);
        }

        int WINAPI WSAConnect_Hook(SOCKET s, const sockaddr* name, int namelen,
                                   LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                                   LPQOS lpSQOS, LPQOS lpGQOS) {
            std::cout << "[WS2_WSAConnect] Hook called - Socket: " << s << std::endl;

            if (name && namelen >= sizeof(sockaddr_in)) {
                WCHAR szAddr[50] = { 0 };
                sockaddr_in* service = (sockaddr_in*)name;
                unsigned short port = htons(service->sin_port);

                std::cout << "[WS2_WSAConnect] Attempting connection to "
                          << inet_ntoa(service->sin_addr) << ":" << port << std::endl;

                if (ShouldRedirectAddress(name, namelen, szAddr, 50)) {
                    std::wcout << L"[WS2_WSAConnect] Redirecting from: " << szAddr << std::endl;
                    if (PerformRedirect(service, "WS2_WSAConnect")) {
                        std::cout << "[WS2_WSAConnect] Redirected to " << inet_ntoa(service->sin_addr) << ":" << port << std::endl;
                    }
                }
            }

            if (!offline::AllowAddress(name, namelen, "WSAConnect")) {
                WSASetLastError(WSAENETUNREACH);
                return SOCKET_ERROR;
            }

            return Original_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
        }

        int WINAPI getpeername_Hook(SOCKET s, sockaddr* name, int* namelen) {
            int result = Original_getpeername(s, name, namelen);

            if (result == 0 && name && namelen && *namelen >= sizeof(sockaddr_in)) {
                sockaddr_in* service = (sockaddr_in*)name;
                if (service->sin_addr.S_un.S_addr == g_HostAddress) {
                    std::cout << "[WS2_getpeername] Swapping host address to route address" << std::endl;
                    service->sin_addr.S_un.S_addr = g_RouteAddress;
                }
            }

            return result;
        }

        // Hooks one WS2_32 export. True only if the hook is created AND enabled.
        template <typename T>
        bool HookExport(HMODULE module, const char* name, T detour, T* original) {
            FARPROC target = GetProcAddress(module, name);
            if (!target) {
                std::cerr << "[WS2Hooks] " << name << " export not found" << std::endl;
                return false;
            }
            MH_STATUS status = MH_CreateHook(target, reinterpret_cast<LPVOID>(detour), reinterpret_cast<LPVOID*>(original));
            if (status != MH_OK) {
                std::cerr << "[WS2Hooks] Failed to hook " << name << ": " << MH_StatusToString(status) << std::endl;
                return false;
            }
            status = MH_EnableHook(target);
            if (status != MH_OK) {
                std::cerr << "[WS2Hooks] Failed to enable " << name << " hook: " << MH_StatusToString(status) << std::endl;
                return false;
            }
            std::cout << "[WS2Hooks] " << name << " hook installed" << std::endl;
            return true;
        }

        // Enforcement layer "ws2": the layer is complete only if BOTH connect and WSAConnect are hooked and enabled
        // (they are the two TCP connect entry points of WS2_32 and both run offline::AllowAddress).
        // getpeername only restores the original peer address for the redirect; its failure does not weaken
        // enforcement, so it is logged but does not count against the layer.
        BOOL InstallWS2Hooks() {
            std::lock_guard<std::mutex> lock(g_HookMutex);

            if (g_WS2HooksInstalled.load()) {
                std::cout << "[WS2Hooks] Already installed, skipping" << std::endl;
                return TRUE;
            }

            if (offline::TestForcedFail("ws2")) {
                std::cerr << "[WS2Hooks] (test) forced failure of the ws2 layer" << std::endl;
                return FALSE;
            }

            std::cout << "[WS2Hooks] Installing WS2_32 direct API hooks..." << std::endl;

            HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
            if (!hWs2) {
                hWs2 = LoadLibraryA("WS2_32.dll");
            }

            if (!hWs2) {
                std::cerr << "[WS2Hooks] ERROR: Failed to get WS2_32.dll handle" << std::endl;
                return FALSE;
            }

            bool connectOk = HookExport(hWs2, "connect", connect_Hook, &Original_connect);
            bool wsaConnectOk = HookExport(hWs2, "WSAConnect", WSAConnect_Hook, &Original_WSAConnect);
            bool peerNameOk = HookExport(hWs2, "getpeername", getpeername_Hook, &Original_getpeername);
            if (!peerNameOk) {
                std::cerr << "[WS2Hooks] WARNING: getpeername not hooked (enforcement unaffected)" << std::endl;
            }

            bool layerOk = connectOk && wsaConnectOk;
            g_WS2HooksInstalled.store(layerOk);
            std::cout << "[WS2Hooks] WS2_32 connect layer " << (layerOk ? "complete" : "INCOMPLETE") << std::endl;
            return layerOk ? TRUE : FALSE;
        }
    }

    // Enforcement layer "wsp": WSPStartup of the MSAFD provider is hooked so that every provider's WSPConnect goes
    // through WSPConnect_Hook. The layer is complete only if the hook is created AND enabled, and WSPStartup
    // has not run yet. MSWSOCK.dll is loaded when the first socket is created, which is also when the provider
    // starts, so an already-loaded MSWSOCK.dll means the hook would never fire and the layer cannot be counted.
    static bool InstallWspLayer(bool providersAlreadyLoaded) {
        if (offline::TestForcedFail("wsp")) {
            std::cerr << "[WinsockHook] (test) forced failure of the wsp layer" << std::endl;
            return false;
        }
        if (providersAlreadyLoaded) {
            std::cerr << "[WinsockHook] WSP layer unusable: MSWSOCK.dll was loaded before the hook (WSPStartup already ran)" << std::endl;
            return false;
        }

        static decltype(&WSPStartup) _WSPStartup = nullptr;
        WSPStartupAddr = (WSPStartup_t)hook::GetFuncAddress("MSWSOCK", "WSPStartup");
        if (!WSPStartupAddr) {
            std::cerr << "[WinsockHook] WSP layer unusable: WSPStartup not found in MSWSOCK.dll" << std::endl;
            return false;
        }
        std::cout << "[WinsockHook] WSPStartupAddr: " << (void*)WSPStartupAddr << std::endl;

        decltype(&WSPStartup) Hook = [](WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) -> int {
            std::cout << "[WinsockHook] *** WSPStartup hook triggered! ***" << std::endl;
            std::cout << "[WinsockHook] Version requested: " << LOBYTE(wVersionRequested) << "." << HIBYTE(wVersionRequested) << std::endl;

            if (lpProtocolInfo) {
                std::wcout << L"[WinsockHook] Protocol: " << lpProtocolInfo->szProtocol << std::endl;
                std::cout << "[WinsockHook] Address Family: " << lpProtocolInfo->iAddressFamily
                          << ", Socket Type: " << lpProtocolInfo->iSocketType
                          << ", Protocol: " << lpProtocolInfo->iProtocol << std::endl;
            }

            g_WSPStartupCalled.store(true);

            int ret = _WSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
            if (ret != 0) {
                std::cerr << "[WinsockHook] ERROR: Original WSPStartup failed with: " << ret << std::endl;
                return ret;
            }

            std::cout << "[WinsockHook] Original WSPStartup succeeded, installing WSP Connect/GetPeerName hooks" << std::endl;
            g_ProcTable = *lpProcTable;

            lpProcTable->lpWSPConnect = WSPConnect_Hook;
            lpProcTable->lpWSPGetPeerName = WSPGetPeerName_Hook;
            offline::TestReport("WSP_FIRED", "1");

            std::cout << "[WinsockHook] WSP hooks installed successfully" << std::endl;
            return ret;
        };

        MH_STATUS createStatus = MH_CreateHook(WSPStartupAddr, Hook, reinterpret_cast<void**>(&_WSPStartup));
        if (createStatus != MH_OK) {
            std::cerr << "[WinsockHook] WSP layer unusable: MH_CreateHook for WSPStartup failed: " << MH_StatusToString(createStatus) << std::endl;
            return false;
        }
        MH_STATUS enableStatus = MH_EnableHook(WSPStartupAddr);
        if (enableStatus != MH_OK) {
            std::cerr << "[WinsockHook] WSP layer unusable: MH_EnableHook for WSPStartup failed: " << MH_StatusToString(enableStatus) << std::endl;
            return false;
        }
        std::cout << "[WinsockHook] MH_CreateHook/MH_EnableHook for WSPStartup succeeded" << std::endl;
        return true;
    }

    // Succeeds only if at least one complete TCP enforcement layer is active:
    //   layer "wsp": WSPStartup hook (WSPConnect of every provider), or
    //   layer "ws2": WS2_32 connect + WSAConnect hooks.
    // A false result makes DllMain unhook everything and terminate the process.
    // (ConnectEx, which neither layer sees, is a mandatory part of offline::Hook.)
    BOOL Hook() {
        std::cout << "[WinsockHook] ============================================" << std::endl;
        std::cout << "[WinsockHook] Initializing multi-layer winsock hook..." << std::endl;
        std::cout << "[WinsockHook] Target hostname: " << config::HostName << std::endl;
        std::cout << "[WinsockHook] ============================================" << std::endl;

        // Providers (MSWSOCK.dll) load lazily on the first socket; once loaded, the WSP hook is too late.
        const bool providersAlreadyLoaded = GetModuleHandleA("MSWSOCK.dll") != nullptr;

        // Check if Winsock is already initialized (timing issue detection)
        WSADATA wsaData;
        int wsaInitResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsaInitResult == 0) {
            std::cout << "[WinsockHook] WARNING: Winsock already initialized or just initialized now" << std::endl;
            WSACleanup();
        } else {
            std::cout << "[WinsockHook] Winsock not yet initialized (good for WSP hook)" << std::endl;
        }

        std::cout << "[WinsockHook] Installing layer ws2: WS2_32 connect/WSAConnect hooks..." << std::endl;
        const bool ws2Active = ws2_fallback::InstallWS2Hooks() != FALSE;

        std::cout << "[WinsockHook] Installing layer wsp: WSP hooks..." << std::endl;
        const bool wspActive = InstallWspLayer(providersAlreadyLoaded);

        const bool ok = ws2Active || wspActive;
        g_HookInitialized.store(ok);

        offline::TestReport("WINSOCK", (std::string("wsp=") + (wspActive ? "1" : "0") + " ws2=" + (ws2Active ? "1" : "0")).c_str());

        std::cout << "[WinsockHook] ============================================" << std::endl;
        std::cout << "[WinsockHook] Layer ws2 (WS2_32 connect/WSAConnect): " << (ws2Active ? "ACTIVE" : "FAILED") << std::endl;
        std::cout << "[WinsockHook] Layer wsp (WSPConnect): " << (wspActive ? "READY (activates on first Winsock call)" : "FAILED") << std::endl;
        if (!ok) {
            std::cerr << "[WinsockHook] ERROR: no TCP enforcement layer is active - refusing to run" << std::endl;
        }
        std::cout << "[WinsockHook] ============================================" << std::endl;
        return ok ? TRUE : FALSE;
    }
}
