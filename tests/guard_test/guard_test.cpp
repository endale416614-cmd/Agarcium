// Fail-closed test for AgarciumClient.dll (offline client patch).
//
//   guard_test.exe <path\to\AgarciumClient.dll>
//
// Runs a series of child processes (this same exe with --child). Each child LoadLibrary's the DLL with a chosen
// set of OFFLINE_GUARD_TEST* environment variables and reports what happened; the parent checks the child's
// exit code and report. Loading the DLL hooks the CHILD process only, and the child talks to 127.0.0.1 only
// (a loopback listener it creates itself) - nothing else touches the network.
//
// Build (VS developer prompt):  cl /nologo /EHsc /MT /O2 guard_test.cpp /link ws2_32.lib

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------- child ----

static std::string GetEnv(const char* name) {
	char buffer[512] = { 0 };
	DWORD length = GetEnvironmentVariableA(name, buffer, sizeof(buffer));
	return (length > 0 && length < sizeof(buffer)) ? std::string(buffer) : std::string();
}

struct Prologue {
	const char* name;
	const unsigned char* address;
	unsigned char before[16];
};

static void Snapshot(Prologue& p, HMODULE module, const char* name) {
	p.name = name;
	p.address = reinterpret_cast<const unsigned char*>(GetProcAddress(module, name));
	memset(p.before, 0, sizeof(p.before));
	if (p.address) {
		memcpy(p.before, p.address, sizeof(p.before));
	}
}

static bool Hooked(const Prologue& p) {
	return p.address && memcmp(p.before, p.address, sizeof(p.before)) != 0;
}

static int RunChild(const char* dllPath) {
	// Winsock is deliberately not touched before the DLL is loaded (the WSP layer needs MSWSOCK.dll unloaded).
	HMODULE ws2 = GetModuleHandleA("WS2_32.dll");
	HMODULE kernelBase = GetModuleHandleA("KERNELBASE.dll");
	Prologue connectFn, wsaConnectFn, wsaIoctlFn, sendtoFn, getaddrinfoFn, createFileFn;
	Snapshot(connectFn, ws2, "connect");
	Snapshot(wsaConnectFn, ws2, "WSAConnect");
	Snapshot(wsaIoctlFn, ws2, "WSAIoctl");
	Snapshot(sendtoFn, ws2, "sendto");
	Snapshot(getaddrinfoFn, ws2, "getaddrinfo");
	Snapshot(createFileFn, kernelBase, "CreateFileW");

	printf("GT:mswsock_before=%d\n", GetModuleHandleA("MSWSOCK.dll") != nullptr);
	fflush(stdout);

	HMODULE dll = LoadLibraryA(dllPath);
	if (!dll) {
		printf("GT:load=FAILED error=%lu\n", GetLastError());
		return 2;
	}
	printf("GT:load=OK\n");
	printf("GT:winsock=%s\n", GetEnv("OFFLINE_GUARD_RESULT_WINSOCK").c_str());
	printf("GT:offline=%s\n", GetEnv("OFFLINE_GUARD_RESULT_OFFLINE").c_str());
	printf("GT:hooked connect=%d WSAConnect=%d WSAIoctl=%d sendto=%d getaddrinfo=%d CreateFileW=%d\n",
		Hooked(connectFn), Hooked(wsaConnectFn), Hooked(wsaIoctlFn), Hooked(sendtoFn), Hooked(getaddrinfoFn), Hooked(createFileFn));
	fflush(stdout);

	// A loopback TCP round trip must still work with the guard in place (and drives the WSP layer, which only
	// activates when the first socket is created).
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printf("GT:loopback=FAILED WSAStartup\n");
		return 3;
	}
	bool loopbackOk = false;
	SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in address = {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	int addressLength = sizeof(address);
	if (bind(listener, (sockaddr*)&address, sizeof(address)) == 0 && listen(listener, 1) == 0 &&
			getsockname(listener, (sockaddr*)&address, &addressLength) == 0 &&
			connect(client, (sockaddr*)&address, sizeof(address)) == 0) {
		SOCKET accepted = accept(listener, nullptr, nullptr);
		if (accepted != INVALID_SOCKET) {
			const char ping[] = "ping";
			char pong[8] = { 0 };
			loopbackOk = send(client, ping, 4, 0) == 4 && recv(accepted, pong, 4, 0) == 4 && memcmp(pong, ping, 4) == 0;
			closesocket(accepted);
		}
	}
	closesocket(client);
	closesocket(listener);
	WSACleanup();
	printf("GT:loopback=%s\n", loopbackOk ? "OK" : "FAILED");
	printf("GT:wsp_fired=%s\n", GetEnv("OFFLINE_GUARD_RESULT_WSP_FIRED").c_str());
	fflush(stdout);

	Sleep(300); // "keeps running" after load
	printf("GT:alive=1\n");
	fflush(stdout);
	return loopbackOk ? 0 : 3;
}

// --------------------------------------------------------------- parent ----

struct Result {
	DWORD exitCode = 0xFFFFFFFF;
	bool timedOut = false;
	std::string output;
};

static Result RunCase(const std::string& self, const std::string& dll, const char* test, const char* fail) {
	SetEnvironmentVariableA("OFFLINE_GUARD_TEST", test);
	SetEnvironmentVariableA("OFFLINE_GUARD_TEST_FAIL", fail);
	SetEnvironmentVariableA("OFFLINE_GUARD_TEST_NOUI", "1");

	Result result;
	SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
	HANDLE readEnd = nullptr, writeEnd = nullptr;
	CreatePipe(&readEnd, &writeEnd, &sa, 1 << 20);
	SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFOA startup = {};
	startup.cb = sizeof(startup);
	startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	startup.hStdOutput = writeEnd;
	startup.hStdError = writeEnd;
	PROCESS_INFORMATION process = {};
	std::string commandLine = "\"" + self + "\" --child \"" + dll + "\"";
	std::vector<char> mutableLine(commandLine.begin(), commandLine.end());
	mutableLine.push_back('\0');
	if (!CreateProcessA(nullptr, mutableLine.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &process)) {
		result.output = "CreateProcess failed";
		CloseHandle(readEnd);
		CloseHandle(writeEnd);
		return result;
	}
	CloseHandle(writeEnd);

	if (WaitForSingleObject(process.hProcess, 30000) == WAIT_TIMEOUT) {
		result.timedOut = true;
		TerminateProcess(process.hProcess, 99); // our own child
		WaitForSingleObject(process.hProcess, 5000);
	}
	GetExitCodeProcess(process.hProcess, &result.exitCode);

	char buffer[4096];
	DWORD got = 0;
	DWORD available = 0;
	while (PeekNamedPipe(readEnd, nullptr, 0, nullptr, &available, nullptr) && available > 0 &&
			ReadFile(readEnd, buffer, sizeof(buffer), &got, nullptr) && got > 0) {
		result.output.append(buffer, got);
	}
	CloseHandle(readEnd);
	CloseHandle(process.hProcess);
	CloseHandle(process.hThread);

	SetEnvironmentVariableA("OFFLINE_GUARD_TEST", nullptr);
	SetEnvironmentVariableA("OFFLINE_GUARD_TEST_FAIL", nullptr);
	SetEnvironmentVariableA("OFFLINE_GUARD_TEST_NOUI", nullptr);
	return result;
}

static bool Has(const Result& r, const char* text) {
	return r.output.find(text) != std::string::npos;
}

static int g_failures = 0;

static void Report(const char* name, const Result& r, DWORD expectedExit, const std::vector<const char*>& expectedText, const std::vector<const char*>& forbiddenText = {}) {
	bool ok = !r.timedOut && r.exitCode == expectedExit;
	std::string why;
	if (r.timedOut) why += " timed-out;";
	if (r.exitCode != expectedExit) why += " exit=" + std::to_string(r.exitCode) + " (expected " + std::to_string(expectedExit) + ");";
	for (const char* text : expectedText) {
		if (!Has(r, text)) { ok = false; why += std::string(" missing '") + text + "';"; }
	}
	for (const char* text : forbiddenText) {
		if (Has(r, text)) { ok = false; why += std::string(" unexpected '") + text + "';"; }
	}
	printf("[%s] %-46s exit=%lu%s\n", ok ? "PASS" : "FAIL", name, r.exitCode, ok ? "" : why.c_str());
	if (!ok) {
		g_failures++;
		printf("---- child output ----\n%s----------------------\n", r.output.c_str());
	}
}

int main(int argc, char** argv) {
	if (argc >= 3 && strcmp(argv[1], "--child") == 0) {
		return RunChild(argv[2]);
	}
	if (argc < 2) {
		printf("usage: guard_test.exe <path\\to\\AgarciumClient.dll>\n");
		return 64;
	}
	char selfPath[MAX_PATH] = { 0 };
	GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
	char dllFull[MAX_PATH] = { 0 };
	GetFullPathNameA(argv[1], MAX_PATH, dllFull, nullptr);
	if (GetFileAttributesA(dllFull) == INVALID_FILE_ATTRIBUTES) {
		printf("DLL not found: %s\n", dllFull);
		return 65;
	}
	printf("DLL under test: %s\n", dllFull);

	const std::string self = selfPath;
	const std::string dll = dllFull;

	// (a) normal load: the process keeps running, both TCP layers and every other guard are in place.
	Report("(a) normal load, no test env at all", RunCase(self, dll, nullptr, nullptr), 0,
		{ "GT:load=OK", "GT:mswsock_before=0", "GT:hooked connect=1 WSAConnect=1 WSAIoctl=1 sendto=1 getaddrinfo=1 CreateFileW=1", "GT:loopback=OK", "GT:alive=1" });
	Report("(a) normal load, test mode on", RunCase(self, dll, "1", nullptr), 0,
		{ "GT:load=OK", "GT:winsock=wsp=1 ws2=1", "GT:offline=dns=1 udp=1 connectex=1 discord=1", "GT:loopback=OK", "GT:wsp_fired=1", "GT:alive=1" });

	// The test switches are inert unless OFFLINE_GUARD_TEST=1.
	Report("    FAIL list ignored without OFFLINE_GUARD_TEST=1", RunCase(self, dll, nullptr, "wsp,ws2,connectex,udp,dns,discord"), 0,
		{ "GT:load=OK", "GT:hooked connect=1 WSAConnect=1 WSAIoctl=1 sendto=1 getaddrinfo=1 CreateFileW=1", "GT:alive=1" });

	// (b) both TCP layers forced to fail: fail closed, process terminated with exit code 1.
	Report("(b) wsp + ws2 forced to fail -> terminated", RunCase(self, dll, "1", "wsp,ws2"), 1, {}, { "GT:load=OK" });
	Report("(b) same, other order / case (WS2,WSP)", RunCase(self, dll, "1", "WS2,WSP"), 1, {}, { "GT:load=OK" });

	// (c) exactly one TCP layer fails: still one complete layer, so the patch stays up and enforcing.
	Report("(c) only wsp forced to fail -> ws2 layer carries", RunCase(self, dll, "1", "wsp"), 0,
		{ "GT:load=OK", "GT:winsock=wsp=0 ws2=1", "GT:hooked connect=1 WSAConnect=1", "GT:loopback=OK", "GT:alive=1" }, { "GT:wsp_fired=1" });
	Report("(c) only ws2 forced to fail -> wsp layer carries", RunCase(self, dll, "1", "ws2"), 0,
		{ "GT:load=OK", "GT:winsock=wsp=1 ws2=0", "GT:hooked connect=0 WSAConnect=0", "GT:loopback=OK", "GT:wsp_fired=1", "GT:alive=1" });

	// ConnectEx is covered by neither TCP layer, so it is mandatory on its own.
	Report("    connectex forced to fail -> terminated", RunCase(self, dll, "1", "connectex"), 1, {}, { "GT:load=OK" });

	// The other guards report failure the same way.
	Report("    udp forced to fail -> terminated", RunCase(self, dll, "1", "udp"), 1, {}, { "GT:load=OK" });
	Report("    dns forced to fail -> terminated", RunCase(self, dll, "1", "dns"), 1, {}, { "GT:load=OK" });
	Report("    discord forced to fail -> terminated", RunCase(self, dll, "1", "discord"), 1, {}, { "GT:load=OK" });

	printf("\n%s (%d failure%s)\n", g_failures ? "SOME TESTS FAILED" : "ALL TESTS PASSED", g_failures, g_failures == 1 ? "" : "s");
	return g_failures ? 1 : 0;
}
