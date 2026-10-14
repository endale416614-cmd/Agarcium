#pragma once
#include <WinSock2.h>

// Keeps the client off the internet: only loopback (this PC) may be reached.
namespace offline {
	// True if a connection/send to this address may go ahead. Logs and returns false otherwise.
	bool AllowAddress(const sockaddr* addr, int addrlen, const char* via);

	// Installs the DNS, UDP and ConnectEx guards. Returns false if any of them is not fully in place.
	bool Hook();

	// ---- Test hooks (fail-closed testing only) ----
	// Honoured only when OFFLINE_GUARD_TEST=1 is set. They can only make the patch fail or stay quiet, never loosen it.
	//   OFFLINE_GUARD_TEST_FAIL=<layer>[,<layer>...]  forces that layer's installation to fail.
	//     Layers: wsp, ws2, connectex, udp, dns
	//   OFFLINE_GUARD_TEST_NOUI=1                     skip the failure MessageBox (the process is still terminated)
	//   OFFLINE_GUARD_RESULT_<key>                    set by the patch so a test can read what got installed
	bool TestMode();
	bool TestForcedFail(const char* layer);
	bool TestNoUI();
	void TestReport(const char* key, const char* value);
}
