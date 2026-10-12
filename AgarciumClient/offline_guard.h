#pragma once
#include <WinSock2.h>

// Keeps the client off the internet: only loopback (this PC) may be reached.
namespace offline {
	// True if a connection/send to this address may go ahead. Logs and returns false otherwise.
	bool AllowAddress(const sockaddr* addr, int addrlen, const char* via);

	// Installs the DNS, UDP, ConnectEx and Discord pipe guards.
	bool Hook();
}
