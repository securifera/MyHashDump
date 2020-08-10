#pragma once

#include <Windows.h>

HMODULE GetProcessModuleHandleByPid(DWORD pid, const char* dllFullPath);
HMODULE GetProcessModuleHandleByHandle(HANDLE hProc, const char* dllFullPath);
HANDLE inject(const char* dllFullPath, DWORD pid);
HANDLE eject(HMODULE hModule, DWORD pid);
HANDLE runfunction(const char* dllFullPath, DWORD pid, const char* functionname);
HANDLE inject_and_run(const char* dllFullPath, DWORD pid, const char* functionname);
HANDLE nt_inject_and_run(const char* dllFullPath, DWORD pid, const char* functionname);
bool cleanupRemoteProcess(DWORD pid, const char* modulePath);
