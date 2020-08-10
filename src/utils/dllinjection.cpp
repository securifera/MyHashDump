#include <cstdio>
#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <inttypes.h>
#include <psapi.h>

#include "dllInjection.h"
#include "utils.h"

//function definition for NtCreateThreadEx (undocument API)
typedef NTSTATUS(WINAPI *pNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN SIZE_T CreateSuspended, //(BOOL)
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

HMODULE GetProcessModuleHandleByPid(DWORD pid, const char* dllFullPath)
{
	HANDLE hProc = NULL;
	HMODULE hMods[1024] = { 0 };
	DWORD cbN = 0;
	HMODULE found = NULL;

	if (!dllFullPath) {
		printf("GetProcessModuleHandle invalid parameter\n");
		return NULL;
	}

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProc == NULL) {
		printf("Failed to open process: %d. 0x%x\n", pid, GetLastError());
		return NULL;
	}

	//Enum processes
	if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbN)) {
		for (unsigned int i = 0; i < (cbN / sizeof(HMODULE)); i++) {
			char modName[512] = { 0 };
			if (GetModuleFileNameExA(hProc, hMods[i], modName, sizeof(modName))) {
				if (strcmp(dllFullPath, modName) == 0) {
					printf("found module name in process\n");
					found = hMods[i];
					break;
				}
			}
		}
	}

	if (hProc)
		CloseHandle(hProc);

	return found;
}

HMODULE GetProcessModuleHandleByHandle(HANDLE hProc, const char* dllFullPath)
{
	HMODULE hMods[1024] = { 0 };
	DWORD cbN = 0;
	HMODULE found = NULL;

	if (!dllFullPath || !hProc) {
		printf("GetProcessModuleHandleByHandle invalid parameter\n");
		return NULL;
	}

	//Enum processes
	if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbN)) {
		for (unsigned int i = 0; i < (cbN / sizeof(HMODULE)); i++) {
			char modName[512] = { 0 };
			if (GetModuleFileNameExA(hProc, hMods[i], modName, sizeof(modName))) {
				if (strcmp(dllFullPath, modName) == 0) {
					printf("found module name in process\n");
					found = hMods[i];
					break;
				}
			}
		}
	}

	return found;
}

LPVOID GetRemoteProcAddress(const char* dllFullPath, const char* functioNanme, HANDLE hProc)
{
	//load DLL into local process
	LPVOID functionAddr;
	HMODULE hm = LoadLibraryA(dllFullPath);
	if (hm == NULL) {
		printf("Error: Loadlibrary local did not work: 0x%x\n", GetLastError());
		return NULL;
	}
	else {
		functionAddr = (LPVOID)GetProcAddress(hm, functioNanme);
		if (functionAddr == NULL) {
			printf("Error: the %s function was not found inside %s library.\n", dllFullPath, functioNanme);
			return NULL;
		}
		FreeLibrary(hm);
	}

	//find offset for function
	if (hm > functionAddr) {
		printf("library address or function address incorrect cant find difference\n");
		return NULL;
	}
	size_t diff = (size_t)functionAddr - (size_t)hm;

	HMODULE remoteHmodule = GetProcessModuleHandleByHandle(hProc, dllFullPath);
	if (remoteHmodule == NULL) {
		printf("Error finding hModule of newly injected DLL\n");
		return NULL;
	}
	else {
		functionAddr = LPVOID((size_t)remoteHmodule + diff);
	}

	return functionAddr;
}

/** eject - inject DLL into target process
 *
 *		NOTE - this function uses NtCreateThreadEx in place of CreateRemoteThread
 */
HANDLE eject(HMODULE hModule, DWORD pid)
{
	HANDLE remoteThreadHandle = NULL;

	printf("Ejecting DLL from Process... PID: %i\n", pid);

	//make sure current process has debug privilege
	addDebugPrivilegesToCurrentProcess();

	//Get a handle for the process with the pid...
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(processHandle == NULL) {
		printf("Couldn't get process handle. Error: %i\n", GetLastError() );
	} else {
		//get address for freelibrary function
		LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll" ), "FreeLibrary");
		//LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle( L"ntdll.dll" ), "LdrUnloadDll");
		if(addr == NULL) {
			printf( "Error: the FreeLibrary function was not found inside kernel32.dll library.\n" );
		} else {
			// Inject FreeLibrary command into target process
			DWORD threadId = 0;
			remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)addr, hModule, NULL, &threadId);
			if(remoteThreadHandle == NULL) {
				printf("The remote thread could not be created. 0x%x\n", GetLastError());
			} else {
				printf("Success: the remote thread was successfully created. with thread id: %i \n", threadId);
			}
		}
	}

	return remoteThreadHandle;
}

/** inject - inject DLL into target process
 *
 *		NOTE - this function uses NtCreateThreadEx in place of CreateRemoteThread
 */
HANDLE inject(const char* dllFullPath, DWORD pid)
{
	HANDLE remoteThreadHandle = NULL;

	printf("Injecting into Process... PID: %i\n", pid);

	//make sure current process has debug privilege
	addDebugPrivilegesToCurrentProcess();

	//Get a handle for the process with the pid...
	HANDLE processHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if(processHandle == NULL) {
		printf("Couldn't get process handle. Error: %i\n", GetLastError());
	} else {
		//Allocate memory inside the process's address space...
		LPVOID arg = (LPVOID)VirtualAllocEx(processHandle, NULL, strlen(dllFullPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(arg == NULL) {
			printf( "Error: the memory could not be allocated inside the chosen process.\n" );
		} else {
			// Write the argument to LoadLibraryA to the process's newly allocated memory region...
			SIZE_T bytesWritten = 0;
			int n = WriteProcessMemory(processHandle, arg, dllFullPath, strlen(dllFullPath), &bytesWritten);
			if( n == 0 ) {
				printf( "Error: there was no bytes written to the process's address space.\n" );
			} else {
				// Get address of the LoadLibrary function.
				LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll" ), "LoadLibraryA");
				if(addr == NULL) {
					printf( "Error: the LoadLibraryA function was not found inside kernel32.dll library.\n" );
				} else {
					// Inject the DLL into the process's address space...
					DWORD threadId = 0;
					remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, &threadId);
					if(remoteThreadHandle == NULL) {
						printf("The remote thread could not be created. 0x%x\n", GetLastError());
					} else {
						printf("Success: the remote thread was successfully created. with thread id: %i \n", threadId);
					}
				}
			}
		}
		CloseHandle(processHandle);
	}

	return remoteThreadHandle;
}

HANDLE runfunction(const char* dllFullPath, DWORD pid, const char* functionname)
{
	HANDLE remoteThreadHandle = NULL;

	//printf("Injecting into Process... PID: %i\n", pid);

	//make sure current process has debug privilege
	addDebugPrivilegesToCurrentProcess();

	//Get a handle for the process with the pid...
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(processHandle == NULL) {
		printf("Couldn't get process handle. Error: %i\n", GetLastError());
	} else {

		HMODULE hm = LoadLibraryA(dllFullPath);
		if(hm == NULL) {
			printf("Error: Loadlibrary local did not work\n");
		} else {
			LPVOID addr = (LPVOID)GetProcAddress(hm, functionname);
			if(addr == NULL) {
				printf("Error: the %s function was not found inside %s library.\n", dllFullPath, functionname);
			} else {
				//Create remotethread in process for dll function
				DWORD threadId = 0;
				remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, NULL, &threadId);
				if(remoteThreadHandle == NULL) {
					printf("The remote thread could not be created. 0x%x\n", GetLastError());
				} else {
					printf("Success: the remote thread was successfully created. with thread id: %i \n", threadId);
				}
			}

			BOOL ret = FreeLibrary(hm);
			if(ret != TRUE) {
				printf("Error: freelibrary failed 0x%x\n", GetLastError());
			}
		}
		CloseHandle(processHandle);
	}

	return remoteThreadHandle;
}

HANDLE inject_and_run(const char* dllFullPath, DWORD pid, const char* functionname)
{
	HANDLE remoteThreadHandle = NULL;

	printf("Injecting into Process... PID: %i\n", pid);

	//Get addr to functionname first
	LPVOID functionaddr;
	HMODULE hm = LoadLibraryA(dllFullPath);
	if(hm == NULL) {
		printf("Error: Loadlibrary local did not work: 0x%x\n", GetLastError());
		return NULL;
	} else {
		functionaddr = (LPVOID)GetProcAddress(hm, functionname);

		if(functionaddr == NULL) {
			printf("Error: the %s function was not found inside %s library.\n", dllFullPath, functionname);
			return NULL;
		}
		FreeLibrary(hm);
	}

	//make sure current process has debug privilege
	addDebugPrivilegesToCurrentProcess();

	//Get a handle for the process with the pid...
	HANDLE processHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	if(processHandle == NULL) {
		printf("Couldn't get process handle. Error: %i\n", GetLastError());
	} else {
		//Allocate memory inside the process's address space...
		LPVOID arg = (LPVOID)VirtualAllocEx(processHandle, NULL, strlen(dllFullPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if(arg == NULL) {
			printf( "Error: the memory could not be allocated inside the chosen process.\n" );
		} else {
			// Write the argument to LoadLibraryA to the process's newly allocated memory region...
			SIZE_T bytesWritten = 0;
			int n = WriteProcessMemory(processHandle, arg, dllFullPath, strlen(dllFullPath), &bytesWritten);
			if( n == 0 ) {
				printf("Error: there was no bytes written to the process's address space.\n");
			} else {
				// Get address of the LoadLibrary function.
				LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll" ), "LoadLibraryA");
				if(addr == NULL) {
					printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
				} else {
					// Inject the DLL into the process's address space...
					DWORD threadId = 0;
					remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, &threadId);
					if(remoteThreadHandle == NULL) {
						printf("The remote thread could not be created. 0x%x\n", GetLastError());
					} else {
						printf("Success: the remote thread was successfully created. with thread id: %i \n", threadId);
					}

					Sleep(1); //Allow LoadLib to succeed

					//run function from injected DLL
					remoteThreadHandle = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)functionaddr, NULL, NULL, &threadId);
					if(remoteThreadHandle == NULL) {
						printf("The remote thread could not be created. 0x%x\n", GetLastError());
					} else {
						printf("Success: the remote thread was successfully created. with thread id: %i \n", threadId);
					}
				}
			}
		}
		CloseHandle(processHandle);
	}

	return remoteThreadHandle;
}

/** nt_inject_and_run - inject a dll into specified process and run function from
 *		dll in injected process.
 *
 *		NOTE - this function uses NtCreateThreadEx in place of CreateRemoteThread
 */
HANDLE nt_inject_and_run(const char* dllFullPath, DWORD pid, const char* functionname)
{
	HANDLE remoteThreadHandle = NULL;

	printf("Injecting %s into PID %d and executing function %s\n", dllFullPath, pid, functionname);

	//make sure current process has debug privilege
	addDebugPrivilegesToCurrentProcess();

	//get NtCreateThreadEx function pointer
	pNtCreateThreadEx NtCreateThreadEx = NULL;
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL) {
		printf("Error finding NtCreateThreadEx, 0x%x\n", GetLastError());
		return NULL;
	}
	//printf("NtCreateThreadEx function address at 0x%" PRIxPTR "\n", NtCreateThreadEx);

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (processHandle == NULL) {
		printf("Error: OpenProcess: 0x%x\n", GetLastError());
	}
	else {
		//Allocate memory inside the process's address space...
		LPVOID arg = (LPVOID)VirtualAllocEx(processHandle, NULL, strlen(dllFullPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (arg == NULL) {
			printf("Error: VirtualAllocEx: 0x%x\n", GetLastError());
		}
		else {
			// Write the argument to LoadLibraryA to the process's newly allocated memory region...
			SIZE_T bytesWritten = 0;
			int n = WriteProcessMemory(processHandle, arg, dllFullPath, strlen(dllFullPath), &bytesWritten);
			if (n == 0) {
				printf("Error: WriteProcessMemory 0 bytes writtent: 0x%x\n", GetLastError());
			}
			else {
				// Get address of the LoadLibrary function.
				LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
				if (addr == NULL) {
					printf("Error: GetProcAddress for LoadLibraryA: 0x%x\n", GetLastError());
				}
				else {
					// Inject the DLL into the process's address space...
					NTSTATUS ret = NtCreateThreadEx(&remoteThreadHandle, GENERIC_ALL, NULL, processHandle, (LPTHREAD_START_ROUTINE)addr, arg, FALSE, NULL, NULL, NULL, NULL);
					if (remoteThreadHandle == NULL) {
						printf("NtCreateThreadEx for LoadLibraryA failed: 0x%x\n", GetLastError());
					}
					else {
						printf("NtCreateThreadEx ret: 0x%x\n", ret);

						//Allow LoadLibraryA to finish
						DWORD ret = WaitForSingleObject(remoteThreadHandle, 5000);
						Sleep(1); //TODO fix

						switch (ret) {
						case WAIT_OBJECT_0:
							break;
						case WAIT_FAILED:
							printf("WaitForSingleObject for loadlibrary thread failed. 0x%x\n", GetLastError());
							break;
						case WAIT_TIMEOUT:
							printf("WaitForSingleObject for loadlibrary timed out. weird 0x%x\n", GetLastError());
							break;
						default:
							break;
						}
						
						LPVOID functionAddr = GetRemoteProcAddress(dllFullPath, functionname, processHandle);
						if (functionAddr == NULL) {
							printf("Couldnt find address to starting function in injected DLL, 0x%x\n", GetLastError());
						}
						else {
							//execute function from injected DLL
							NtCreateThreadEx(&remoteThreadHandle, GENERIC_ALL, NULL, processHandle, (LPTHREAD_START_ROUTINE)functionAddr, NULL, FALSE, NULL, NULL, NULL, NULL);
							if (remoteThreadHandle == NULL) {
								printf("NtCreateThreadEx for function \"%s\" failed: 0x%x\n", functionname, GetLastError());
							}
						}
						
					}
				}
			}
			VirtualFreeEx(processHandle, arg, strlen(dllFullPath), MEM_RELEASE);
			//TODO check return
		}
		CloseHandle(processHandle);
	}

	return remoteThreadHandle;
}

bool cleanupRemoteProcess(DWORD pid, const char* modulePath)
{
	int maxAttempts = 3;
	HMODULE hm = NULL;

	bool moduleFound = false;

	// try eject max of 3 times (doesnt always succeed)
	for (int i = 0; i < maxAttempts; i++) {
		hm = GetProcessModuleHandleByPid(pid, modulePath);
		if (hm != NULL) {
			eject(hm, pid); //TODO update this to use NtCreateThreadEx!!!!!!!!!
		}
	}

	//check to see if succeeded last time
	hm = GetProcessModuleHandleByPid(pid, modulePath);
	if (hm != NULL) {
		printf("Unable to unload module\n");
		return false;
	}
	else {
		return true;
	}
}
