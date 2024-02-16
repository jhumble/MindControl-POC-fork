#pragma once
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h>
#include <processsnapshot.h>
#include <Dbghelp.h>
#include <fibersapi.h>
#pragma comment(lib, "Dbghelp.lib")

#define RETVAL_TAG 0xAABBCCDD



//----------
// TypeDefs
//----------

typedef NTSTATUS (NTAPI * RtlRemoteCall_t)(
	HANDLE	Process,
	HANDLE	Thread,
	PVOID	CallSite,
	ULONG	ArgumentCount,
	PULONG	Arguments,
	BOOLEAN	PassContext,
	BOOLEAN	AlreadySuspended
);

typedef NTSTATUS (NTAPI * NtContinue_t)(
	PCONTEXT	ThreadContext,
	BOOLEAN		RaiseAlert
);

typedef HANDLE (WINAPI * OpenProcess_t)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

typedef BOOL (WINAPI * CloseHandle_t)(
    HANDLE hObject
);

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID	lpAddress,
	SIZE_T	dwSize,
	DWORD	flNewProtect,
	PDWORD	lpflOldProtect
);

typedef BOOL (WINAPI * ReadProcessMemory_t)(
  HANDLE  hProcess,
  LPCVOID lpBaseAddress,
  LPVOID  lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesRead
);

typedef DWORD (WINAPI * EnumUILanguagesW_t)(
	UILANGUAGE_ENUMPROCW lpUILanguageEnumProc,
	DWORD                dwFlags,
	LONG_PTR             lParam
);

typedef HANDLE (WINAPI * CreateThread_t)(
	LPSECURITY_ATTRIBUTES	lpThreadAttributes,
	SIZE_T					dwStackSize,
	LPTHREAD_START_ROUTINE	lpStartAddress,
	LPVOID					lpParameter,
	DWORD					dwCreationFlags,
	LPDWORD					lpThreadId
);

typedef BOOL (WINAPI * VirtualFree_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
);

typedef void (WINAPI * Sleep_t)(
	DWORD dwMilliseconds
);


//--------------------
// MINDCONTROL STRUCT
//--------------------
typedef struct _API_REMOTE_CALL {
	// remote API call return value
	size_t		retval;
	
	// standard function to call at the end of the shellcode
	NtContinue_t ntContinue;
	CONTEXT		context;
	
	// VirtualAlloc args
	VirtualAlloc_t MC_VirtualAlloc;
	LPVOID		param1;
	SIZE_T		param2;
	DWORD		param3;
	DWORD		param4;
	LPVOID		virtAllocRet;

	// OpenProcess args
	OpenProcess_t MC_OpenProcess;
	DWORD dwDesiredAccess;
  	BOOL  bInheritHandle;
  	DWORD dwProcessId;
	HANDLE hProc;

	// ReadProcessMemory args
	ReadProcessMemory_t MC_ReadProcessMemory;
	HANDLE hProcess;
	LPCVOID lpBaseAddress;
	LPVOID lpBuffer;
	SIZE_T nSize;
	SIZE_T *lpNumberOfBytesRead;

	// EnumUILanguagesW args
	EnumUILanguagesW_t MC_EnumUILanguagesW;
	UILANGUAGE_ENUMPROCW lpUILanguageEnumProc;
	DWORD dwFlags;
	LONG_PTR lParam;

	// CloseHandle args
	CloseHandle_t MC_CloseHandle;
	HANDLE hObject;

	// CreateThread args
	CreateThread_t MC_CreateThread;
	LPSECURITY_ATTRIBUTES	lpThreadAttributes;
	SIZE_T					dwStackSize;
	LPTHREAD_START_ROUTINE	lpStartAddress;
	LPVOID					lpParameter;
	DWORD					dwCreationFlags;
	LPDWORD					lpThreadId;
	HANDLE MC_tHandle;

	// VirtualFree args
	VirtualFree_t MC_VirtualFree;
	DWORD dwFreeType;

	// Sleep args
	Sleep_t MC_Sleep;
	DWORD dwMilliseconds;

} MindControl;
