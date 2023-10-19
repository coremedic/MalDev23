#include <windows.h>
#include <iostream>

// this code allocates 256kb of RWX memory 
int main() {
	VOID* mem = VirtualAlloc(NULL, 0x40000, 0x00002000 | 0x00001000, PAGE_EXECUTE_READWRITE); // 0x40 works fine i think?
	PVOID baseaddr = (PVOID)mem; // PVOID = VOID* in win32 api
	printf("RWX memory region allocated at 0x%x\n", baseaddr);
	system("pause");
}
