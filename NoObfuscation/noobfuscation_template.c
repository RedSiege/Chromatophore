#include <windows.h>
#include <stdio.h>

// compile: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcnoobfuscation.c /link /out:noobfuscation.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

unsigned char shellcode[] = { ###SHELLCODE### };

int main(void)
{
        int idx = 0;
        while ( idx < sizeof(shellcode))
        {
                if (idx == (sizeof(shellcode) - 1) )
                {
                        printf("0x%02x ", (unsigned char)shellcode[idx]);
                }
                else
                {
                        printf("0x%02x, ", (unsigned char)shellcode[idx]);
                }
                idx++;
        }
}
          
