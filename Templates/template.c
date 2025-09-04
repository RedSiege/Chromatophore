#include <windows.h>
#include <stdio.h>

// compile:
//  cl.exe /nologo /W0 /Tcfilename.c /link /out:output.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void)
{

	unsigned char shellcode[###SC_LENGTH###] = {0};
	int sc_len = sizeof(shellcode);



	int idx = 0;
	printf("Decoded shellcode:\n");
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
