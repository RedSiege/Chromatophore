#include <windows.h>
#include <stdio.h>

// compile:
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcjigsaw.c /link /out:jigsaw.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void)
{
	unsigned char jigsaw[###SHELLCODE_LENGTH###] = { ###JIGSAW### };
	int positions[###SHELLCODE_LENGTH###] = { ###POSITIONS### };
	unsigned char shellcode[###SHELLCODE_LENGTH###] = { 0x00 };
	int position;
	
	// Reconstruct the payload
	for (int idx = 0; idx < sizeof(positions) / sizeof(positions[0]); idx++) {
		printf("");
		position = positions[idx];
		shellcode[position] = jigsaw[idx];
	}

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
