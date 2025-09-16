#include <windows.h>
#include <stdio.h>

// compile:
//  cl.exe /nologo /W0 /Tccaesar.c /link /out:caesar.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void)
{

	char shellcode[###SC_LENGTH###] = {0};
	int sc_len = sizeof(shellcode);

	char caesar[###SC_LENGTH###] = {###CAESAR###};

	for (int i = 0; i < sizeof(caesar); i++)         // Loop over encrypted shellcode
	{
		if ( (caesar[i] - 13) < 0 )              // Test if result is less than 0. Values must be 0-255
		{
			shellcode[i] = caesar[i] + 256 - 13;     //  Add 256
		}		
		else
		{
			shellcode[i] = caesar[i] - 13;           // Not less than 0. Subtract 13
		}
	}



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
