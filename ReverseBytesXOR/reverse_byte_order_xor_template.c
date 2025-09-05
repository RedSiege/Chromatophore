#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// compile: cl.exe /nologo /MT /Tcreverse_byte_order_xor.c /link /OUT:reverse_byte_order_xor.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void) {

    unsigned int reversed_payload[###SHELLCODE_LENGTH###] = { ###SHELLCODE### };
    char shellcode[###SHELLCODE_LENGTH###] = { 0 };

    int xorkey = ###KEY###;
	
    // reverse and de-xor our array of ints
    for (int i = 0; i < ###SHELLCODE_LENGTH###; i++)
    {
            char decoded = reversed_payload[###SHELLCODE_LENGTH### - i - 1] ^ xorkey;
            shellcode[i] = decoded;
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

    return 0;
}

