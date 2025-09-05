#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// compile: cl.exe /nologo /Tcreverse_byte_order.c /link /OUT:reverse_byte_order.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void) {

	char reversed_payload[###SHELLCODE_LENGTH###] = { ###SHELLCODE### };
	char shellcode[###SHELLCODE_LENGTH###] = { 0x00 };

	// reverse our array of ints
	for (int i = 0; i < sizeof(reversed_payload); i++)
	{
		printf(""); // defender fires an alert on this routine without this ¯\_(ツ)_/¯
		shellcode[i] = reversed_payload[sizeof(reversed_payload) - i - 1];
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

