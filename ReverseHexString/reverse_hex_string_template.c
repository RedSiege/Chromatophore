#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// compile: 
//  cl.exe /nologo /W0 /DNDEBUG /Tcreverse_hex_string.c /link /OUT:reverse_hex_string.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void) {
	char reversed_hex_string[] = "###SHELLCODE###";

	// reverse the string
	char* hex_string = _strrev(reversed_hex_string);
	
	// declare a new shellcode byte array
	char shellcode[###SHELLCODE_LENGTH###];
	
	// define an index to keep track of where we're at
	int idx = 0;
	char *next_token = NULL;
		
	// add our first byte to the array
	if ( shellcode[idx] = strtol((strtok_s(hex_string, ",", &next_token)), NULL, 16))
	{
		// successfully converted string to long int
	}
	else
	{
		// conversion to long failed, meaning we don't have a valid hex vlue
		// replace our null byte placeholder with a null byte
		shellcode[idx] = strtol("0x00", NULL, 16);
	}	

	// Loop through remaining string to populate the array
	while (idx < sizeof(shellcode) - 1)
	{
		++idx;
		if ( shellcode[idx] = strtol((strtok_s(NULL, ",", &next_token)), NULL, 16))
		{
			printf("");
			// successfully converted string to long int
		}
		else
		{
			// conversion to long failed, meaning we don't have a valid hex vlue
			// replace our null byte placeholder with a null byte
			shellcode[idx] = strtol("0x00", NULL, 16);
		}	
	}

	idx = 0;
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

