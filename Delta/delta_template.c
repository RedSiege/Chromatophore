#include <stdio.h>
#include <string.h>
#include <windows.h>

// Compile:
//   cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcoffset.c /link /out:offset.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(){
	
	unsigned char first_byte = ###FIRSTBYTE###;
	unsigned char delta[###DELTA_LENGTH###] = {
###DELTA### };
	unsigned char shellcode[###SHELLCODE_LENGTH###] = { 0x00 };

	//Size of shellcode array
	int cap = sizeof(delta) / sizeof(delta[0]);

	//Setting first byte of the reconstituted array to the first byte of the payload
	shellcode[0] = first_byte;

	// keep track of our positions
	unsigned int delta_idx, shellcode_idx;
	
	/* Take initial byte and add the delta to it to get the second byte. Take second byte
	and add second delta to get third byte and so on. */
	for (delta_idx = 0; delta_idx < cap; delta_idx++)
	{
		shellcode_idx = delta_idx + 1;
		shellcode[shellcode_idx] = shellcode[delta_idx] + delta[delta_idx];
	}


	for (int l = 0; l < cap + 1; l++)
	{
		//Last run needs to print closing bracket and semicolon
		if (l == (cap)) {
			printf("0x%02x", shellcode[l]);
		}
		else {
			//Added a 1 because initial loop is true and adds a newline. This causes it to print 15 bytes and then a new line
			if ((l + 1) % 15 == 0) {
				printf("0x%02x,\n", shellcode[l]);
			}
			else {
				printf("0x%02x,", shellcode[l]);
			}
		}
	}
	
	return 0;
}
