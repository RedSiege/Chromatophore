#include <windows.h>
#include <stdio.h>

// compile:
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tctwoarray.c /link /out:twoarray.exe /SUBSYSTEM:CONSOLE /MACHINE:x64


#define PAYLOAD_SIZE ###SHELLCODE_LENGTH### 

int main(void)
{
	/* 
		Defender will complain if the even and odd arrays are declared globally.
		I've determined it's identifying the reconstruction routine as the bad bytes.
		Defender does not complain if these variables are declared in the main scope.
		¯\_(ツ)_/¯
	*/
	char evens[###EVENS_LENGTH###] = { ###EVENS### };
	char odds[###ODDS_LENGTH###] = { ###ODDS### };
	char shellcode[PAYLOAD_SIZE] = { 0x00 };
	int twoArrIdx = 0;
	int idx = 0;

	while (idx < PAYLOAD_SIZE)
	{
		// read from the even array
		shellcode[idx] = evens[twoArrIdx];
		
		// odds will be one byte less than evens if PAYLOAD_SIZE is odd
		if ( twoArrIdx == (int)sizeof(odds) )
		{
			// do nothing, otherwise we'll read past the end of our array
		}
		else
		{
			// read from odd array
			shellcode[idx+1] = odds[twoArrIdx];
			
			// increment twoArrIdx to move to the next position in the evens and odds arrays
			twoArrIdx++;
		}

		// we've just added two bytes, so we need to shift two positions instead of one
		idx = idx + 2;
	}

	idx = 0;
	while ( idx < PAYLOAD_SIZE)
	{
		if (idx == (PAYLOAD_SIZE - 1))
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
