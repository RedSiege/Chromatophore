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

	char _key[16] = "###KEY###";
	unsigned char shellcode[###SHELLCODE_LENGTH###] = { ###SHELLCODE### };
	
	// declare a variable for our shellcode size
 	unsigned int shellcode_size = sizeof(shellcode);
	
	// create a new struct from our key
	key.Buffer = (&_key);
	key.Length = 16;
 
	// create a new struct from the shellcode
	_data.Buffer = &shellcode;
	_data.Length = shellcode_size;
 
	//SystemFunction033(&data, &key);
	SystemFunction033(&_data, &key);
	
 	int idx = 0;
		while ( idx < sizeof(shellcode))
	{
		if (idx == (sizeof(shellcode) - 1) )
		{
			printf("0x%02x ", shellcode[idx]);
		}
		else
		{
			printf("0x%02x, ", shellcode[idx]);
		}
		idx++;
	}

}
