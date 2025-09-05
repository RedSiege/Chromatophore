#include <windows.h>
#include <stdio.h>
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

// compile:
//  cl.exe /nologo /MT /W0 /GS- /DNDEBUG /Tcuuid.c /link /out:uuid.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

// Define our ustring struct
struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

int main(void)
{
	char * UUIDs[] = {
###UUIDS###
	};
	
	// get the size of our shellcode stored as UUIDs
	unsigned int shellcode_size = (unsigned int)sizeof(UUIDs) * 2;
	
	// Declare a buffer for storing our shellcode
	void * buffer = VirtualAlloc(NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// This keeps track of our current position in the allocated buffer
	void * bufferBaseAddress = NULL; 
	
	// This keeps track of how many bytes we've written into the buffer
	int i = 0;
	
	// Loop through our list of UUIDs and use UuidFromStringA to convert and load into memory
    for (int count = 0; count < sizeof(UUIDs) / sizeof(UUIDs[0]); count++) {
		bufferBaseAddress = ((ULONG_PTR)buffer + i);
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)UUIDs[count], bufferBaseAddress);
        i += 16;
    }
	
	// create a new struct from the buffer we allocated
	_data.Buffer = buffer;
	_data.Length = shellcode_size;
	
 	int idx = 0;
	while ( idx < _data.Length)
	{
		if (idx == (shellcode_size - 1) )
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
