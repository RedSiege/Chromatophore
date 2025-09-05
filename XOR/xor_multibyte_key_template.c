#include <windows.h>
#include <stdio.h>

// compile: 
//	cl.exe /nologo /Tcxor-multibyte-key.c /link /out:xor-multibyte-key.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

void XOR(char * ciphertext, size_t ciphertext_len, char * key, size_t key_len) {
	int myByte = 0;
	int k_minus_one = key_len - 1;
	for (int idx = 0;  idx < ciphertext_len; idx++) {
		if (myByte == k_minus_one)
		{ 
			myByte = 0;
		}
		
		ciphertext[idx] = ciphertext[idx] ^ key[myByte];
		myByte++;

	}
}

int main(void)
{
	char shellcode[###SC_LENGTH###] = {###SHELLCODE###};
	char xorkey[] = "###XORKEY###";
	
	// XOR our shellcode with the key to decode it
	XOR((char *) shellcode, sizeof(shellcode), xorkey, sizeof(xorkey));
	
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
