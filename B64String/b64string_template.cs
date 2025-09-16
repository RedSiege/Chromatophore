using System;

// Compile:
//  c:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:b64string.exe /target:exe b64string.cs
namespace B64
{

	class Program
	{

		public static void Main()
		{

			string s = "###SHELLCODE###";
		
			byte[] shellcode = Convert.FromBase64String(s);
			int idx = 0;
			while (idx < shellcode.Length)
			{
				Console.Write("{0} ", shellcode[idx].ToString("x2"));
				idx = idx + 1;
			}
		
		}
	}
}
